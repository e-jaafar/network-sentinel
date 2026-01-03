#!/usr/bin/env python3
"""
Database module for Network Sentinel
Handles scan history storage with SQLite
"""

import aiosqlite
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

DB_PATH = Path(__file__).parent.parent / "data" / "sentinel.db"


async def init_db():
    """Initialize the database with required tables"""
    async with aiosqlite.connect(DB_PATH) as db:
        # Scans table - stores each scan session
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TEXT NOT NULL,
                network TEXT NOT NULL,
                device_count INTEGER NOT NULL,
                high_risk_count INTEGER DEFAULT 0,
                medium_risk_count INTEGER DEFAULT 0,
                low_risk_count INTEGER DEFAULT 0,
                minimal_risk_count INTEGER DEFAULT 0,
                total_open_ports INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Devices table - stores devices found in each scan
        await db.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                ip TEXT NOT NULL,
                mac TEXT NOT NULL,
                hostname TEXT,
                vendor TEXT,
                ports_json TEXT,
                risk_level TEXT,
                risk_score INTEGER,
                risk_reasons_json TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        """)
        
        # Alerts table - stores security alerts
        await db.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                device_ip TEXT,
                alert_type TEXT NOT NULL,
                message TEXT NOT NULL,
                severity TEXT NOT NULL,
                notified BOOLEAN DEFAULT FALSE,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        """)
        
        # Settings table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        
        await db.commit()
        print(f"[DB] Database initialized at {DB_PATH}")


async def save_scan(scan_data: dict) -> int:
    """Save a scan result to the database, returns scan_id"""
    async with aiosqlite.connect(DB_PATH) as db:
        # Count risk levels
        risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "MINIMAL": 0}
        total_ports = 0
        
        for device in scan_data.get("devices", []):
            level = device.get("risk", {}).get("level", "MINIMAL")
            risk_counts[level] = risk_counts.get(level, 0) + 1
            total_ports += len(device.get("ports", []))
        
        # Insert scan record
        cursor = await db.execute("""
            INSERT INTO scans (scan_time, network, device_count, high_risk_count, 
                             medium_risk_count, low_risk_count, minimal_risk_count, total_open_ports)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_data["scan_time"],
            scan_data["network"],
            scan_data["device_count"],
            risk_counts["HIGH"],
            risk_counts["MEDIUM"],
            risk_counts["LOW"],
            risk_counts["MINIMAL"],
            total_ports
        ))
        
        scan_id = cursor.lastrowid
        
        # Insert devices
        for device in scan_data.get("devices", []):
            await db.execute("""
                INSERT INTO devices (scan_id, ip, mac, hostname, vendor, ports_json, 
                                   risk_level, risk_score, risk_reasons_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                device["ip"],
                device["mac"],
                device.get("hostname"),
                device.get("vendor", "Unknown"),
                json.dumps(device.get("ports", [])),
                device.get("risk", {}).get("level", "MINIMAL"),
                device.get("risk", {}).get("score", 0),
                json.dumps(device.get("risk", {}).get("reasons", []))
            ))
        
        await db.commit()
        print(f"[DB] Saved scan {scan_id} with {scan_data['device_count']} devices")
        return scan_id


async def get_scan_history(limit: int = 50) -> list:
    """Get recent scan history"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("""
            SELECT * FROM scans ORDER BY created_at DESC LIMIT ?
        """, (limit,))
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def get_scan_by_id(scan_id: int) -> Optional[dict]:
    """Get a specific scan with all its devices"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        
        # Get scan
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan_row = await cursor.fetchone()
        
        if not scan_row:
            return None
        
        scan = dict(scan_row)
        
        # Get devices
        cursor = await db.execute("SELECT * FROM devices WHERE scan_id = ?", (scan_id,))
        device_rows = await cursor.fetchall()
        
        devices = []
        for row in device_rows:
            device = dict(row)
            device["ports"] = json.loads(device["ports_json"])
            device["risk"] = {
                "level": device["risk_level"],
                "score": device["risk_score"],
                "reasons": json.loads(device["risk_reasons_json"])
            }
            # Clean up JSON fields
            del device["ports_json"]
            del device["risk_reasons_json"]
            del device["risk_level"]
            del device["risk_score"]
            devices.append(device)
        
        scan["devices"] = devices
        return scan


async def get_previous_scan() -> Optional[dict]:
    """Get the previous scan (second most recent)"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("""
            SELECT id FROM scans ORDER BY created_at DESC LIMIT 1 OFFSET 1
        """)
        row = await cursor.fetchone()
        
        if row:
            return await get_scan_by_id(row["id"])
        return None


async def compare_scans(current_scan: dict, previous_scan: Optional[dict]) -> list:
    """
    Compare two scans and return alerts for:
    - New devices
    - New high/medium risk devices
    - New open ports
    """
    alerts = []
    
    if not previous_scan:
        return alerts
    
    prev_ips = {d["ip"]: d for d in previous_scan.get("devices", [])}
    
    for device in current_scan.get("devices", []):
        ip = device["ip"]
        
        # New device detected
        if ip not in prev_ips:
            alerts.append({
                "type": "NEW_DEVICE",
                "severity": "MEDIUM",
                "device_ip": ip,
                "message": f"New device detected: {ip} ({device.get('vendor', 'Unknown')})"
            })
            continue
        
        prev_device = prev_ips[ip]
        
        # Risk level increased
        risk_order = {"MINIMAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
        current_risk = device.get("risk", {}).get("level", "MINIMAL")
        prev_risk = prev_device.get("risk", {}).get("level", "MINIMAL")
        
        if risk_order.get(current_risk, 0) > risk_order.get(prev_risk, 0):
            alerts.append({
                "type": "RISK_INCREASED",
                "severity": current_risk,
                "device_ip": ip,
                "message": f"Risk increased on {ip}: {prev_risk} -> {current_risk}"
            })
        
        # New ports opened
        prev_ports = {p["port"] for p in prev_device.get("ports", [])}
        current_ports = {p["port"] for p in device.get("ports", [])}
        new_ports = current_ports - prev_ports
        
        if new_ports:
            port_list = ", ".join(str(p) for p in sorted(new_ports))
            alerts.append({
                "type": "NEW_PORTS",
                "severity": "MEDIUM",
                "device_ip": ip,
                "message": f"New ports opened on {ip}: {port_list}"
            })
    
    return alerts


async def save_alert(scan_id: int, alert: dict):
    """Save an alert to the database"""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO alerts (scan_id, device_ip, alert_type, message, severity)
            VALUES (?, ?, ?, ?, ?)
        """, (
            scan_id,
            alert.get("device_ip"),
            alert["type"],
            alert["message"],
            alert["severity"]
        ))
        await db.commit()


async def get_alerts(limit: int = 100, unnotified_only: bool = False) -> list:
    """Get recent alerts"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        
        query = "SELECT * FROM alerts"
        if unnotified_only:
            query += " WHERE notified = FALSE"
        query += " ORDER BY created_at DESC LIMIT ?"
        
        cursor = await db.execute(query, (limit,))
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def mark_alerts_notified(alert_ids: list):
    """Mark alerts as notified"""
    async with aiosqlite.connect(DB_PATH) as db:
        placeholders = ",".join("?" * len(alert_ids))
        await db.execute(f"""
            UPDATE alerts SET notified = TRUE WHERE id IN ({placeholders})
        """, alert_ids)
        await db.commit()


async def get_setting(key: str, default: str = None) -> Optional[str]:
    """Get a setting value"""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = await cursor.fetchone()
        return row[0] if row else default


async def set_setting(key: str, value: str):
    """Set a setting value"""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)
        """, (key, value))
        await db.commit()
