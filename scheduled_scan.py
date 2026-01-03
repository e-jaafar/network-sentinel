#!/usr/bin/env python3
"""
Scheduled scan script for Network Sentinel
Run via cron to perform automatic network scans
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from datetime import datetime

# Add paths
BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR / "backend"))
sys.path.insert(0, str(BASE_DIR / "scanner"))

# Activate virtual environment packages
venv_path = BASE_DIR / "venv" / "lib" / "python3.11" / "site-packages"
sys.path.insert(0, str(venv_path))

from database import init_db, save_scan, get_previous_scan, compare_scans, save_alert, get_setting
from discord_notify import send_discord_alert, send_scan_complete_notification
from network_scanner import full_scan, save_results

DATA_DIR = BASE_DIR / "data"
SCAN_RESULTS_FILE = DATA_DIR / "scan_results.json"
LOG_FILE = DATA_DIR / "scheduled_scans.log"


def log(message: str):
    """Log message to file and stdout"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] {message}"
    print(log_line)
    
    with open(LOG_FILE, "a") as f:
        f.write(log_line + "\n")


async def run_scheduled_scan():
    """Run a scheduled network scan with all features"""
    
    log("Starting scheduled scan...")
    
    # Ensure data directory exists
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    # Initialize database
    await init_db()
    
    # Get previous scan for comparison
    previous_scan = await get_previous_scan()
    log(f"Previous scan loaded: {previous_scan is not None}")
    
    # Run the network scan
    try:
        results = full_scan()
        log(f"Scan complete: {results['device_count']} devices found")
    except Exception as e:
        log(f"ERROR: Scan failed - {e}")
        return
    
    # Save results to JSON file
    save_results(results, str(SCAN_RESULTS_FILE))
    log(f"Results saved to {SCAN_RESULTS_FILE}")
    
    # Save to database
    scan_id = await save_scan(results)
    log(f"Scan saved to database with ID: {scan_id}")
    
    # Compare with previous scan
    alerts = await compare_scans(results, previous_scan)
    log(f"Generated {len(alerts)} alerts")
    
    # Save alerts
    for alert in alerts:
        await save_alert(scan_id, alert)
    
    # Load Discord webhook from database
    webhook_url = await get_setting("discord_webhook_url")
    if webhook_url:
        os.environ["DISCORD_WEBHOOK_URL"] = webhook_url
        log("Discord webhook configured")
        
        # Calculate summary
        risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "MINIMAL": 0}
        for d in results["devices"]:
            level = d.get("risk", {}).get("level", "MINIMAL")
            risk_counts[level] += 1
        
        scan_summary = {
            "network": results["network"],
            "device_count": results["device_count"],
            "total_ports": sum(len(d.get("ports", [])) for d in results["devices"]),
            "high_risk": risk_counts["HIGH"],
            "medium_risk": risk_counts["MEDIUM"],
            "low_risk": risk_counts["LOW"],
        }
        
        # Send Discord notification
        if alerts:
            success = send_discord_alert(alerts, scan_summary, webhook_url=webhook_url)
            log(f"Discord alert sent: {success}")
        else:
            # Optionally send a "scan complete" notification even without alerts
            # Uncomment the next line if you want notifications for every scan
            # send_scan_complete_notification(scan_summary)
            log("No alerts to send")
    else:
        log("Discord webhook not configured - skipping notification")
    
    log("Scheduled scan completed successfully")


def main():
    """Main entry point"""
    # Check for root privileges
    if os.geteuid() != 0:
        print("ERROR: This script requires root privileges for ARP scanning.")
        print("Run with: sudo python3 scheduled_scan.py")
        sys.exit(1)
    
    # Run the async scan
    asyncio.run(run_scheduled_scan())


if __name__ == "__main__":
    main()
