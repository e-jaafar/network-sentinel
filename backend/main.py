#!/usr/bin/env python3
"""
Network Sentinel - FastAPI Backend
Provides REST API for network scanning and AI-powered security analysis
"""

import os
import sys
import json
import asyncio
from datetime import datetime, timedelta
from typing import Optional
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Add modules to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scanner"))
sys.path.insert(0, str(Path(__file__).parent))

from database import (
    init_db, save_scan, get_scan_history, get_scan_by_id, 
    get_previous_scan, compare_scans, save_alert, get_alerts,
    mark_alerts_notified, get_setting, set_setting
)
from discord_notify import send_discord_alert, send_scan_complete_notification
from pdf_report import generate_pdf_report
from auth import (
    Token, LoginRequest, User, 
    authenticate_user, create_access_token, get_current_user,
    hash_password, ACCESS_TOKEN_EXPIRE_HOURS
)

app = FastAPI(
    title="Network Sentinel API",
    description="AI-powered network security monitoring",
    version="2.0.0"
)

# CORS for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Paths
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
SCAN_RESULTS_FILE = DATA_DIR / "scan_results.json"

# Ollama config
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:1b")

# Global state
scan_in_progress = False
connected_clients: list[WebSocket] = []


# Pydantic models
class ScanRequest(BaseModel):
    network: Optional[str] = None
    scan_ports: bool = True


class AIAnalysisRequest(BaseModel):
    device_ip: Optional[str] = None


class DiscordWebhookConfig(BaseModel):
    webhook_url: str


class ScanResult(BaseModel):
    scan_time: str
    network: str
    device_count: int
    devices: list


# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    await init_db()
    print("[Startup] Database initialized")


# WebSocket manager
async def broadcast_message(message: dict):
    """Send message to all connected WebSocket clients"""
    for client in connected_clients:
        try:
            await client.send_json(message)
        except Exception:
            pass


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_json({"type": "pong", "data": data})
    except WebSocketDisconnect:
        connected_clients.remove(websocket)


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "online",
        "service": "Network Sentinel API",
        "version": "2.0.0",
        "ollama_model": OLLAMA_MODEL
    }


# ==================== AUTH ENDPOINTS ====================

@app.post("/api/auth/login", response_model=Token)
async def login(request: LoginRequest):
    """Authenticate and get access token"""
    user = await authenticate_user(request.username, request.password)
    
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )
    
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    )
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_HOURS * 3600
    )


@app.get("/api/auth/me")
async def get_me(current_user: User = Depends(get_current_user)):
    """Get current authenticated user"""
    return {"username": current_user.username}


@app.post("/api/auth/change-password")
async def change_password(
    current_user: User = Depends(get_current_user),
    old_password: str = "",
    new_password: str = ""
):
    """Change admin password"""
    from auth import get_admin_credentials, verify_password
    
    _, current_hash = await get_admin_credentials()
    
    if not verify_password(old_password, current_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    if len(new_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    
    new_hash = hash_password(new_password)
    await set_setting("admin_password_hash", new_hash)
    
    return {"status": "success", "message": "Password changed successfully"}


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


@app.post("/api/auth/change-password")
async def change_password_v2(
    request: ChangePasswordRequest,
    current_user: User = Depends(get_current_user)
):
    """Change admin password"""
    from auth import get_admin_credentials, verify_password
    
    _, current_hash = await get_admin_credentials()
    
    if not verify_password(request.old_password, current_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    if len(request.new_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    
    new_hash = hash_password(request.new_password)
    await set_setting("admin_password_hash", new_hash)
    
    return {"status": "success", "message": "Password changed successfully"}


# ==================== SCAN ENDPOINTS ====================

@app.get("/api/scan/latest")
async def get_latest_scan(current_user: User = Depends(get_current_user)):
    """Get the most recent scan results"""
    if not SCAN_RESULTS_FILE.exists():
        raise HTTPException(status_code=404, detail="No scan results found. Run a scan first.")
    
    with open(SCAN_RESULTS_FILE) as f:
        results = json.load(f)
    
    return results


@app.get("/api/scan/history")
async def get_history(limit: int = 50, current_user: User = Depends(get_current_user)):
    """Get scan history from database"""
    history = await get_scan_history(limit)
    return {"scans": history, "count": len(history)}


@app.get("/api/scan/history/{scan_id}")
async def get_historical_scan(scan_id: int, current_user: User = Depends(get_current_user)):
    """Get a specific historical scan by ID"""
    scan = await get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return scan


@app.get("/api/scan/device/{ip}")
async def get_device(ip: str, current_user: User = Depends(get_current_user)):
    """Get details for a specific device"""
    if not SCAN_RESULTS_FILE.exists():
        raise HTTPException(status_code=404, detail="No scan results found")
    
    with open(SCAN_RESULTS_FILE) as f:
        results = json.load(f)
    
    for device in results.get("devices", []):
        if device["ip"] == ip:
            return device
    
    raise HTTPException(status_code=404, detail=f"Device {ip} not found")


@app.post("/api/scan/start")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks, current_user: User = Depends(get_current_user)):
    """Start a new network scan"""
    global scan_in_progress
    
    if scan_in_progress:
        raise HTTPException(status_code=409, detail="Scan already in progress")
    
    scan_in_progress = True
    background_tasks.add_task(run_scan, request.network, request.scan_ports)
    
    return {"status": "started", "message": "Scan initiated in background"}


async def run_scan(network: Optional[str], scan_ports: bool):
    """Background task to run the network scan"""
    global scan_in_progress
    
    try:
        await broadcast_message({"type": "scan_started", "timestamp": datetime.now().isoformat()})
        
        # Get previous scan for comparison
        previous_scan = await get_previous_scan()
        
        # Run scanner script with sudo
        scanner_path = BASE_DIR / "scanner" / "network_scanner.py"
        venv_python = BASE_DIR / "venv" / "bin" / "python3"
        
        cmd = ["sudo", str(venv_python), str(scanner_path)]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode == 0:
            # Reload results
            with open(SCAN_RESULTS_FILE) as f:
                results = json.load(f)
            
            # Save to database
            scan_id = await save_scan(results)
            
            # Compare with previous scan and generate alerts
            alerts = await compare_scans(results, previous_scan)
            
            # Save alerts to database
            for alert in alerts:
                await save_alert(scan_id, alert)
            
            # Send Discord notification if alerts or webhook configured
            if alerts:
                webhook_url = await get_setting("discord_webhook_url")
                if webhook_url:
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
                    }
                    send_discord_alert(alerts, scan_summary, webhook_url=webhook_url)
            
            await broadcast_message({
                "type": "scan_complete",
                "timestamp": datetime.now().isoformat(),
                "device_count": results["device_count"],
                "scan_id": scan_id,
                "alerts": len(alerts)
            })
        else:
            await broadcast_message({
                "type": "scan_error",
                "error": stderr.decode() if stderr else "Unknown error"
            })
    
    except Exception as e:
        await broadcast_message({"type": "scan_error", "error": str(e)})
    
    finally:
        scan_in_progress = False


@app.get("/api/scan/status")
async def scan_status(current_user: User = Depends(get_current_user)):
    """Check if a scan is currently running"""
    return {"in_progress": scan_in_progress}


# ==================== ALERTS ENDPOINTS ====================

@app.get("/api/alerts")
async def list_alerts(limit: int = 100, current_user: User = Depends(get_current_user)):
    """Get recent security alerts"""
    alerts = await get_alerts(limit)
    return {"alerts": alerts, "count": len(alerts)}


@app.get("/api/alerts/unnotified")
async def list_unnotified_alerts(current_user: User = Depends(get_current_user)):
    """Get alerts that haven't been sent to Discord yet"""
    alerts = await get_alerts(unnotified_only=True)
    return {"alerts": alerts, "count": len(alerts)}


# ==================== AI ENDPOINTS ====================

@app.post("/api/ai/analyze")
async def ai_analyze(request: AIAnalysisRequest, current_user: User = Depends(get_current_user)):
    """Use Ollama to analyze scan results"""
    if not SCAN_RESULTS_FILE.exists():
        raise HTTPException(status_code=404, detail="No scan results found. Run a scan first.")
    
    with open(SCAN_RESULTS_FILE) as f:
        scan_data = json.load(f)
    
    if request.device_ip:
        devices = [d for d in scan_data["devices"] if d["ip"] == request.device_ip]
        if not devices:
            raise HTTPException(status_code=404, detail=f"Device {request.device_ip} not found")
    else:
        devices = scan_data["devices"]
    
    prompt = build_analysis_prompt(devices, scan_data["network"])
    
    try:
        analysis = await call_ollama(prompt)
        return {
            "analysis": analysis,
            "analyzed_devices": len(devices),
            "model": OLLAMA_MODEL,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")


@app.get("/api/ai/quick-summary")
async def ai_quick_summary(current_user: User = Depends(get_current_user)):
    """Get a quick AI-generated summary"""
    if not SCAN_RESULTS_FILE.exists():
        raise HTTPException(status_code=404, detail="No scan results found")
    
    with open(SCAN_RESULTS_FILE) as f:
        scan_data = json.load(f)
    
    risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "MINIMAL": 0}
    for device in scan_data["devices"]:
        level = device.get("risk", {}).get("level", "MINIMAL")
        risk_counts[level] = risk_counts.get(level, 0) + 1
    
    prompt = f"""You are a helpful home network assistant for a legitimate network monitoring dashboard. The user owns this network and wants to understand their devices.

This is a HOME NETWORK scan from a security monitoring tool the user installed on their own Raspberry Pi. This is NOT hacking - it's the user checking their own devices.

Please give a brief 2-3 sentence summary of what you see:

Network: {scan_data['network']}
Total devices found: {scan_data['device_count']}
Device categories:
- Devices needing attention: {risk_counts['HIGH']}
- Devices to review: {risk_counts['MEDIUM']}
- Normal devices: {risk_counts['LOW'] + risk_counts['MINIMAL']}

Respond naturally about the network health. Example: "Your network has X devices. Everything looks normal." or "You have X devices, and Y might need attention due to open ports."""

    try:
        summary = await call_ollama(prompt)
        return {
            "summary": summary,
            "risk_counts": risk_counts,
            "total_devices": scan_data["device_count"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI summary failed: {str(e)}")


def build_analysis_prompt(devices: list, network: str) -> str:
    """Build a detailed prompt for security analysis"""
    devices_info = []
    for d in devices:
        info = f"- IP: {d['ip']}, MAC: {d['mac']}, Vendor: {d.get('vendor', 'Unknown')}"
        if d.get('hostname'):
            info += f", Hostname: {d['hostname']}"
        if d.get('ports'):
            ports = [f"{p['port']}/{p['service']}" for p in d['ports']]
            info += f", Open Ports: {', '.join(ports)}"
        if d.get('risk', {}).get('reasons'):
            info += f", Risk Issues: {'; '.join(d['risk']['reasons'])}"
        devices_info.append(info)
    
    return f"""You are a helpful home network assistant. The user owns this network and installed a monitoring dashboard on their Raspberry Pi to understand their devices better.

This is a LEGITIMATE home network audit - the user wants to know what is connected to their own WiFi and if anything needs attention.

Please analyze these scan results and provide:

1. **Overview**: What kind of network is this? (home network, small office, etc.)
2. **Device Summary**: What types of devices are connected?
3. **Things to Check**: Any devices with services that might need attention (like open ports)
4. **Tips**: Simple suggestions to keep the network healthy

Network: {network}
Devices found: {len(devices)}

Device Details:
{chr(10).join(devices_info)}

Be helpful and friendly. Use simple language. Format with markdown."""


async def call_ollama(prompt: str) -> str:
    """Call Ollama API for text generation"""
    async with httpx.AsyncClient(timeout=180.0) as client:
        response = await client.post(
            f"{OLLAMA_HOST}/api/generate",
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.7, "top_p": 0.9}
            }
        )
        
        if response.status_code != 200:
            raise Exception(f"Ollama returned status {response.status_code}: {response.text}")
        
        result = response.json()
        return result.get("response", "No response generated")


@app.get("/api/ollama/status")
async def ollama_status():
    """Check if Ollama is available"""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{OLLAMA_HOST}/api/tags")
            
            if response.status_code == 200:
                models = response.json().get("models", [])
                model_names = [m["name"] for m in models]
                return {
                    "status": "online",
                    "host": OLLAMA_HOST,
                    "models": model_names,
                    "default_model": OLLAMA_MODEL,
                    "model_available": OLLAMA_MODEL in model_names or any(OLLAMA_MODEL.split(":")[0] in m for m in model_names)
                }
            else:
                return {"status": "error", "message": f"Unexpected status: {response.status_code}"}
    
    except httpx.ConnectError:
        return {"status": "offline", "message": "Cannot connect to Ollama"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ==================== REPORT ENDPOINTS ====================

@app.get("/api/report/pdf")
async def generate_report(scan_id: Optional[int] = None, include_ai: bool = False, current_user: User = Depends(get_current_user)):
    """Generate a PDF security report"""
    
    # Get scan data
    if scan_id:
        scan_data = await get_scan_by_id(scan_id)
        if not scan_data:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    else:
        if not SCAN_RESULTS_FILE.exists():
            raise HTTPException(status_code=404, detail="No scan results found")
        with open(SCAN_RESULTS_FILE) as f:
            scan_data = json.load(f)
    
    # Optionally include AI analysis
    ai_analysis = None
    if include_ai:
        try:
            prompt = build_analysis_prompt(scan_data.get("devices", []), scan_data.get("network", "Unknown"))
            ai_analysis = await call_ollama(prompt)
        except Exception as e:
            print(f"[PDF] AI analysis failed: {e}")
    
    # Generate PDF
    pdf_bytes = generate_pdf_report(scan_data, ai_analysis)
    
    filename = f"network_sentinel_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# ==================== SETTINGS ENDPOINTS ====================

@app.get("/api/settings/discord")
async def get_discord_settings(current_user: User = Depends(get_current_user)):
    """Get Discord webhook configuration status"""
    webhook_url = await get_setting("discord_webhook_url")
    return {
        "configured": bool(webhook_url),
        "webhook_url_masked": webhook_url[:50] + "..." if webhook_url and len(webhook_url) > 50 else None
    }


@app.post("/api/settings/discord")
async def set_discord_webhook(config: DiscordWebhookConfig, current_user: User = Depends(get_current_user)):
    """Configure Discord webhook for notifications"""
    await set_setting("discord_webhook_url", config.webhook_url)
    
    # Update environment variable for current session
    os.environ["DISCORD_WEBHOOK_URL"] = config.webhook_url
    
    return {"status": "configured", "message": "Discord webhook URL saved"}


@app.post("/api/settings/discord/test")
async def test_discord_webhook(current_user: User = Depends(get_current_user)):
    """Send a test notification to Discord"""
    webhook_url = await get_setting("discord_webhook_url")
    if not webhook_url:
        raise HTTPException(status_code=400, detail="Discord webhook not configured")
    
    test_alerts = [{
        "type": "TEST",
        "severity": "LOW",
        "device_ip": "192.168.1.1",
        "message": "This is a test notification from Network Sentinel"
    }]
    
    success = send_discord_alert(test_alerts, {
        "network": "Test Network",
        "device_count": 1,
        "total_ports": 0
    }, webhook_url=webhook_url)
    
    if success:
        return {"status": "sent", "message": "Test notification sent to Discord"}
    else:
        raise HTTPException(status_code=500, detail="Failed to send test notification")


# ==================== STATS ENDPOINT ====================

@app.get("/api/stats")
async def get_stats(current_user: User = Depends(get_current_user)):
    """Get overall network statistics"""
    if not SCAN_RESULTS_FILE.exists():
        return {"has_data": False, "message": "No scan data available"}
    
    with open(SCAN_RESULTS_FILE) as f:
        data = json.load(f)
    
    total_ports = sum(len(d.get("ports", [])) for d in data["devices"])
    risk_counts = {}
    vendors = {}
    
    for device in data["devices"]:
        level = device.get("risk", {}).get("level", "MINIMAL")
        risk_counts[level] = risk_counts.get(level, 0) + 1
        vendor = device.get("vendor", "Unknown")
        vendors[vendor] = vendors.get(vendor, 0) + 1
    
    # Get scan history count
    history = await get_scan_history(limit=1000)
    
    return {
        "has_data": True,
        "scan_time": data["scan_time"],
        "network": data["network"],
        "total_devices": data["device_count"],
        "total_open_ports": total_ports,
        "risk_distribution": risk_counts,
        "vendor_distribution": vendors,
        "total_scans": len(history)
    }


if __name__ == "__main__":
    import uvicorn
    
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    print("Starting Network Sentinel API v2.0...")
    print(f"Ollama Host: {OLLAMA_HOST}")
    print(f"Ollama Model: {OLLAMA_MODEL}")
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
