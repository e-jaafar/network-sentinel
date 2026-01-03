#!/usr/bin/env python3
"""
Discord notification module for Network Sentinel
"""

import os
from discord_webhook import DiscordWebhook, DiscordEmbed
from typing import Optional


def get_webhook_url() -> str:
    """Get webhook URL from environment (set dynamically)"""
    return os.getenv("DISCORD_WEBHOOK_URL", "")


def send_discord_alert(alerts: list, scan_summary: dict, webhook_url: str = None) -> bool:
    """
    Send security alerts to Discord
    Returns True if sent successfully
    """
    url = webhook_url or get_webhook_url()
    if not url:
        print("[Discord] No webhook URL configured")
        return False
    
    if not alerts:
        return True
    
    webhook = DiscordWebhook(url=url)
    
    # Create embed
    embed = DiscordEmbed(
        title="Network Sentinel Alert",
        description=f"Security changes detected on network `{scan_summary.get('network', 'Unknown')}`",
        color="ff0055" if any(a["severity"] == "HIGH" for a in alerts) else "ffcc00"
    )
    
    # Add scan summary
    embed.add_embed_field(
        name="Scan Summary",
        value=f"Devices: {scan_summary.get('device_count', 0)} | Open Ports: {scan_summary.get('total_ports', 0)}",
        inline=False
    )
    
    # Add alerts
    for alert in alerts[:10]:  # Limit to 10 alerts
        severity_emoji = {
            "HIGH": "[!]",
            "MEDIUM": "[*]",
            "LOW": "[-]",
            "MINIMAL": "[.]"
        }.get(alert["severity"], "[.]")
        
        embed.add_embed_field(
            name=f"{severity_emoji} {alert['type']}",
            value=alert["message"],
            inline=False
        )
    
    if len(alerts) > 10:
        embed.add_embed_field(
            name="",
            value=f"*...and {len(alerts) - 10} more alerts*",
            inline=False
        )
    
    embed.set_footer(text="Network Sentinel | Powered by Llama 3.2")
    embed.set_timestamp()
    
    webhook.add_embed(embed)
    
    try:
        response = webhook.execute()
        print(f"[Discord] Alert sent successfully")
        return True
    except Exception as e:
        print(f"[Discord] Failed to send alert: {e}")
        return False


def send_scan_complete_notification(scan_summary: dict, webhook_url: str = None) -> bool:
    """Send a notification that scan completed (even without alerts)"""
    url = webhook_url or get_webhook_url()
    if not url:
        return False
    
    webhook = DiscordWebhook(url=url)
    
    risk_emoji = "[OK]"
    if scan_summary.get("high_risk", 0) > 0:
        risk_emoji = "[!!!]"
    elif scan_summary.get("medium_risk", 0) > 0:
        risk_emoji = "[!!]"
    
    embed = DiscordEmbed(
        title=f"{risk_emoji} Network Scan Complete",
        color="00ff88"
    )
    
    embed.add_embed_field(name="Network", value=scan_summary.get("network", "Unknown"), inline=True)
    embed.add_embed_field(name="Devices", value=str(scan_summary.get("device_count", 0)), inline=True)
    embed.add_embed_field(name="Open Ports", value=str(scan_summary.get("total_ports", 0)), inline=True)
    
    risk_str = f"High: {scan_summary.get('high_risk', 0)} | Medium: {scan_summary.get('medium_risk', 0)} | Low: {scan_summary.get('low_risk', 0)}"
    embed.add_embed_field(name="Risk Summary", value=risk_str, inline=False)
    
    embed.set_footer(text="Network Sentinel")
    embed.set_timestamp()
    
    webhook.add_embed(embed)
    
    try:
        webhook.execute()
        return True
    except Exception as e:
        print(f"[Discord] Failed to send notification: {e}")
        return False
