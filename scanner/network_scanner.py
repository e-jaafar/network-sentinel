#!/usr/bin/env python3
"""
Network Scanner - Scans local network for devices and open ports
Requires root/sudo to send ARP packets
"""

import json
import socket
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from scapy.all import ARP, Ether, srp, conf
import netifaces

# Suppress Scapy warnings
conf.verb = 0

# Common ports to scan
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1883: "MQTT",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8883: "MQTT-TLS",
    9000: "PHP-FPM",
    27017: "MongoDB",
    32400: "Plex",
}


def get_local_network() -> str:
    """Auto-detect the local network CIDR"""
    try:
        # Get the default gateway interface
        gateways = netifaces.gateways()
        default_interface = gateways['default'][netifaces.AF_INET][1]
        
        # Get the IP and netmask for that interface
        addrs = netifaces.ifaddresses(default_interface)
        ip = addrs[netifaces.AF_INET][0]['addr']
        netmask = addrs[netifaces.AF_INET][0]['netmask']
        
        # Calculate CIDR (simple approach for common netmasks)
        netmask_to_cidr = {
            "255.255.255.0": 24,
            "255.255.0.0": 16,
            "255.0.0.0": 8,
        }
        cidr = netmask_to_cidr.get(netmask, 24)
        
        # Return network CIDR
        network_parts = ip.split('.')
        network_parts[3] = '0'
        return f"{'.'.join(network_parts)}/{cidr}"
    except Exception as e:
        print(f"[!] Could not auto-detect network: {e}")
        return "192.168.1.0/24"


def get_hostname(ip: str) -> Optional[str]:
    """Try to resolve hostname from IP"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror):
        return None


def scan_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a specific port is open on the target IP"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def scan_ports(ip: str, ports: list[int] = None, timeout: float = 0.5) -> list[dict]:
    """Scan multiple ports on a single IP"""
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_port = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
        
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append({
                        "port": port,
                        "service": COMMON_PORTS.get(port, "Unknown")
                    })
            except Exception:
                pass
    
    return sorted(open_ports, key=lambda x: x["port"])


def arp_scan(network: str, timeout: int = 3) -> list[dict]:
    """
    Perform ARP scan to discover devices on the network.
    Requires root privileges.
    """
    print(f"[*] Scanning network: {network}")
    
    # Create ARP request packet
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    
    # Send packets and receive responses
    result = srp(packet, timeout=timeout, verbose=False)[0]
    
    devices = []
    for sent, received in result:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc.upper(),
        })
    
    print(f"[+] Found {len(devices)} device(s)")
    return devices


def get_mac_vendor(mac: str) -> str:
    """
    Get vendor from MAC address (first 3 octets = OUI)
    This is a simplified version - full implementation would use an OUI database
    """
    # Common vendor prefixes (you can expand this)
    oui_database = {
        "B8:27:EB": "Raspberry Pi",
        "DC:A6:32": "Raspberry Pi",
        "E4:5F:01": "Raspberry Pi",
        "D8:3A:DD": "Raspberry Pi",
        "2C:CF:67": "Apple",
        "F0:18:98": "Apple",
        "A4:83:E7": "Apple",
        "00:1A:2B": "Cisco",
        "00:50:56": "VMware",
        "52:54:00": "QEMU/KVM",
        "00:15:5D": "Microsoft Hyper-V",
        "94:65:9C": "Intel",
        "AC:22:0B": "ASRock",
        "00:E0:4C": "Realtek",
        "00:0C:29": "VMware",
        "00:1B:21": "Intel",
        "00:1E:67": "Intel",
        "3C:7C:3F": "ASUSTek",
        "00:26:B9": "Dell",
        "F8:B1:56": "Dell",
        "30:9C:23": "Intel",
        "F4:39:09": "HP",
    }
    
    mac_prefix = mac[:8].upper()
    return oui_database.get(mac_prefix, "Unknown")


def calculate_risk_score(device: dict) -> dict:
    """
    Calculate a basic risk score for a device based on open ports
    Returns risk level and reasons
    """
    risk_score = 0
    risk_reasons = []
    
    high_risk_ports = {
        21: ("FTP", "Unencrypted file transfer"),
        23: ("Telnet", "Unencrypted remote access"),
        445: ("SMB", "Potential ransomware vector"),
        3389: ("RDP", "Remote desktop exposure"),
        5900: ("VNC", "Remote desktop exposure"),
    }
    
    medium_risk_ports = {
        22: ("SSH", "Remote access enabled"),
        25: ("SMTP", "Mail server running"),
        3306: ("MySQL", "Database exposed"),
        5432: ("PostgreSQL", "Database exposed"),
        6379: ("Redis", "Database exposed - often no auth"),
        27017: ("MongoDB", "Database exposed"),
    }
    
    open_ports = device.get("ports", [])
    
    for port_info in open_ports:
        port = port_info["port"]
        
        if port in high_risk_ports:
            risk_score += 30
            name, reason = high_risk_ports[port]
            risk_reasons.append(f"HIGH: Port {port} ({name}) - {reason}")
        
        elif port in medium_risk_ports:
            risk_score += 15
            name, reason = medium_risk_ports[port]
            risk_reasons.append(f"MEDIUM: Port {port} ({name}) - {reason}")
    
    # Determine risk level
    if risk_score >= 50:
        risk_level = "HIGH"
    elif risk_score >= 20:
        risk_level = "MEDIUM"
    elif risk_score > 0:
        risk_level = "LOW"
    else:
        risk_level = "MINIMAL"
    
    return {
        "score": min(risk_score, 100),
        "level": risk_level,
        "reasons": risk_reasons
    }


def full_scan(network: str = None, scan_ports_flag: bool = True) -> dict:
    """
    Perform a full network scan:
    1. ARP scan to find devices
    2. Port scan on each device
    3. Risk assessment
    """
    if network is None:
        network = get_local_network()
    
    print("=" * 60)
    print(f"  Network Sentinel Scanner")
    print(f"  Started: {datetime.now().isoformat()}")
    print("=" * 60)
    
    # Step 1: ARP Scan
    devices = arp_scan(network)
    
    # Step 2: Enrich each device
    for i, device in enumerate(devices):
        ip = device["ip"]
        print(f"\n[{i+1}/{len(devices)}] Scanning {ip}...")
        
        # Get hostname
        hostname = get_hostname(ip)
        device["hostname"] = hostname
        
        # Get vendor
        device["vendor"] = get_mac_vendor(device["mac"])
        
        # Port scan
        if scan_ports_flag:
            print(f"    [*] Scanning ports...")
            device["ports"] = scan_ports(ip)
            print(f"    [+] Found {len(device['ports'])} open port(s)")
        else:
            device["ports"] = []
        
        # Risk assessment
        device["risk"] = calculate_risk_score(device)
        print(f"    [*] Risk level: {device['risk']['level']}")
    
    # Build result
    result = {
        "scan_time": datetime.now().isoformat(),
        "network": network,
        "device_count": len(devices),
        "devices": devices
    }
    
    print("\n" + "=" * 60)
    print(f"  Scan complete! Found {len(devices)} device(s)")
    print("=" * 60)
    
    return result


def save_results(results: dict, filepath: str = "data/scan_results.json"):
    """Save scan results to JSON file"""
    import os
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)
    
    with open(filepath, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"[+] Results saved to {filepath}")


def print_summary(results: dict):
    """Print a nice summary of the scan results"""
    print("\n" + "=" * 70)
    print("  SCAN SUMMARY")
    print("=" * 70)
    
    for device in results["devices"]:
        risk_emoji = {
            "HIGH": "[!!!]",
            "MEDIUM": "[!!]", 
            "LOW": "[!]",
            "MINIMAL": "[OK]"
        }
        
        print(f"\n{risk_emoji.get(device['risk']['level'], '[?]')} {device['ip']}")
        print(f"    MAC: {device['mac']} ({device['vendor']})")
        if device['hostname']:
            print(f"    Hostname: {device['hostname']}")
        
        if device['ports']:
            ports_str = ", ".join([f"{p['port']}/{p['service']}" for p in device['ports']])
            print(f"    Open Ports: {ports_str}")
        
        if device['risk']['reasons']:
            print(f"    Risk: {device['risk']['level']} (Score: {device['risk']['score']})")
            for reason in device['risk']['reasons']:
                print(f"      - {reason}")


if __name__ == "__main__":
    import sys
    import os
    
    # Check for root privileges (required for ARP scanning)
    if os.geteuid() != 0:
        print("[!] This script requires root privileges for ARP scanning.")
        print("[!] Please run with: sudo python3 network_scanner.py")
        sys.exit(1)
    
    # Run full scan
    results = full_scan()
    
    # Print summary
    print_summary(results)
    
    # Save results
    script_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(os.path.dirname(script_dir), "data")
    save_results(results, os.path.join(data_dir, "scan_results.json"))
