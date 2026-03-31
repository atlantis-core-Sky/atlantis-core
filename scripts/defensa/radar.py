#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
ATLANTIS - RADAR PASIVO v2.5 (RUTAS RELATIVAS)
Monitoreo silencioso de red
• Detecta automáticamente la red actual
• Sanitización de inputs para evitar inyección de comandos
• Funciona en cualquier red (casa, trabajo, café, hotel)
• RUTAS RELATIVAS al ejecutable de Atlantis
"""

import os
import sys
import json
import time
import socket
import threading
import argparse
import subprocess
import platform
import signal
import shlex
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

# ============================================================
# DETECCIÓN DE RUTA BASE
# ============================================================
def get_base_path():
    """Obtiene la ruta base del ejecutable de Atlantis"""
    try:
        import subprocess as sp
        result = sp.run(["which", "atlantis"], capture_output=True, text=True)
        if result.returncode == 0:
            exe_path = Path(result.stdout.strip())
            return exe_path.parent
    except:
        pass
    
    script_dir = Path(__file__).parent.absolute()
    return script_dir.parent.parent

# ============================================================
# CONFIGURACIÓN - RUTAS RELATIVAS
# ============================================================
BASE_PATH = get_base_path()
DATA_DIR = BASE_PATH / "data"
DEFENSA_DIR = DATA_DIR / "defensa"

DATA_DIR.mkdir(parents=True, exist_ok=True)
DEFENSA_DIR.mkdir(parents=True, exist_ok=True)

RADAR_LOG = DEFENSA_DIR / "radar.log"
DEVICES_DB = DEFENSA_DIR / "radar_devices.json"
ALERTS_FILE = DEFENSA_DIR / "radar_alerts.json"

print(f"📁 Data directory: {DATA_DIR}", file=sys.stderr)

# ============================================================
# SANITIZACIÓN DE INPUTS
# ============================================================
def sanitize_input(input_str):
    if not input_str:
        return ""
    return shlex.quote(str(input_str))

def is_wsl():
    try:
        release = platform.uname().release.lower()
        return 'microsoft' in release or 'wsl' in release
    except:
        return False

# ============================================================
# DETECCIÓN AUTOMÁTICA DE RED
# ============================================================
def detectar_red_actual():
    try:
        import ipaddress
        import netifaces

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_local = s.getsockname()[0]
        s.close()

        gateways = netifaces.gateways()
        iface = gateways['default'][netifaces.AF_INET][1]
        addrs = netifaces.ifaddresses(iface)
        netmask = addrs[netifaces.AF_INET][0]['netmask']

        red = ipaddress.IPv4Network(f"{ip_local}/{netmask}", strict=False)
        return str(red)
    except:
        return "192.168.1.0/24"

# ============================================================
# VENDOR DATABASE
# ============================================================
VENDORS = {
    "f4:69:42": "Askey Computer", "7c:70:db": "ASIX Electronics", "4c:1b:86": "Nothing Technology",
    "80:9d:65": "FN-Link Technology", "8e:7a:67": "Shark Robotics",
    "00:00:0c": "Cisco", "00:14:22": "Dell", "00:17:f2": "Apple", "00:1e:52": "Apple",
    "00:1f:f3": "Apple", "00:21:e9": "Samsung", "00:23:76": "HP", "00:25:00": "Apple",
    "08:00:27": "Oracle", "0c:9d:92": "Huawei", "1c:6f:65": "TP-Link", "20:4e:7f": "Asus",
    "24:4b:fe": "Microsoft", "28:6d:cd": "Xiaomi", "2c:33:7a": "Google", "30:9c:23": "Amazon",
    "34:96:72": "Intel", "38:0b:40": "Apple", "3c:5c:24": "Intel", "40:b0:76": "Apple",
    "44:65:0d": "Samsung", "48:5d:36": "Intel", "4c:7f:62": "Huawei", "50:2f:5e": "Intel",
    "54:60:09": "Intel", "5c:cf:7f": "Apple", "60:33:4b": "Intel", "64:66:b3": "Intel",
    "68:db:f5": "Intel", "6c:88:14": "Apple", "70:8b:cd": "Apple", "74:85:2a": "Apple",
    "78:4f:43": "Intel", "7c:11:cb": "Intel", "80:56:f2": "Intel", "84:7b:eb": "Apple",
    "88:66:5a": "Apple", "8c:85:90": "Intel", "90:0c:27": "Samsung", "94:65:2d": "Apple",
    "98:03:a0": "Apple", "9c:29:ef": "Intel", "a0:51:0b": "Intel", "a4:83:e7": "Intel",
    "a8:7e:ea": "Intel", "ac:1f:74": "Intel", "b0:7d:64": "Intel", "b4:0e:de": "Intel",
    "b8:8a:ec": "Intel", "bc:76:70": "Intel", "c0:25:a5": "Intel", "c4:41:1e": "Apple",
    "c8:69:cd": "Intel", "cc:3d:82": "Intel", "d0:17:6a": "Intel", "d4:3d:7e": "Intel",
    "d8:5b:2a": "Apple", "dc:2b:2a": "Intel", "e0:1c:fc": "Intel", "e4:70:b8": "Intel",
    "e8:48:1f": "Intel", "ec:8e:ae": "Intel", "f0:6e:0b": "Intel", "f4:6b:ef": "Intel",
    "f8:32:e4": "Intel", "fc:15:b4": "Intel",
}

class Radar:
    def __init__(self, interface: str = None, verbose: bool = False):
        self.interface = interface
        self.verbose = verbose
        self.running = False
        self.known_devices: Dict[str, Dict] = self._load_devices()
        self.activity_log: List[Dict] = []
        self.sniffer_thread = None
        self.alert_count = 0
        self.in_wsl = is_wsl()
        self.red_actual = detectar_red_actual()
        self._setup_signal_handlers()

    def _setup_signal_handlers(self):
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, sig, frame):
        print("\n🛑 Shutdown signal received. Stopping radar...")
        self.stop()
        sys.exit(0)

    def _load_devices(self) -> Dict[str, Dict]:
        try:
            with open(DEVICES_DB, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {}

    def _save_devices(self):
        try:
            with open(DEVICES_DB, 'w', encoding='utf-8') as f:
                json.dump(self.known_devices, f, indent=2, ensure_ascii=False)
            if self.verbose:
                print(f"💾 Saved {len(self.known_devices)} devices")
        except Exception as e:
            self._log(f"Error saving devices: {e}", "ERROR")

    def _log(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().isoformat()
        try:
            with open(RADAR_LOG, 'a', encoding='utf-8') as f:
                f.write(f"[{timestamp}] {level}: {message}\n")
        except:
            pass
        if self.verbose:
            print(f"{level}: {message}")

    def _alert(self, message: str, device: Dict = None):
        self.alert_count += 1
        alert = {"id": self.alert_count, "timestamp": datetime.now().isoformat(), "message": message, "device": device}
        try:
            alerts = []
            if ALERTS_FILE.exists():
                with open(ALERTS_FILE, 'r', encoding='utf-8') as f:
                    alerts = json.load(f)
            alerts.append(alert)
            if len(alerts) > 200:
                alerts = alerts[-200:]
            with open(ALERTS_FILE, 'w', encoding='utf-8') as f:
                json.dump(alerts, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self._log(f"Error saving alert: {e}", "ERROR")

        if not self.verbose:
            print(f"\n🚨 RADAR ALERT: {message}")
            if device:
                print(f"   Device: {device.get('ip', 'unknown')} | {device.get('mac', 'unknown')} | {device.get('vendor', 'Unknown')}")

    def _is_multicast(self, ip: str) -> bool:
        return ip.startswith("224.") or ip.startswith("239.") or ip == "255.255.255.255" or ip.startswith("0.")

    def _is_link_local(self, ip: str) -> bool:
        return ip.startswith("169.254.")

    def _get_vendor(self, mac: str) -> str:
        if not mac or mac == "unknown":
            return "Unknown"
        mac = mac.lower().replace('-', ':')
        for length in [8, 5]:
            pref = mac[:length]
            if pref in VENDORS:
                return VENDORS[pref]
        return "Unknown"

    def start(self):
        self.running = True
        self._log(f"Radar started (WSL: {self.in_wsl}) | Red: {self.red_actual}")
        self._schedule_save()

        if not self.in_wsl:
            try:
                from scapy.all import sniff, ARP, IP
                self.sniffer_thread = threading.Thread(target=self._sniff_loop)
                self.sniffer_thread.daemon = True
                self.sniffer_thread.start()
                self._log("Scapy sniffer started")
            except ImportError:
                self._log("Scapy not available", "WARNING")
        else:
            self._log("WSL mode - using ARP table monitoring", "INFO")

        self._monitor_arp()

    def _schedule_save(self):
        def saver():
            while self.running:
                time.sleep(30)
                self._save_devices()
        thread = threading.Thread(target=saver)
        thread.daemon = True
        thread.start()

    def stop(self):
        self.running = False
        self._save_devices()
        self._log("Radar stopped")

    def _sniff_loop(self):
        try:
            from scapy.all import sniff, ARP, IP
            sniff(filter="arp or ip", prn=self._packet_handler, store=0, stop_filter=lambda _: not self.running)
        except Exception as e:
            self._log(f"Sniffer error: {e}", "ERROR")

    def _packet_handler(self, packet):
        if not self.running:
            return
        try:
            if packet.haslayer('ARP'):
                arp = packet['ARP']
                src_ip = arp.psrc
                src_mac = arp.hwsrc.lower()
                if not self._is_multicast(src_ip) and not self._is_link_local(src_ip):
                    self._observe_device(src_ip, src_mac, "sniffed")
        except Exception as e:
            if self.verbose:
                print(f"Packet error: {e}")

    def _observe_device(self, ip: str, mac: str, role: str):
        if not mac or mac == "00:00:00:00:00:00":
            return
        mac = mac.lower().replace('-', ':')

        if ip in self.known_devices:
            device = self.known_devices[ip]
            if device.get('mac') != mac:
                self._alert(f"MAC change detected for {ip}", {"ip": ip, "old_mac": device.get('mac'), "new_mac": mac})
            device['last_seen'] = datetime.now().isoformat()
            device['last_role'] = role
            device['appearances'] = device.get('appearances', 0) + 1
        else:
            vendor = self._get_vendor(mac)
            device = {
                "ip": ip, "mac": mac, "vendor": vendor,
                "first_seen": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat(),
                "last_role": role, "appearances": 1,
                "hostname": self._resolve_hostname(ip)
            }
            self.known_devices[ip] = device
            if not ip.endswith(".1") and not ip.endswith(".254"):
                self._alert(f"New device detected: {ip}", device)

    def _resolve_hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Unknown"

    def _monitor_arp(self):
        last_check = 0
        while self.running:
            try:
                if time.time() - last_check > 10:
                    result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
                    for line in result.stdout.split('\n'):
                        parts = line.split()
                        if len(parts) >= 2 and '.' in parts[0]:
                            ip = parts[0]
                            mac = parts[1].replace('-', ':').lower() if len(parts) > 1 else "00:00:00:00:00:00"
                            if mac != "ff:ff:ff:ff:ff:ff" and not self._is_multicast(ip):
                                self._observe_device(ip, mac, "arp_table")
                    last_check = time.time()
                time.sleep(2)
            except Exception as e:
                if self.verbose:
                    print(f"ARP error: {e}")
                time.sleep(5)

    def get_devices(self) -> List[Dict]:
        return list(self.known_devices.values())

    def get_alerts(self, limit: int = 50) -> List[Dict]:
        try:
            with open(ALERTS_FILE, 'r', encoding='utf-8') as f:
                alerts = json.load(f)
                return alerts[-limit:]
        except:
            return []

    def get_stats(self) -> Dict[str, Any]:
        now = datetime.now()
        active_count = 0
        for d in self.known_devices.values():
            try:
                last = datetime.fromisoformat(d['last_seen'])
                if (now - last).total_seconds() < 300:
                    active_count += 1
            except:
                pass
        return {
            "total_devices_observed": len(self.known_devices),
            "active_devices_now": active_count,
            "total_alerts": len(self.get_alerts()),
            "running": self.running,
            "alert_count": self.alert_count,
            "wsl_mode": self.in_wsl,
            "red_actual": self.red_actual,
        }

def main():
    parser = argparse.ArgumentParser(description="ATLANTIS Passive Radar")
    parser.add_argument("--start", action="store_true", help="Start radar")
    parser.add_argument("--devices", action="store_true", help="List known devices")
    parser.add_argument("--alerts", action="store_true", help="Show recent alerts")
    parser.add_argument("--status", action="store_true", help="Show radar status")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    radar = Radar(verbose=args.verbose)

    if args.start:
        print("📡 Starting ATLANTIS Passive Radar...")
        print(f"   🌐 Red detectada: {radar.red_actual}")
        print("   Press Ctrl+C to stop\n")
        try:
            radar.start()
            while radar.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\n🛑 Stopping radar...")
            radar.stop()

    elif args.devices:
        devices = radar.get_devices()
        if args.json:
            print(json.dumps(devices, indent=2))
        else:
            print(f"\n📋 KNOWN DEVICES ({len(devices)})")
            print("="*70)
            print(f"{'IP':<16} {'MAC':<18} {'Vendor':<20} {'Last Seen'}")
            print("-"*70)
            for d in sorted(devices, key=lambda x: x.get('last_seen', ''), reverse=True)[:20]:
                ip = d.get('ip', 'unknown')
                mac = d.get('mac', 'unknown')
                vendor = d.get('vendor', 'Unknown')[:18]
                last = d.get('last_seen', '')[:16] if d.get('last_seen') else 'unknown'
                print(f"{ip:<16} {mac:<18} {vendor:<20} {last}")

    elif args.alerts:
        alerts = radar.get_alerts()
        if args.json:
            print(json.dumps(alerts, indent=2))
        else:
            print(f"\n🚨 RECENT ALERTS ({len(alerts)})")
            print("="*70)
            for a in alerts[-20:]:
                ts = a.get('timestamp', '')[:16]
                msg = a.get('message', '')
                print(f"  • [{ts}] {msg}")

    elif args.status:
        stats = radar.get_stats()
        if args.json:
            print(json.dumps(stats, indent=2))
        else:
            print(f"\n📡 RADAR STATUS")
            print("="*50)
            print(f"Running: {stats['running']}")
            print(f"WSL Mode: {stats['wsl_mode']}")
            print(f"Red actual: {stats['red_actual']}")
            print(f"Devices observed: {stats['total_devices_observed']}")
            print(f"Active now: {stats['active_devices_now']}")
            print(f"Total alerts: {stats['total_alerts']}")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
