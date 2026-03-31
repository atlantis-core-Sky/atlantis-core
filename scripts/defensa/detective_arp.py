#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
ATLANTIS - ARP SPOOFING DETECTOR v3.4 (RUTAS RELATIVAS)
• Real-time ARP monitoring with configurable timeout
• JSON output for NEMESIS integration
• Proper signal handling (Ctrl+C works on Windows)
• Threshold-based alerting
• Persistent alert storage
• Sanitización de inputs
• Detección automática de red (funciona en cualquier red)
• BLOQUEO AUTOMÁTICO de IPs atacantes
• RUTAS RELATIVAS al ejecutable de Atlantis
"""

import os
import sys
import json
import time
import signal
import argparse
import threading
import subprocess
import shlex
import socket
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

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

BASELINE_FILE = DEFENSA_DIR / "linea_base.json"
LOG_FILE = DEFENSA_DIR / "detective.log"
ALERTS_FILE = DEFENSA_DIR / "detective_alerts.json"

print(f"📁 Data directory: {DATA_DIR}", file=sys.stderr)

# ============================================================
# SANITIZACIÓN DE INPUTS
# ============================================================
def sanitize_input(input_str):
    """Sanitiza entrada para evitar inyección de comandos"""
    if not input_str:
        return ""
    return shlex.quote(str(input_str))

# ============================================================
# DETECCIÓN AUTOMÁTICA DE RED
# ============================================================
def detectar_red_actual():
    """Detecta la red actual automáticamente (casa, trabajo, café, hotel)"""
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
    except Exception as e:
        return "192.168.1.0/24"

# ============================================================
# WINDOWS ENCODING FIX (CRITICAL FOR NEMESIS)
# ============================================================
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# ============================================================
# SCAPY IMPORT WITH GRACEFUL FALLBACK
# ============================================================
try:
    from scapy.all import sniff, ARP, Ether
    from scapy.all import conf as scapy_conf
    SCAPY_AVAILABLE = True
except ImportError as e:
    SCAPY_AVAILABLE = False
    SCAPY_ERROR = str(e)

# ============================================================
# PROFESSIONAL LOGGING
# ============================================================
class Logger:
    """Professional logging with file and console output"""

    def __init__(self, log_file: Path, verbose: bool = False):
        self.log_file = log_file
        self.verbose = verbose

    def info(self, message: str):
        self._write("INFO", message)
        if self.verbose:
            print(f"ℹ️ {message}")

    def warning(self, message: str):
        self._write("WARNING", message)
        if self.verbose:
            print(f"⚠️ {message}")

    def error(self, message: str):
        self._write("ERROR", message)
        if self.verbose:
            print(f"❌ {message}")

    def success(self, message: str):
        self._write("SUCCESS", message)
        if self.verbose:
            print(f"✅ {message}")

    def alert(self, message: str):
        self._write("ALERT", message)
        if self.verbose:
            print(f"🚨 {message}")

    def _write(self, level: str, message: str):
        try:
            timestamp = datetime.now().isoformat()
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(f"[{timestamp}] {level}: {message}\n")
        except:
            pass

# ============================================================
# ARP DETECTION ENGINE
# ============================================================
class ARPDetector:
    """Professional ARP Spoofing Detection Engine with Auto-Block"""

    def __init__(
        self,
        threshold: int = 3,
        json_output: bool = False,
        verbose: bool = False,
        timeout: Optional[int] = None,
        log_file: Path = LOG_FILE,
        auto_block: bool = True,
    ):
        self.trust_table: Dict[str, str] = {}
        self.alerts: List[Dict[str, Any]] = []
        self.threshold = threshold
        self.json_output = json_output
        self.verbose = verbose
        self.timeout = timeout
        self.running = False
        self.alert_count = 0
        self.logger = Logger(log_file, verbose)
        self.red_actual = detectar_red_actual()
        self.auto_block = auto_block

        self._load_baseline()

    def _load_baseline(self) -> bool:
        if not BASELINE_FILE.exists():
            self.logger.warning("No baseline file found. Run Vigía first.")
            return False

        try:
            with open(BASELINE_FILE, 'r', encoding='utf-8') as f:
                devices = json.load(f)
                for d in devices:
                    if 'ip' in d and 'mac' in d:
                        self.trust_table[d['ip']] = d['mac'].lower()
            self.logger.success(f"Loaded {len(self.trust_table)} trusted devices")
            return True
        except Exception as e:
            self.logger.error(f"Failed to load baseline: {e}")
            return False

    def add_to_trust(self, ip: str, mac: str) -> bool:
        ip = ip.lower()
        mac = mac.lower()

        if ip in self.trust_table:
            if self.trust_table[ip] != mac:
                return False
        else:
            self.trust_table[ip] = mac
            self.logger.info(f"Learned new mapping: {ip} -> {mac}")
        return True

    def _block_attacker(self, ip: str):
        try:
            import el_defensor
            from el_defensor import DefenderController
            controller = DefenderController(verbose=False, json_output=True)
            if controller.block_ip(ip):
                self.logger.success(f"🚫 IP atacante {ip} bloqueada automáticamente")
            else:
                self.logger.error(f"❌ No se pudo bloquear IP {ip}")
        except Exception as e:
            self.logger.error(f"Error al bloquear IP {ip}: {e}")

    def process_packet(self, packet) -> Optional[Dict[str, Any]]:
        if ARP not in packet:
            return None

        arp = packet[ARP]

        packet_info = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": arp.psrc,
            "src_mac": arp.hwsrc.lower(),
            "dst_ip": arp.pdst,
            "dst_mac": arp.hwdst.lower() if arp.hwdst else "00:00:00:00:00:00",
            "operation": "request" if arp.op == 1 else "reply",
            "interface": getattr(packet, 'sniffed_on', None)
        }

        if arp.op == 2:
            if packet_info["src_ip"] in self.trust_table:
                expected_mac = self.trust_table[packet_info["src_ip"]]
                if packet_info["src_mac"] != expected_mac:
                    alert = {
                        "type": "ARP_SPOOFING",
                        "severity": "HIGH",
                        "timestamp": packet_info["timestamp"],
                        "ip": packet_info["src_ip"],
                        "expected_mac": expected_mac,
                        "detected_mac": packet_info["src_mac"],
                        "dst_ip": packet_info["dst_ip"],
                        "interface": packet_info["interface"],
                        "alert_id": self.alert_count + 1
                    }

                    self.alerts.append(alert)
                    self.alert_count += 1

                    self.logger.alert(
                        f"ARP Spoofing detected! IP={packet_info['src_ip']}, "
                        f"Expected MAC={expected_mac}, Detected MAC={packet_info['src_mac']}"
                    )
                    self._save_alert(alert)

                    if self.auto_block:
                        self.logger.info(f"🔒 Activando bloqueo automático para IP {packet_info['src_ip']}")
                        self._block_attacker(packet_info["src_ip"])

                    return alert
            else:
                self.add_to_trust(packet_info["src_ip"], packet_info["src_mac"])

        return packet_info

    def _save_alert(self, alert: Dict[str, Any]):
        try:
            alerts = []
            if ALERTS_FILE.exists():
                with open(ALERTS_FILE, 'r', encoding='utf-8') as f:
                    alerts = json.load(f)

            alerts.append(alert)
            if len(alerts) > 1000:
                alerts = alerts[-1000:]

            with open(ALERTS_FILE, 'w', encoding='utf-8') as f:
                json.dump(alerts, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f"Failed to save alert: {e}")

    def start_monitoring(self, interface: Optional[str] = None):
        self.running = True

        if interface:
            scapy_conf.iface = interface
            self.logger.info(f"Using interface: {interface}")

        if not self.json_output and self.verbose:
            print("\n🔍 ARP Detective started. Monitoring...")
            print(f"   🌐 Red detectada: {self.red_actual}")
            print(f"   🔒 Bloqueo automático: {'ACTIVADO' if self.auto_block else 'DESACTIVADO'}")
            print("   Press Ctrl+C to stop.\n")

        try:
            sniff_kwargs = {
                "filter": "arp",
                "prn": self._packet_handler,
                "store": 0,
                "stop_filter": lambda _: not self.running
            }

            if self.timeout is not None:
                sniff_kwargs["timeout"] = self.timeout
                self.logger.info(f"Timeout set to {self.timeout} seconds")

            sniff(**sniff_kwargs)

        except PermissionError:
            self.logger.error("Permission denied. Run as administrator.")
            if not self.json_output:
                print("\n❌ Error: Administrator privileges required.")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Sniffing error: {e}")
            if not self.json_output:
                print(f"\n❌ Error: {e}")

    def _packet_handler(self, packet):
        result = self.process_packet(packet)

        if result and not self.json_output and self.verbose:
            if isinstance(result, dict) and result.get("type") == "ARP_SPOOFING":
                self._display_alert(result)

    def _display_alert(self, alert: Dict[str, Any]):
        print(f"\n🚨 ARP SPOOFING DETECTED!")
        print(f"   IP: {alert['ip']}")
        print(f"   Expected MAC: {alert['expected_mac']}")
        print(f"   Detected MAC: {alert['detected_mac']}")
        print(f"   Time: {alert['timestamp']}")
        print(f"   Alert #{alert['alert_id']}\n")

    def get_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        return self.alerts[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        return {
            "trust_table_size": len(self.trust_table),
            "total_alerts": self.alert_count,
            "running": self.running,
            "threshold": self.threshold,
            "timeout": self.timeout,
            "red_actual": self.red_actual,
            "auto_block": self.auto_block,
        }

    def stop(self):
        self.running = False
        self.logger.info("Stopping ARP Detective")

detector_instance = None

def signal_handler(sig, frame):
    print("\n\n🛑 Received interrupt signal. Stopping...")
    if detector_instance:
        detector_instance.stop()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def get_active_interface() -> Optional[str]:
    try:
        import netifaces
        gateways = netifaces.gateways()
        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
            return gateways['default'][netifaces.AF_INET][1]
    except ImportError:
        pass

    if sys.platform == "win32":
        try:
            result = subprocess.run(
                ["wmic", "nic", "where", "NetEnabled=true", "get", "NetConnectionID"],
                capture_output=True, text=True, encoding='utf-8',
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            lines = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            if len(lines) > 1:
                return lines[1]
        except:
            pass
    return None

def check_admin() -> bool:
    if sys.platform == "win32":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        try:
            return os.geteuid() == 0
        except:
            return False

def main():
    if not SCAPY_AVAILABLE:
        print("❌ Scapy is not installed or failed to import.")
        print(f"   Error: {SCAPY_ERROR}")
        print("\n   Install with: python -m pip install scapy")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="ATLANTIS ARP Spoofing Detector v3.4 - Adaptive Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  python detective_arp.py --verbose
  python detective_arp.py --json --timeout 30
  python detective_arp.py --interface "Ethernet" --threshold 5
  python detective_arp.py --oneshot --timeout 10
        """
    )

    parser.add_argument("--interface", "-i", help="Network interface to monitor")
    parser.add_argument("--json", action="store_true", help="JSON output mode for NEMESIS")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose console output")
    parser.add_argument("--threshold", "-t", type=int, default=3, help="Alert threshold")
    parser.add_argument("--timeout", type=int, help="Monitoring timeout in seconds")
    parser.add_argument("--oneshot", "-1", action="store_true", help="One-shot mode")
    parser.add_argument("--no-auto-block", action="store_true", help="Disable automatic IP blocking")
    parser.add_argument("--log-file", type=Path, default=LOG_FILE, help="Log file path")

    args = parser.parse_args()

    if args.oneshot and args.timeout is None:
        args.timeout = 10

    if not check_admin():
        print("❌ Administrator privileges required for packet sniffing.")
        print("   Please run as administrator.")
        sys.exit(1)

    if not args.interface:
        args.interface = get_active_interface()
        if args.verbose and args.interface:
            print(f"🌐 Auto-detected interface: {args.interface}")

    global detector_instance
    detector_instance = ARPDetector(
        threshold=args.threshold,
        json_output=args.json,
        verbose=args.verbose,
        timeout=args.timeout,
        log_file=args.log_file,
        auto_block=not args.no_auto_block,
    )

    if args.json:
        detector_instance.start_monitoring(interface=args.interface)

        output = {
            "success": True,
            "timestamp": datetime.now().isoformat(),
            "interface": args.interface,
            "trust_table_size": len(detector_instance.trust_table),
            "alerts": detector_instance.get_alerts(),
            "stats": detector_instance.get_stats(),
            "version": "3.4"
        }
        print(json.dumps(output, ensure_ascii=False))
        return

    print("╔" + "═"*68 + "╗")
    print("║     ATLANTIS - ARP DETECTIVE v3.4 (ADAPTIVE)         ║")
    print("╚" + "═"*68 + "╝")
    print()

    print(f"📊 Configuration:")
    print(f"   • Interface: {args.interface or 'auto'}")
    print(f"   • Threshold: {args.threshold}")
    print(f"   • Timeout: {args.timeout if args.timeout else 'continuous'}")
    print(f"   • Mode: {'one-shot' if args.oneshot else 'continuous'}")
    print(f"   • Red detectada: {detector_instance.red_actual}")
    print(f"   • Auto-block: {'ACTIVADO' if detector_instance.auto_block else 'DESACTIVADO'}")
    print()

    try:
        detector_instance.start_monitoring(interface=args.interface)
    except KeyboardInterrupt:
        print("\n🛑 Stopped by user.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    finally:
        if args.verbose:
            print(f"\n📊 Final Statistics:")
            print(f"   • Total alerts: {detector_instance.alert_count}")
            print(f"   • Trust table size: {len(detector_instance.trust_table)}")

if __name__ == "__main__":
    main()
