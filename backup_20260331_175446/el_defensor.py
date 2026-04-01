#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
ATLANTIS - FIREWALL DEFENDER v3.1 (RUTAS RELATIVAS)
• Funciona en Windows (netsh/PowerShell) y Linux/WSL (iptables)
• JSON output for NEMESIS integration
• Automatic IP blocking from ARP alerts
• Manual block/unblock with verification
• Comprehensive logging and statistics
• Sanitización de inputs
• RUTAS RELATIVAS al ejecutable de Atlantis
"""

import os
import sys
import re
import json
import time
import argparse
import subprocess
import threading
import shlex
import platform
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

ALERTS_FILE = DEFENSA_DIR / "alertas_arp.json"
BLOCKED_IPS_FILE = DEFENSA_DIR / "blocked_ips.json"
LOG_FILE = DEFENSA_DIR / "defender.log"

print(f"📁 Data directory: {DATA_DIR}", file=sys.stderr)

if not BLOCKED_IPS_FILE.exists():
    with open(BLOCKED_IPS_FILE, 'w', encoding='utf-8') as f:
        json.dump({}, f)

# ============================================================
# SANITIZACIÓN DE INPUTS
# ============================================================
def sanitize_input(input_str):
    if not input_str:
        return ""
    return shlex.quote(str(input_str))

# ============================================================
# DETECCIÓN DE ENTORNO
# ============================================================
def is_wsl():
    try:
        release = platform.uname().release.lower()
        return 'microsoft' in release or 'wsl' in release
    except:
        return False

def is_linux():
    return platform.system() == "Linux" and not is_wsl()

def is_windows():
    return platform.system() == "Windows"

# ============================================================
# WINDOWS ENCODING FIX
# ============================================================
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# ============================================================
# PROFESSIONAL LOGGER
# ============================================================
class DefenderLogger:
    def __init__(self, log_file: Path, verbose: bool = False):
        self.log_file = log_file
        self.verbose = verbose

    def info(self, message: str):
        self._log("INFO", message)
        if self.verbose:
            print(f"ℹ️ {message}")

    def success(self, message: str):
        self._log("SUCCESS", message)
        if self.verbose:
            print(f"✅ {message}")

    def warning(self, message: str):
        self._log("WARNING", message)
        if self.verbose:
            print(f"⚠️ {message}")

    def error(self, message: str):
        self._log("ERROR", message)
        if self.verbose:
            print(f"❌ {message}")

    def alert(self, message: str):
        self._log("ALERT", message)
        if self.verbose:
            print(f"🚨 {message}")

    def _log(self, level: str, message: str):
        try:
            timestamp = datetime.now().isoformat()
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(f"[{timestamp}] {level}: {message}\n")
        except:
            pass

# ============================================================
# FIREWALL MANAGER (ADAPTATIVO)
# ============================================================
class FirewallManager:
    def __init__(self, logger: DefenderLogger):
        self.logger = logger
        self.rule_prefix = "ATLANTIS_Block_"
        self.env = self._detect_env()
        self.logger.info(f"Firewall Manager iniciado en modo: {self.env}")

    def _detect_env(self):
        if is_windows():
            return "windows"
        elif is_wsl():
            return "wsl"
        elif is_linux():
            return "linux"
        else:
            return "unknown"

    def block_ip(self, ip: str) -> bool:
        ip_sanitizado = sanitize_input(ip)
        
        if self.env == "windows":
            return self._block_ip_windows(ip_sanitizado)
        elif self.env in ["wsl", "linux"]:
            return self._block_ip_linux(ip_sanitizado)
        else:
            self.logger.error(f"Entorno no soportado: {self.env}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        ip_sanitizado = sanitize_input(ip)
        
        if self.env == "windows":
            return self._unblock_ip_windows(ip_sanitizado)
        elif self.env in ["wsl", "linux"]:
            return self._unblock_ip_linux(ip_sanitizado)
        else:
            return False

    def _block_ip_windows(self, ip: str) -> bool:
        rule_name = f"{self.rule_prefix}{ip.replace('.', '_')}"
        self.logger.info(f"Bloqueando IP {ip} (Windows Firewall)")

        netsh_cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", "action=block",
            f"remoteip={ip}", "protocol=any"
        ]

        try:
            result = subprocess.run(netsh_cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.logger.success(f"IP {ip} bloqueada (netsh)")
                return True
        except Exception as e:
            self.logger.warning(f"netsh falló: {e}")

        ps_cmd = [
            "powershell", "-Command",
            f'New-NetFirewallRule -DisplayName "{rule_name}" '
            f'-Direction Inbound -Action Block -RemoteAddress "{ip}" '
            f'-Protocol Any -ErrorAction SilentlyContinue'
        ]

        try:
            result = subprocess.run(ps_cmd, capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                self.logger.success(f"IP {ip} bloqueada (PowerShell)")
                return True
        except Exception as e:
            self.logger.warning(f"PowerShell falló: {e}")

        return False

    def _block_ip_linux(self, ip: str) -> bool:
        self.logger.info(f"Bloqueando IP {ip} (iptables)")

        try:
            subprocess.run(["iptables", "--version"], capture_output=True, check=True)
        except:
            self.logger.warning("iptables no disponible")
            return False

        try:
            cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.logger.success(f"IP {ip} bloqueada (iptables)")
                return True
            else:
                self.logger.warning(f"iptables falló: {result.stderr}")
        except Exception as e:
            self.logger.warning(f"iptables exception: {e}")

        try:
            cmd = ["sudo", "ip6tables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.logger.success(f"IP {ip} bloqueada (ip6tables)")
                return True
        except:
            pass

        return False

    def _unblock_ip_windows(self, ip: str) -> bool:
        rule_name = f"{self.rule_prefix}{ip.replace('.', '_')}"
        self.logger.info(f"Desbloqueando IP {ip} (Windows Firewall)")

        netsh_cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
        try:
            result = subprocess.run(netsh_cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.logger.success(f"IP {ip} desbloqueada")
                return True
        except:
            pass

        ps_cmd = ["powershell", "-Command", f'Remove-NetFirewallRule -DisplayName "{rule_name}" -ErrorAction SilentlyContinue']
        try:
            result = subprocess.run(ps_cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.logger.success(f"IP {ip} desbloqueada (PowerShell)")
                return True
        except:
            pass

        return False

    def _unblock_ip_linux(self, ip: str) -> bool:
        self.logger.info(f"Desbloqueando IP {ip} (iptables)")

        try:
            cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.logger.success(f"IP {ip} desbloqueada (iptables)")
                return True
        except Exception as e:
            self.logger.warning(f"iptables delete falló: {e}")

        try:
            cmd = ["sudo", "ip6tables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.logger.success(f"IP {ip} desbloqueada (ip6tables)")
                return True
        except:
            pass

        return False

    def is_blocked(self, ip: str) -> bool:
        if self.env in ["wsl", "linux"]:
            try:
                cmd = ["sudo", "iptables", "-L", "INPUT", "-n"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                return ip in result.stdout
            except:
                pass
        return False

    def list_blocked_ips(self) -> List[str]:
        ips = []
        if self.env in ["wsl", "linux"]:
            try:
                cmd = ["sudo", "iptables", "-L", "INPUT", "-n"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                for line in result.stdout.split('\n'):
                    if "DROP" in line:
                        parts = line.split()
                        for part in parts:
                            if '.' in part and len(part.split('.')) == 4:
                                ips.append(part)
            except:
                pass
        return ips

# ============================================================
# ALERT MONITOR
# ============================================================
class AlertMonitor:
    def __init__(self, firewall: FirewallManager, logger: DefenderLogger, auto_block: bool = True):
        self.firewall = firewall
        self.logger = logger
        self.auto_block = auto_block
        self.running = False
        self.processed_alerts = set()
        self.stats = {
            "alerts_processed": 0,
            "ips_blocked": 0,
            "ips_already_blocked": 0,
            "block_failures": 0
        }

    def start_monitoring(self):
        self.running = True
        thread = threading.Thread(target=self._monitor_loop)
        thread.daemon = True
        thread.start()
        self.logger.info("Alert monitor started")

    def stop_monitoring(self):
        self.running = False
        self.logger.info("Alert monitor stopped")

    def _monitor_loop(self):
        last_position = 0
        while self.running:
            try:
                if not ALERTS_FILE.exists():
                    time.sleep(2)
                    continue

                with open(ALERTS_FILE, 'r', encoding='utf-8') as f:
                    f.seek(last_position)
                    new_lines = f.readlines()
                    last_position = f.tell()

                for line in new_lines:
                    self._process_alert_line(line)

                time.sleep(1)
            except Exception as e:
                self.logger.error(f"Monitor error: {e}")
                time.sleep(5)

    def _process_alert_line(self, line: str):
        try:
            if line.strip().startswith('{'):
                alert = json.loads(line)
                ip = alert.get('ip')
                alert_id = alert.get('alert_id', hash(line))
            else:
                ip = self._extract_ip_from_text(line)
                alert_id = hash(line)

            if not ip:
                return

            if alert_id in self.processed_alerts:
                return

            self.processed_alerts.add(alert_id)
            self.stats["alerts_processed"] += 1

            if self.auto_block:
                self._handle_alert(ip, line)
        except Exception as e:
            self.logger.error(f"Error processing alert: {e}")

    def _extract_ip_from_text(self, line: str) -> Optional[str]:
        patterns = [r'IP=(\d+\.\d+\.\d+\.\d+)', r'(\d+\.\d+\.\d+\.\d+)']
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)
        return None

    def _handle_alert(self, ip: str, alert_line: str):
        self.logger.alert(f"Attack detected from IP: {ip}")

        if self.firewall.is_blocked(ip):
            self.logger.info(f"IP {ip} already blocked")
            self.stats["ips_already_blocked"] += 1
            return

        if self.firewall.block_ip(ip):
            self.stats["ips_blocked"] += 1
            self._record_blocked_ip(ip, alert_line)
        else:
            self.stats["block_failures"] += 1

    def _record_blocked_ip(self, ip: str, alert_line: str):
        try:
            with open(BLOCKED_IPS_FILE, 'r', encoding='utf-8') as f:
                blocked = json.load(f)

            blocked[ip] = {
                "blocked_at": datetime.now().isoformat(),
                "alert": alert_line.strip(),
                "method": "automatic"
            }

            with open(BLOCKED_IPS_FILE, 'w', encoding='utf-8') as f:
                json.dump(blocked, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f"Failed to record blocked IP: {e}")

    def get_stats(self) -> Dict[str, Any]:
        return self.stats.copy()

# ============================================================
# MAIN DEFENDER CONTROLLER
# ============================================================
class DefenderController:
    def __init__(self, verbose: bool = False, json_output: bool = False):
        self.logger = DefenderLogger(LOG_FILE, verbose)
        self.firewall = FirewallManager(self.logger)
        self.monitor = AlertMonitor(self.firewall, self.logger)
        self.json_output = json_output
        self.verbose = verbose

    def block_ip(self, ip: str) -> bool:
        ip_sanitizado = sanitize_input(ip)
        success = self.firewall.block_ip(ip_sanitizado)

        if success:
            try:
                with open(BLOCKED_IPS_FILE, 'r', encoding='utf-8') as f:
                    blocked = json.load(f)

                blocked[ip_sanitizado] = {
                    "blocked_at": datetime.now().isoformat(),
                    "method": "manual"
                }

                with open(BLOCKED_IPS_FILE, 'w', encoding='utf-8') as f:
                    json.dump(blocked, f, indent=2, ensure_ascii=False)
            except:
                pass

        return success

    def unblock_ip(self, ip: str) -> bool:
        ip_sanitizado = sanitize_input(ip)
        success = self.firewall.unblock_ip(ip_sanitizado)

        if success:
            try:
                with open(BLOCKED_IPS_FILE, 'r', encoding='utf-8') as f:
                    blocked = json.load(f)

                if ip_sanitizado in blocked:
                    del blocked[ip_sanitizado]

                with open(BLOCKED_IPS_FILE, 'w', encoding='utf-8') as f:
                    json.dump(blocked, f, indent=2, ensure_ascii=False)
            except:
                pass

        return success

    def list_blocked(self) -> List[Dict[str, Any]]:
        result = []
        firewall_ips = self.firewall.list_blocked_ips()

        try:
            with open(BLOCKED_IPS_FILE, 'r', encoding='utf-8') as f:
                stored = json.load(f)

            for ip, data in stored.items():
                result.append({
                    "ip": ip,
                    "blocked_at": data.get("blocked_at"),
                    "method": data.get("method", "unknown"),
                    "alert": data.get("alert", ""),
                    "firewall_verified": ip in firewall_ips
                })
        except:
            for ip in firewall_ips:
                result.append({
                    "ip": ip,
                    "blocked_at": None,
                    "method": "unknown",
                    "alert": "",
                    "firewall_verified": True
                })

        return result

    def get_stats(self) -> Dict[str, Any]:
        blocked_list = self.list_blocked()
        firewall_ips = self.firewall.list_blocked_ips()

        return {
            "total_blocked": len(blocked_list),
            "firewall_rules": len(firewall_ips),
            "monitor_stats": self.monitor.get_stats(),
            "blocked_ips": blocked_list[:10],
        }

    def start_automatic(self):
        self.logger.info("Starting automatic defense mode")
        self.monitor.start_monitoring()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Stopping defense mode")
            self.monitor.stop_monitoring()

def main():
    parser = argparse.ArgumentParser(
        description="ATLANTIS Firewall Defender v3.1 - Adaptive Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  python el_defensor.py --auto
  python el_defensor.py --block 192.168.1.100
  python el_defensor.py --unblock 192.168.1.100
  python el_defensor.py --list --json
  python el_defensor.py --stats
        """
    )

    parser.add_argument("--auto", action="store_true", help="Automatic blocking mode")
    parser.add_argument("--block", metavar="IP", help="Manually block an IP")
    parser.add_argument("--unblock", metavar="IP", help="Manually unblock an IP")
    parser.add_argument("--list", action="store_true", help="List blocked IPs")
    parser.add_argument("--stats", action="store_true", help="Show statistics")
    parser.add_argument("--json", action="store_true", help="JSON output mode for NEMESIS")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    controller = DefenderController(verbose=args.verbose, json_output=args.json)

    if args.block:
        success = controller.block_ip(args.block)
        if args.json:
            print(json.dumps({"success": success, "ip": args.block, "action": "block"}))
        elif success:
            print(f"✅ IP {args.block} blocked successfully")
        else:
            print(f"❌ Failed to block IP {args.block}")
        return

    if args.unblock:
        success = controller.unblock_ip(args.unblock)
        if args.json:
            print(json.dumps({"success": success, "ip": args.unblock, "action": "unblock"}))
        elif success:
            print(f"✅ IP {args.unblock} unblocked successfully")
        else:
            print(f"❌ Failed to unblock IP {args.unblock}")
        return

    if args.list:
        blocked = controller.list_blocked()
        if args.json:
            print(json.dumps(blocked, indent=2))
        else:
            print(f"\n📋 BLOCKED IPS ({len(blocked)}):")
            print("="*50)
            for b in blocked:
                status = "✓" if b['firewall_verified'] else "?"
                date = b['blocked_at'][:10] if b['blocked_at'] else "unknown"
                print(f"  {status} {b['ip']} - {date} ({b['method']})")
        return

    if args.stats:
        stats = controller.get_stats()
        if args.json:
            print(json.dumps(stats, indent=2))
        else:
            print(f"\n📊 DEFENDER STATISTICS")
            print("="*50)
            print(f"Total blocked IPs: {stats['total_blocked']}")
            print(f"Firewall rules: {stats['firewall_rules']}")
            print(f"Monitor stats:")
            for k, v in stats['monitor_stats'].items():
                print(f"  • {k}: {v}")
        return

    if args.auto:
        print("\n🛡️ ATLANTIS DEFENDER - AUTOMATIC MODE")
        print("="*50)
        print("Monitoring alerts and blocking attackers...")
        print("Press Ctrl+C to stop\n")
        controller.start_automatic()
        return

    print("╔" + "═"*60 + "╗")
    print("║     ATLANTIS - FIREWALL DEFENDER v3.1 (ADAPTIVE)     ║")
    print("╚" + "═"*60 + "╝")

    while True:
        print("\n📋 MAIN MENU:")
        print("   1. Start automatic monitoring")
        print("   2. List blocked IPs")
        print("   3. Block IP manually")
        print("   4. Unblock IP manually")
        print("   5. Show statistics")
        print("   6. Exit")

        choice = input("\n➤ Option: ").strip()

        if choice == "1":
            print("\n🛡️ Starting automatic mode (Ctrl+C to stop)...")
            try:
                controller.start_automatic()
            except KeyboardInterrupt:
                print("\n\n✅ Monitoring stopped.")
        elif choice == "2":
            blocked = controller.list_blocked()
            if blocked:
                print(f"\n📋 BLOCKED IPS ({len(blocked)}):")
                print("-"*50)
                for b in blocked:
                    status = "✅" if b['firewall_verified'] else "⚠️"
                    date = b['blocked_at'][:16] if b['blocked_at'] else "unknown"
                    print(f"  {status} {b['ip']:<15} | {date} | {b['method']}")
            else:
                print("\n✅ No blocked IPs found.")
        elif choice == "3":
            ip = input("📌 IP to block: ").strip()
            if controller.block_ip(ip):
                print(f"✅ IP {ip} blocked")
            else:
                print(f"❌ Failed to block {ip}")
        elif choice == "4":
            ip = input("📌 IP to unblock: ").strip()
            if controller.unblock_ip(ip):
                print(f"✅ IP {ip} unblocked")
            else:
                print(f"❌ Failed to unblock {ip}")
        elif choice == "5":
            stats = controller.get_stats()
            print(f"\n📊 DEFENDER STATISTICS")
            print("="*50)
            print(f"Total blocked IPs: {stats['total_blocked']}")
            print(f"Firewall rules: {stats['firewall_rules']}")
            print(f"\nMonitor stats:")
            for k, v in stats['monitor_stats'].items():
                print(f"  • {k}: {v}")
        elif choice == "6":
            print("\n👋 See you, Defender.")
            break
        else:
            print("❌ Invalid option")

if __name__ == "__main__":
    main()
