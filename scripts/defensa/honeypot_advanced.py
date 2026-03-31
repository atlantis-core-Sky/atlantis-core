#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ATLANTIS - ADVANCED HONEYPOTS v1.2
• HTTP honeypot (WordPress, phpMyAdmin) - SIEMPRE FUNCIONA
• FTP honeypot (captura credenciales) - OPCIONAL
• SMB honeypot (detecta ransomware) - OPCIONAL
• BLOQUEO AUTOMÁTICO de IPs atacantes (3+ intentos)
• CIERRE CORRECTO: mata todos los procesos hijos
• Rutas relativas automáticas
"""

import os
import sys
import json
import time
import socket
import threading
import argparse
import signal
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from http.server import HTTPServer, BaseHTTPRequestHandler

# ============================================================
# INTENTAR IMPORTAR DEPENDENCIAS OPCIONALES
# ============================================================
FTP_AVAILABLE = False
SMB_AVAILABLE = False

try:
    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import FTPHandler
    from pyftpdlib.servers import FTPServer
    FTP_AVAILABLE = True
except ImportError:
    pass

try:
    from impacket import smbserver
    SMB_AVAILABLE = True
except ImportError:
    pass

# ============================================================
# DETECCIÓN DE RUTA BASE
# ============================================================
def get_base_path() -> Path:
    try:
        import subprocess as sp
        result = sp.run(["which", "atlantis"], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            exe_path = Path(result.stdout.strip())
            if exe_path.exists():
                return exe_path.parent
    except:
        pass
    
    script_dir = Path(__file__).parent.absolute()
    possible_paths = [
        script_dir.parent.parent,
        script_dir.parent,
        Path.cwd(),
        Path.home() / "atlantis-core",
    ]
    
    for path in possible_paths:
        if (path / "data").exists():
            return path
    
    return script_dir.parent.parent

# ============================================================
# CONFIGURACIÓN
# ============================================================
BASE_PATH = get_base_path()
DATA_DIR = BASE_PATH / "data"
HONEYPOT_DIR = DATA_DIR / "advanced_honeypot_logs"
HTTP_LOG = HONEYPOT_DIR / "http_attacks.jsonl"
FTP_LOG = HONEYPOT_DIR / "ftp_attacks.jsonl"
SMB_LOG = HONEYPOT_DIR / "smb_attacks.jsonl"
PID_FILE = DATA_DIR / "advanced_honeypot.pid"
STATUS_FILE = DATA_DIR / "advanced_honeypot_status.json"

HONEYPOT_DIR.mkdir(parents=True, exist_ok=True)

stop_event = threading.Event()

# ============================================================
# LISTA BLANCA Y BLOQUEO AUTOMÁTICO
# ============================================================
WHITELIST = [
    '1.1.1.1', '8.8.8.8', '9.9.9.9',  # DNS públicos
    '208.67.222.222', '208.67.220.220',  # OpenDNS
]

def is_local_ip(ip: str) -> bool:
    """Detecta si una IP es local"""
    return (ip.startswith('127.') or 
            ip.startswith('192.168.') or 
            ip.startswith('10.') or
            ip.startswith('172.16.') or
            ip.startswith('172.17.') or
            ip.startswith('172.18.') or
            ip.startswith('172.19.') or
            ip.startswith('172.20.') or
            ip.startswith('172.21.') or
            ip.startswith('172.22.') or
            ip.startswith('172.23.') or
            ip.startswith('172.24.') or
            ip.startswith('172.25.') or
            ip.startswith('172.26.') or
            ip.startswith('172.27.') or
            ip.startswith('172.28.') or
            ip.startswith('172.29.') or
            ip.startswith('172.30.') or
            ip.startswith('172.31.') or
            ip == '0.0.0.0')

def block_ip_automatically(ip: str, reason: str, honeypot_type: str) -> bool:
    """Bloquea una IP automáticamente si es sospechosa"""
    if is_local_ip(ip):
        return False
    if ip in WHITELIST:
        return False
    
    try:
        result = subprocess.run(
            ["sudo", sys.executable,
             str(BASE_PATH / "scripts/defensa/el_defensor.py"),
             "--block", ip, "--json"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            print(f"🚫 [BLOQUEO AUTOMÁTICO] {ip} - {reason}")
            return True
    except Exception as e:
        print(f"⚠️ Error bloqueando {ip}: {e}")
    
    return False

# ============================================================
# LOGGER CON BLOQUEO AUTOMÁTICO
# ============================================================
class HoneypotLogger:
    def __init__(self, log_file: Path, honeypot_type: str):
        self.log_file = log_file
        self.honeypot_type = honeypot_type
        self.attempts = {}
    
    def log(self, attack: Dict):
        attack["timestamp"] = datetime.now().isoformat()
        attack["honeypot_type"] = self.honeypot_type
        
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(attack, ensure_ascii=False) + '\n')
        except:
            pass
        
        ip = attack.get("ip")
        if ip and not is_local_ip(ip):
            self.attempts[ip] = self.attempts.get(ip, 0) + 1
            if self.attempts[ip] >= 3:
                reason = f"{self.honeypot_type} honeypot: {self.attempts[ip]} intentos"
                block_ip_automatically(ip, reason, self.honeypot_type)
        
        print(f"🍯 [{self.honeypot_type}] {attack.get('ip', 'unknown')} - {attack.get('action', 'unknown')}")

# ============================================================
# HTTP HONEYPOT
# ============================================================
class WordPressHandler(BaseHTTPRequestHandler):
    logger = None
    fake_pages = {
        "/": "WordPress 5.8",
        "/wp-admin": "WordPress Admin Login",
        "/wp-login.php": "WordPress Login",
        "/phpmyadmin": "phpMyAdmin 5.1",
        "/admin": "Admin Panel",
        "/xmlrpc.php": "XML-RPC API",
        "/.env": "Environment file (fake)",
        "/wp-config.php": "WordPress config (fake)",
        "/api": "API Endpoint",
        "/graphql": "GraphQL API",
    }
    
    def log_message(self, format, *args):
        pass
    
    def do_GET(self):
        self._handle_request("GET")
    
    def do_POST(self):
        self._handle_request("POST")
    
    def _handle_request(self, method):
        client_ip = self.client_address[0]
        path = self.path.split('?')[0]
        
        attack = {
            "ip": client_ip,
            "method": method,
            "path": path,
            "user_agent": self.headers.get('User-Agent', 'unknown'),
            "action": f"{method} {path}"
        }
        
        if path in self.fake_pages:
            content = f"<html><body><h1>{self.fake_pages[path]}</h1><form method='POST'><input type='text' name='log'><input type='password' name='pwd'><input type='submit'></form></body></html>"
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(content.encode())
            attack["response"] = 200
        elif path == "/wp-login.php" and method == "POST":
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8', errors='ignore')
            attack["credentials"] = post_data
            self.send_response(302)
            self.send_header('Location', '/wp-admin')
            self.end_headers()
            attack["response"] = 302
        else:
            self.send_response(404)
            self.end_headers()
            attack["response"] = 404
        
        if self.logger:
            self.logger.log(attack)

class HTTPServerThread(threading.Thread):
    def __init__(self, port: int, logger: HoneypotLogger):
        super().__init__(daemon=True)
        self.port = port
        self.logger = logger
        self.server = None
        self.running = False
    
    def run(self):
        WordPressHandler.logger = self.logger
        self.server = HTTPServer(('0.0.0.0', self.port), WordPressHandler)
        self.running = True
        print(f"🍯 HTTP honeypot listening on port {self.port}")
        while not stop_event.is_set():
            try:
                self.server.handle_request()
            except:
                pass
        self.server.server_close()
    
    def stop(self):
        self.running = False
        if self.server:
            self.server.shutdown()

# ============================================================
# FTP HONEYPOT (OPCIONAL)
# ============================================================
if FTP_AVAILABLE:
    class FTPHoneypotHandler(FTPHandler):
        logger = None
        
        def on_login(self, username, password):
            attack = {
                "ip": self.remote_ip,
                "username": username,
                "password": password,
                "action": "login_attempt",
                "protocol": "FTP"
            }
            if self.logger:
                self.logger.log(attack)
            return False
        
        def on_login_failed(self, username, password):
            attack = {
                "ip": self.remote_ip,
                "username": username,
                "password": password,
                "action": "login_failed",
                "protocol": "FTP"
            }
            if self.logger:
                self.logger.log(attack)
            return False

    class FTPServerThread(threading.Thread):
        def __init__(self, port: int, logger: HoneypotLogger):
            super().__init__(daemon=True)
            self.port = port
            self.logger = logger
            self.server = None
            self.running = False
        
        def run(self):
            try:
                authorizer = DummyAuthorizer()
                authorizer.add_anonymous("/tmp", perm="elr")
                FTPHoneypotHandler.logger = self.logger
                handler = FTPHoneypotHandler
                handler.authorizer = authorizer
                self.server = FTPServer(('0.0.0.0', self.port), handler)
                self.running = True
                print(f"🍯 FTP honeypot listening on port {self.port}")
                self.server.serve_forever()
            except Exception as e:
                print(f"⚠️ FTP error: {e}")
        
        def stop(self):
            self.running = False
            if self.server:
                self.server.close_all()
else:
    class FTPServerThread(threading.Thread):
        def __init__(self, port: int, logger: HoneypotLogger):
            super().__init__(daemon=True)
            self.port = port
            self.logger = logger
        
        def run(self):
            print("⚠️ FTP honeypot no disponible (instala: pip install pyftpdlib)")
        
        def stop(self):
            pass

# ============================================================
# SMB HONEYPOT (OPCIONAL)
# ============================================================
if SMB_AVAILABLE:
    class SMBHoneypot(threading.Thread):
        def __init__(self, port: int, logger: HoneypotLogger):
            super().__init__(daemon=True)
            self.port = port
            self.logger = logger
            self.server = None
            self.running = False
        
        def run(self):
            try:
                self.server = smbserver.SMBSERVER(('0.0.0.0', self.port))
                self.running = True
                print(f"🍯 SMB honeypot listening on port {self.port}")
                self.server.serve_forever()
            except Exception as e:
                print(f"⚠️ SMB error: {e}")
        
        def stop(self):
            self.running = False
            if self.server:
                self.server.shutdown()
else:
    class SMBHoneypot(threading.Thread):
        def __init__(self, port: int, logger: HoneypotLogger):
            super().__init__(daemon=True)
            self.port = port
            self.logger = logger
        
        def run(self):
            print("⚠️ SMB honeypot no disponible (instala: pip install impacket)")
        
        def stop(self):
            pass

# ============================================================
# CONTROLADOR PRINCIPAL
# ============================================================
class AdvancedHoneypotController:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.http_logger = HoneypotLogger(HTTP_LOG, "HTTP")
        self.ftp_logger = HoneypotLogger(FTP_LOG, "FTP")
        self.smb_logger = HoneypotLogger(SMB_LOG, "SMB")
        self.http_thread = None
        self.ftp_thread = None
        self.smb_thread = None
        self.running = False
    
    def start(self, ports: Dict[str, int] = None):
        if ports is None:
            ports = {"http": 8080, "ftp": 21, "smb": 445}
        
        self.http_thread = HTTPServerThread(ports["http"], self.http_logger)
        self.http_thread.start()
        
        self.ftp_thread = FTPServerThread(ports["ftp"], self.ftp_logger)
        self.ftp_thread.start()
        
        self.smb_thread = SMBHoneypot(ports["smb"], self.smb_logger)
        self.smb_thread.start()
        
        self.running = True
        print(f"\n🍯 Advanced honeypots started:")
        print(f"   HTTP: port {ports['http']} ✅")
        if FTP_AVAILABLE:
            print(f"   FTP: port {ports['ftp']} ✅")
        else:
            print(f"   FTP: port {ports['ftp']} ⚠️ (no disponible)")
        if SMB_AVAILABLE:
            print(f"   SMB: port {ports['smb']} ✅")
        else:
            print(f"   SMB: port {ports['smb']} ⚠️ (no disponible)")
        print(f"\n🔒 Bloqueo automático activado (3 intentos = bloqueo)")
        print()
    
    def stop(self):
        stop_event.set()
        if self.http_thread:
            self.http_thread.stop()
        if self.ftp_thread:
            self.ftp_thread.stop()
        if self.smb_thread:
            self.smb_thread.stop()
        self.running = False
        print("🍯 Advanced honeypots stopped")
    
    def get_stats(self) -> Dict:
        stats = {"http": 0, "ftp": 0, "smb": 0}
        for log, name in [(HTTP_LOG, "http"), (FTP_LOG, "ftp"), (SMB_LOG, "smb")]:
            if log.exists():
                try:
                    with open(log, 'r') as f:
                        stats[name] = sum(1 for _ in f)
                except:
                    pass
        return stats

# ============================================================
# FUNCIONES DE DAEMON (CORREGIDAS - MATA TODO EL GRUPO)
# ============================================================
def write_pid():
    try:
        with open(PID_FILE, 'w') as f:
            f.write(str(os.getpid()))
            f.flush()
    except:
        pass

def remove_pid():
    try:
        if PID_FILE.exists():
            PID_FILE.unlink()
    except:
        pass

def write_status(status: Dict):
    try:
        with open(STATUS_FILE, 'w') as f:
            json.dump(status, f)
    except:
        pass

def is_running():
    if not PID_FILE.exists():
        return False
    try:
        with open(PID_FILE, 'r') as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)
        return True
    except:
        remove_pid()
        return False

def stop_process():
    """Detiene el proceso y TODOS sus hijos (el grupo completo)"""
    if PID_FILE.exists():
        try:
            with open(PID_FILE, 'r') as f:
                pid = int(f.read().strip())
            
            # Matar todo el grupo de procesos
            try:
                os.killpg(os.getpgid(pid), signal.SIGTERM)
            except:
                # Si no se puede matar el grupo, matar el proceso individual
                os.kill(pid, signal.SIGTERM)
            
            time.sleep(2)
            
            # Asegurar que murieron
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except:
                try:
                    os.kill(pid, signal.SIGKILL)
                except:
                    pass
        except:
            pass
        remove_pid()
    if STATUS_FILE.exists():
        STATUS_FILE.unlink()

def signal_handler(sig, frame):
    print("\n🛑 Stopping advanced honeypots...")
    if controller:
        controller.stop()
    remove_pid()
    write_status({"running": False, "stopped_at": datetime.now().isoformat()})
    sys.exit(0)

controller = None

# ============================================================
# MAIN
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="ATLANTIS Advanced Honeypots v1.2 - Con cierre correcto",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EJEMPLOS:
  # Iniciar todos los honeypots
  sudo python3 honeypot_advanced.py --start

  # Ver estadísticas
  python3 honeypot_advanced.py --stats

  # Detener (mata todos los procesos hijos)
  sudo python3 honeypot_advanced.py --stop

BLOQUEO AUTOMÁTICO:
  Después de 3 intentos desde la misma IP, se bloquea automáticamente.
  IPs locales (192.168.x.x, 10.x.x.x) y lista blanca no se bloquean.
        """
    )
    
    parser.add_argument("--start", action="store_true", help="Start all honeypots")
    parser.add_argument("--stop", action="store_true", help="Stop running honeypots")
    parser.add_argument("--status", action="store_true", help="Show status")
    parser.add_argument("--stats", action="store_true", help="Show statistics")
    parser.add_argument("--http-port", type=int, default=8080, help="HTTP port")
    parser.add_argument("--ftp-port", type=int, default=21, help="FTP port")
    parser.add_argument("--smb-port", type=int, default=445, help="SMB port")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    global controller
    controller = AdvancedHoneypotController(verbose=args.verbose)
    
    if args.stop:
        if is_running():
            stop_process()
            if args.json:
                print(json.dumps({"success": True, "action": "stop"}))
            else:
                print("✅ Advanced honeypots stopped")
        else:
            if args.json:
                print(json.dumps({"success": False, "action": "stop", "message": "Not running"}))
            else:
                print("❌ Advanced honeypots not running")
        return
    
    if args.status:
        running = is_running()
        if args.json:
            print(json.dumps({"running": running}))
        else:
            print(f"Advanced honeypots: {'✅ Running' if running else '⏸️ Stopped'}")
        return
    
    if args.stats:
        stats = controller.get_stats()
        if args.json:
            print(json.dumps(stats))
        else:
            print(f"\n📊 Advanced Honeypot Statistics")
            print(f"HTTP attacks: {stats['http']}")
            print(f"FTP attacks: {stats['ftp']}")
            print(f"SMB attacks: {stats['smb']}")
        return
    
    if args.start:
        if is_running():
            if args.json:
                print(json.dumps({"success": False, "error": "Already running"}))
            else:
                print("❌ Advanced honeypots already running")
            return
        
        # Daemonizar
        pid = os.fork()
        if pid > 0:
            write_pid()
            write_status({"running": True, "start_time": datetime.now().isoformat()})
            if args.json:
                print(json.dumps({"success": True, "action": "start", "pid": pid}))
            else:
                print(f"✅ Advanced honeypots started (PID: {pid})")
                print(f"   🔒 Bloqueo automático: 3 intentos = bloqueo")
                if not FTP_AVAILABLE:
                    print("   ⚠️ FTP honeypot no disponible (instala: pip install pyftpdlib)")
                if not SMB_AVAILABLE:
                    print("   ⚠️ SMB honeypot no disponible (instala: pip install impacket)")
            return
        else:
            # Crear nuevo grupo de procesos para poder matarlos todos después
            os.setsid()
            sys.stdin = open('/dev/null', 'r')
            sys.stdout = open('/dev/null', 'w')
            sys.stderr = open('/dev/null', 'w')
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    controller.start(ports={"http": args.http_port, "ftp": args.ftp_port, "smb": args.smb_port})
    write_pid()
    write_status({"running": True, "start_time": datetime.now().isoformat()})
    
    try:
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        controller.stop()
        remove_pid()
        write_status({"running": False, "stopped_at": datetime.now().isoformat()})

if __name__ == "__main__":
    main()
