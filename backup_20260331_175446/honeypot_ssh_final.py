#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
╔══════════════════════════════════════════════════════════════════════════╗
║                         VENOM v2.1 - SSH HONEYPOT                        ║
║                         RUTAS RELATIVAS                                  ║
║  • Detecta automáticamente dónde está Atlantis                          ║
║  • Usa carpetas relativas al ejecutable                                 ║
║  • Funciona en cualquier ubicación                                      ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import time
import socket
import signal
import threading
import hashlib
import argparse
import atexit
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

# ============================================================
# DETECCIÓN DE RUTA BASE
# ============================================================
def get_base_path():
    """Obtiene la ruta base del ejecutable de Atlantis"""
    try:
        # Buscar el ejecutable de Atlantis
        import subprocess
        result = subprocess.run(["which", "atlantis"], capture_output=True, text=True)
        if result.returncode == 0:
            exe_path = Path(result.stdout.strip())
            return exe_path.parent
    except:
        pass
    
    # Fallback: usar la ubicación del script
    script_dir = Path(__file__).parent.absolute()
    # Subir 3 niveles: scripts/defensa/ -> atlantis/
    return script_dir.parent.parent

# ============================================================
# CONFIGURACIÓN - RUTAS RELATIVAS
# ============================================================
BASE_PATH = get_base_path()
DATA_DIR = BASE_PATH / "data"
LOG_DIR = DATA_DIR / "venom_logs"
PID_FILE = DATA_DIR / "honeypot.pid"
STATUS_FILE = DATA_DIR / "honeypot_status.json"

# Crear directorios
LOG_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

print(f"📁 Data directory: {DATA_DIR}", file=sys.stderr)

DEFAULT_PORTS = [2222, 2223, 2224]
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"

stop_event = threading.Event()

# ============================================================
# PARAMIKO - LA ÚNICA DEPENDENCIA
# ============================================================
try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

# ============================================================
# DAEMON FUNCTIONS (ESCRIBEN PID INMEDIATAMENTE)
# ============================================================
def write_pid():
    try:
        with open(PID_FILE, 'w') as f:
            f.write(str(os.getpid()))
            f.flush()
            os.fsync(f.fileno())
        return True
    except:
        return False

def remove_pid():
    try:
        if PID_FILE.exists():
            PID_FILE.unlink()
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

def write_status(status: Dict):
    try:
        with open(STATUS_FILE, 'w') as f:
            json.dump(status, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
    except:
        pass

def read_status():
    if STATUS_FILE.exists():
        try:
            with open(STATUS_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return {"running": False, "total_connections": 0, "ports": []}

# ============================================================
# LOGGER
# ============================================================
class Logger:
    def __init__(self):
        self.log_file = LOG_DIR / "honeypot.log"
    
    def _write(self, level: str, msg: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(f"{ts} | {level:8} | {msg}\n")
        except:
            pass
    
    def info(self, msg): self._write("INFO", msg)
    def error(self, msg): self._write("ERROR", msg)
    
    def attack(self, ip: str, port: int, username: str, password: str):
        session_id = hashlib.md5(f"{ip}:{port}:{time.time()}".encode()).hexdigest()[:8]
        attack = {
            "timestamp": datetime.now().isoformat(),
            "session_id": session_id,
            "ip": ip,
            "port": port,
            "username": username,
            "password": password,
            "type": "bruteforce_attempt"
        }
        try:
            with open(LOG_DIR / "attacks.jsonl", 'a', encoding='utf-8') as f:
                f.write(json.dumps(attack, ensure_ascii=False) + '\n')
        except:
            pass
        self._write("ATTACK", f"{ip}:{port} - {username}:{password}")

# ============================================================
# SERVIDOR SSH CON PARAMIKO
# ============================================================
class SSHServer(paramiko.ServerInterface):
    def __init__(self, ip: str, port: int, logger: Logger):
        self.ip = ip
        self.port = port
        self.logger = logger
        self.event = threading.Event()
    
    def check_auth_password(self, username: str, password: str) -> int:
        self.logger.attack(self.ip, self.port, username, password)
        return paramiko.AUTH_FAILED
    
    def check_channel_request(self, kind: str, chanid: int) -> int:
        return paramiko.OPEN_SUCCEEDED
    
    def get_allowed_auths(self, username: str) -> str:
        return "password"

class SSHListener:
    def __init__(self, port: int, logger: Logger):
        self.port = port
        self.logger = logger
        self.socket = None
        self.running = False
        self.thread = None
        self.connections = 0
        self._verify_paramiko()
    
    def _verify_paramiko(self):
        if not PARAMIKO_AVAILABLE:
            self.logger.error("SSH module requires paramiko. Install: pip install paramiko")
    
    def start(self):
        if not PARAMIKO_AVAILABLE:
            return False
        self.running = True
        self.thread = threading.Thread(target=self._listen_loop)
        self.thread.daemon = True
        self.thread.start()
        return True
    
    def stop(self):
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
    
    def _listen_loop(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', self.port))
            self.socket.listen(100)
            self.socket.settimeout(0.5)
            self.logger.info(f"SSH Honeypot listening on port {self.port}")
            
            while self.running and not stop_event.is_set():
                try:
                    client, addr = self.socket.accept()
                    self.connections += 1
                    thread = threading.Thread(target=self._handle_client, args=(client, addr))
                    thread.daemon = True
                    thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Port {self.port} accept error: {e}")
        except Exception as e:
            self.logger.error(f"Port {self.port} listener failed: {e}")
        finally:
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
    
    def _handle_client(self, client, addr):
        try:
            client.settimeout(30)
            
            transport = paramiko.Transport(client)
            transport.local_version = SSH_BANNER
            transport.add_server_key(paramiko.RSAKey.generate(2048))
            
            server = SSHServer(addr[0], addr[1], self.logger)
            transport.start_server(server=server)
            
            channel = transport.accept(10)
            if channel:
                time.sleep(1)
            
            transport.close()
        except Exception as e:
            pass
        finally:
            try:
                client.close()
            except:
                pass
    
    def get_stats(self):
        return {"port": self.port, "connections": self.connections, "running": self.running, "protocol": "ssh"}

# ============================================================
# CONTROLADOR PRINCIPAL
# ============================================================
class VenomController:
    def __init__(self, ports: List[int] = None):
        self.ports = ports or DEFAULT_PORTS
        self.logger = Logger()
        self.listeners: Dict[int, SSHListener] = {}
        self.start_time = None
    
    def start(self):
        self.logger.info(f"Starting VENOM v2.1 SSH Honeypot on ports: {self.ports}")
        
        for port in self.ports:
            listener = SSHListener(port, self.logger)
            if listener.start():
                self.listeners[port] = listener
                self.logger.info(f"  ✓ Port {port} - SSH Honeypot")
                time.sleep(0.3)
            else:
                self.logger.error(f"  ✗ Port {port} - Failed to start")
        
        self.start_time = datetime.now()
        return len(self.listeners) > 0
    
    def stop(self):
        self.logger.info("Stopping VENOM Honeypot...")
        for listener in self.listeners.values():
            listener.stop()
        stop_event.set()
    
    def get_stats(self) -> Dict:
        if not self.start_time:
            return {"running": False, "total_connections": 0, "ports": []}
        
        total_conn = sum(l.connections for l in self.listeners.values())
        ports_stats = [l.get_stats() for l in self.listeners.values()]
        
        return {
            "running": True,
            "start_time": self.start_time.isoformat(),
            "uptime_seconds": (datetime.now() - self.start_time).total_seconds(),
            "ports": ports_stats,
            "total_connections": total_conn,
            "version": "2.1"
        }

# ============================================================
# MANEJO DE SEÑALES
# ============================================================
controller = None

def signal_handler(sig, frame):
    if controller:
        controller.stop()
    write_status({"running": False, "total_connections": 0, "ports": []})
    remove_pid()
    sys.exit(0)

# ============================================================
# MAIN
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="VENOM v2.1 SSH Honeypot")
    parser.add_argument("--ports", "-p", type=str, default="2222", help="Comma-separated ports")
    parser.add_argument("--start", action="store_true", help="Start honeypot in background")
    parser.add_argument("--stop", action="store_true", help="Stop running honeypot")
    parser.add_argument("--status", action="store_true", help="Show running status")
    parser.add_argument("--stats", action="store_true", help="Show statistics")
    parser.add_argument("--json", action="store_true", help="JSON output")
    
    args = parser.parse_args()
    
    # Comando stop
    if args.stop:
        if is_running():
            try:
                with open(PID_FILE, 'r') as f:
                    pid = int(f.read().strip())
                os.kill(pid, signal.SIGTERM)
                time.sleep(1)
                try:
                    os.kill(pid, 0)
                    os.kill(pid, signal.SIGKILL)
                except:
                    pass
                remove_pid()
                print(json.dumps({"success": True, "action": "stop"}))
            except:
                print(json.dumps({"success": False, "action": "stop"}))
        else:
            print(json.dumps({"success": False, "action": "stop", "message": "Not running"}))
        return
    
    # Comando status
    if args.status:
        if is_running():
            status = read_status()
            print(json.dumps({"success": True, "running": True, "status": status}))
        else:
            print(json.dumps({"success": True, "running": False}))
        return
    
    # Comando stats
    if args.stats:
        if is_running():
            status = read_status()
            print(json.dumps(status))
        else:
            print(json.dumps({"running": False, "total_connections": 0, "ports": []}))
        return
    
    # Parsear puertos
    try:
        ports = [int(p.strip()) for p in args.ports.split(',')]
    except:
        print(json.dumps({"success": False, "error": "Invalid port list"}))
        sys.exit(1)
    
    # Comando start
    if args.start:
        if is_running():
            print(json.dumps({"success": False, "error": "Already running"}))
            return
        
        pid = os.fork()
        if pid > 0:
            time.sleep(1)
            if PID_FILE.exists():
                try:
                    with open(PID_FILE, 'r') as f:
                        child_pid = int(f.read().strip())
                    print(json.dumps({"success": True, "action": "start", "pid": child_pid}))
                except:
                    print(json.dumps({"success": False, "error": "Start failed"}))
            else:
                print(json.dumps({"success": False, "error": "Start failed"}))
            return
        else:
            os.setsid()
            sys.stdin = open('/dev/null', 'r')
            sys.stdout = open('/dev/null', 'w')
            sys.stderr = open('/dev/null', 'w')
    
    # Configurar señales
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    global controller
    controller = VenomController(ports=ports)
    
    if not write_pid():
        sys.exit(1)
    
    if not controller.start():
        remove_pid()
        sys.exit(1)
    
    write_status(controller.get_stats())
    
    def update_status():
        while not stop_event.is_set():
            write_status(controller.get_stats())
            time.sleep(5)
    
    status_thread = threading.Thread(target=update_status)
    status_thread.daemon = True
    status_thread.start()
    
    atexit.register(lambda: write_status({"running": False, "total_connections": 0, "ports": []}))
    
    try:
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        controller.stop()
        remove_pid()
        write_status({"running": False, "total_connections": 0, "ports": []})

if __name__ == "__main__":
    main()
