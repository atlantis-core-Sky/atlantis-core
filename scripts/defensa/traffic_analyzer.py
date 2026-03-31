#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ATLANTIS - TRAFFIC ANALYZER v1.1
• Análisis de tráfico encriptado TLS/HTTPS
• Detección de exfiltración de datos
• Detección de comunicación con C2
• Integración con Threat Intelligence
• Coordinación con ML y Defender
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
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict, deque

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from scapy.all import sniff, IP, TCP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

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
TRAFFIC_DIR = DATA_DIR / "traffic_logs"
CONNECTIONS_FILE = TRAFFIC_DIR / "connections.jsonl"
ANOMALIES_FILE = TRAFFIC_DIR / "anomalies.jsonl"
THREAT_DB = DATA_DIR / "threat_intel/threat_intel.db"
PID_FILE = DATA_DIR / "traffic_analyzer.pid"
STATUS_FILE = DATA_DIR / "traffic_analyzer_status.json"

TRAFFIC_DIR.mkdir(parents=True, exist_ok=True)

stop_event = threading.Event()

# ============================================================
# LOGGER
# ============================================================
class TrafficLogger:
    def __init__(self, log_file: Path, verbose: bool = False):
        self.log_file = log_file
        self.verbose = verbose
    
    def log(self, data: Dict):
        data["timestamp"] = datetime.now().isoformat()
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(data, ensure_ascii=False) + '\n')
        except:
            pass
        if self.verbose:
            print(f"📡 [{data.get('type', 'unknown')}] {data.get('ip', 'unknown')}:{data.get('port', '?')}")

# ============================================================
# THREAT INTELLIGENCE CLIENT
# ============================================================
class ThreatIntelClient:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._cache = {}
        self._cache_time = {}
    
    def check_ip(self, ip: str) -> Dict:
        """Consulta si una IP es maliciosa (con caché)"""
        # Caché de 5 minutos
        if ip in self._cache:
            if time.time() - self._cache_time.get(ip, 0) < 300:
                return self._cache[ip]
        
        try:
            # Consultar directamente la base de datos SQLite
            if THREAT_DB.exists():
                conn = sqlite3.connect(THREAT_DB)
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT source, category, confidence, blocked
                    FROM malicious_ips WHERE ip = ?
                ''', (ip,))
                row = cursor.fetchone()
                conn.close()
                
                if row:
                    result = {
                        "malicious": True,
                        "source": row[0],
                        "category": row[1],
                        "confidence": row[2],
                        "blocked": bool(row[3])
                    }
                    self._cache[ip] = result
                    self._cache_time[ip] = time.time()
                    return result
            
            # Si no está en DB, consultar via script
            result = subprocess.run(
            ["sudo", sys.executable,
                 str(BASE_PATH / "scripts/defensa/threat_intel.py"),
                 "--check", ip, "--json"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                self._cache[ip] = data
                self._cache_time[ip] = time.time()
                return data
        except Exception as e:
            if self.verbose:
                print(f"⚠️ Threat intel error for {ip}: {e}")
        
        return {"malicious": False}
    
    def block_ip(self, ip: str) -> bool:
        """Bloquea IP via threat intel"""
        try:
            result = subprocess.run(
            ["sudo", sys.executable,
                 str(BASE_PATH / "scripts/defensa/threat_intel.py"),
                 "--block", ip, "--json"],
                capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except:
            return False

# ============================================================
# ANALIZADOR DE CONEXIONES
# ============================================================
class ConnectionAnalyzer:
    def __init__(self, logger: TrafficLogger, threat_intel: ThreatIntelClient, verbose: bool = False):
        self.logger = logger
        self.threat_intel = threat_intel
        self.verbose = verbose
        self.connections = defaultdict(lambda: {
            "count": 0,
            "bytes_sent": 0,
            "bytes_recv": 0,
            "first_seen": None,
            "last_seen": None,
            "ports": set(),
            "suspicious": False,
            "threat_info": None
        })
        self.thresholds = {
            "unique_ips_per_minute": 50,
            "data_exfil_per_minute": 10 * 1024 * 1024,
            "connections_to_known_bad": 1,
            "suspicious_ports": {4444, 5555, 6666, 7777, 8888, 9999, 31337, 8080, 8443},
        }
    
    def add_connection(self, conn: Dict):
        ip = conn.get("ip")
        port = conn.get("port", 0)
        bytes_sent = conn.get("bytes_sent", 0)
        bytes_recv = conn.get("bytes_recv", 0)
        
        if not ip:
            return
        
        # Consultar threat intelligence
        threat_info = self.threat_intel.check_ip(ip)
        
        data = self.connections[ip]
        data["count"] += 1
        data["bytes_sent"] += bytes_sent
        data["bytes_recv"] += bytes_recv
        data["ports"].add(port)
        
        if not data["first_seen"]:
            data["first_seen"] = conn.get("timestamp", datetime.now().isoformat())
        data["last_seen"] = conn.get("timestamp", datetime.now().isoformat())
        
        # Actualizar threat_info si es malicioso
        if threat_info.get("malicious") and not data["threat_info"]:
            data["threat_info"] = threat_info
        
        # Detectar sospechas
        is_suspicious = False
        reasons = []
        
        # 1. Puerto sospechoso
        if port in self.thresholds["suspicious_ports"]:
            is_suspicious = True
            reasons.append(f"puerto_sospechoso_{port}")
        
        # 2. IP maliciosa (threat intel)
        if threat_info.get("malicious"):
            is_suspicious = True
            reasons.append(f"threat_intel: {threat_info.get('category', 'unknown')}")
        
        # 3. Muchas conexiones desde misma IP
        if data["count"] > self.thresholds["unique_ips_per_minute"]:
            is_suspicious = True
            reasons.append("escaneo_rapido")
        
        # 4. Muchos datos enviados
        if data["bytes_sent"] > self.thresholds["data_exfil_per_minute"]:
            is_suspicious = True
            reasons.append("exfiltracion_datos")
        
        if is_suspicious and not data["suspicious"]:
            data["suspicious"] = True
            anomaly = {
                "type": "traffic_anomaly",
                "ip": ip,
                "port": port,
                "reasons": reasons,
                "threat_info": threat_info if threat_info.get("malicious") else None,
                "connection_count": data["count"],
                "bytes_sent": data["bytes_sent"],
                "bytes_recv": data["bytes_recv"],
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
                "severity": "critical" if threat_info.get("malicious") else ("high" if len(reasons) > 1 else "medium")
            }
            self.logger.log(anomaly)
            
            # Guardar en archivo de anomalías
            try:
                with open(ANOMALIES_FILE, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(anomaly, ensure_ascii=False) + '\n')
            except:
                pass
            
            # Si es IP maliciosa, intentar bloquear automáticamente
            if threat_info.get("malicious") and threat_info.get("confidence", 0) > 80:
                if self.verbose:
                    print(f"🚫 Intentando bloquear IP maliciosa: {ip}")
                self.threat_intel.block_ip(ip)
            
            if self.verbose:
                print(f"🚨 TRAFFIC ANOMALY: {ip}:{port} - {', '.join(reasons)}")
    
    def get_stats(self) -> Dict:
        return {
            "total_connections": len(self.connections),
            "suspicious_ips": sum(1 for c in self.connections.values() if c["suspicious"]),
            "active_connections": len([c for c in self.connections.values() if c["last_seen"] and 
                                       (datetime.now() - datetime.fromisoformat(c["last_seen"])).seconds < 60]),
            "threat_matches": sum(1 for c in self.connections.values() if c.get("threat_info"))
        }

# ============================================================
# CAPTURADOR DE TRÁFICO
# ============================================================
class TrafficCapture:
    def __init__(self, analyzer: ConnectionAnalyzer, logger: TrafficLogger, verbose: bool = False):
        self.analyzer = analyzer
        self.logger = logger
        self.verbose = verbose
        self.running = False
        self.captured_ips = set()
    
    def get_active_connections(self):
        if not PSUTIL_AVAILABLE:
            return
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr and conn.raddr.ip and conn.raddr.port:
                    if conn.raddr.ip.startswith('127.') or conn.raddr.ip.startswith('192.168.'):
                        continue
                    if conn.status in ['ESTABLISHED', 'SYN_SENT', 'CLOSE_WAIT']:
                        self.captured_ips.add(conn.raddr.ip)
                        connection = {
                            "type": "active_connection",
                            "ip": conn.raddr.ip,
                            "port": conn.raddr.port,
                            "protocol": "TCP",
                            "status": conn.status,
                            "pid": conn.pid if conn.pid else None
                        }
                        self.logger.log(connection)
                        self.analyzer.add_connection(connection)
        except Exception as e:
            if self.verbose:
                print(f"⚠️ Error en active connections: {e}")
    
    def capture_packets(self, interface: str = None, count: int = 100):
        if not SCAPY_AVAILABLE:
            return
        try:
            def packet_handler(packet):
                if IP in packet and TCP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    if not dst_ip.startswith('127.') and not dst_ip.startswith('192.168.'):
                        self.captured_ips.add(dst_ip)
                        connection = {
                            "type": "packet_capture",
                            "ip": dst_ip,
                            "port": dst_port,
                            "protocol": "TCP",
                            "src_ip": src_ip,
                            "src_port": src_port,
                            "packet_size": len(packet)
                        }
                        self.logger.log(connection)
                        self.analyzer.add_connection(connection)
            sniff_kwargs = {"prn": packet_handler, "store": 0, "filter": "tcp"}
            if interface:
                sniff_kwargs["iface"] = interface
            if count:
                sniff_kwargs["count"] = count
            sniff(**sniff_kwargs)
        except Exception as e:
            if self.verbose:
                print(f"⚠️ Error en packet capture: {e}")
    
    def start_monitoring(self):
        self.running = True
        if self.verbose:
            print("📡 Traffic analyzer started")
            print(f"   Active connections: {'✅' if PSUTIL_AVAILABLE else '❌'}")
            print(f"   Packet capture: {'✅' if SCAPY_AVAILABLE else '❌'}")
            print(f"   Threat intelligence: {'✅'}")
        while not stop_event.is_set():
            self.get_active_connections()
            time.sleep(5)
            if SCAPY_AVAILABLE:
                self.capture_packets(count=50)
            time.sleep(30)
    
    def stop(self):
        self.running = False

# ============================================================
# CONTROLADOR PRINCIPAL
# ============================================================
class TrafficAnalyzerController:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.threat_intel = ThreatIntelClient(verbose)
        self.logger = TrafficLogger(CONNECTIONS_FILE, verbose)
        self.analyzer = ConnectionAnalyzer(self.logger, self.threat_intel, verbose)
        self.capture = TrafficCapture(self.analyzer, self.logger, verbose)
        self.running = False
    
    def start(self):
        if self.running:
            return
        self.running = True
        if self.verbose:
            print("📡 Starting traffic analyzer...")
        self.thread = threading.Thread(target=self.capture.start_monitoring)
        self.thread.daemon = True
        self.thread.start()
        print("📡 Traffic analyzer started")
    
    def stop(self):
        stop_event.set()
        self.capture.stop()
        self.running = False
        print("📡 Traffic analyzer stopped")
    
    def get_stats(self) -> Dict:
        stats = self.analyzer.get_stats()
        stats["running"] = self.running
        stats["psutil_available"] = PSUTIL_AVAILABLE
        stats["scapy_available"] = SCAPY_AVAILABLE
        stats["total_ips_seen"] = len(self.capture.captured_ips)
        return stats
    
    def get_anomalies(self, limit: int = 50) -> List[Dict]:
        anomalies = []
        if ANOMALIES_FILE.exists():
            try:
                with open(ANOMALIES_FILE, 'r') as f:
                    for line in f:
                        try:
                            anomalies.append(json.loads(line))
                        except:
                            pass
                        if len(anomalies) >= limit:
                            break
            except:
                pass
        return anomalies

# ============================================================
# FUNCIONES DE DAEMON
# ============================================================
def write_pid():
    try:
        with open(PID_FILE, 'w') as f:
            f.write(str(os.getpid()))
        return True
    except:
        return False

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
    if PID_FILE.exists():
        try:
            with open(PID_FILE, 'r') as f:
                pid = int(f.read().strip())
            os.kill(pid, signal.SIGTERM)
            time.sleep(2)
            try:
                os.kill(pid, 0)
                os.kill(pid, signal.SIGKILL)
            except:
                pass
        except:
            pass
        remove_pid()
    if STATUS_FILE.exists():
        STATUS_FILE.unlink()

def signal_handler(sig, frame):
    print("\n🛑 Stopping traffic analyzer...")
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
    parser = argparse.ArgumentParser(description="ATLANTIS Traffic Analyzer v1.1")
    parser.add_argument("--start", action="store_true", help="Start traffic analyzer")
    parser.add_argument("--stop", action="store_true", help="Stop traffic analyzer")
    parser.add_argument("--status", action="store_true", help="Show status")
    parser.add_argument("--stats", action="store_true", help="Show statistics")
    parser.add_argument("--anomalies", action="store_true", help="Show detected anomalies")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    global controller
    controller = TrafficAnalyzerController(verbose=args.verbose)
    
    if args.stop:
        if is_running():
            stop_process()
            if args.json:
                print(json.dumps({"success": True, "action": "stop"}))
            else:
                print("✅ Traffic analyzer stopped")
        else:
            if args.json:
                print(json.dumps({"success": False, "action": "stop", "message": "Not running"}))
            else:
                print("❌ Traffic analyzer not running")
        return
    
    if args.status:
        running = is_running()
        if args.json:
            print(json.dumps({"running": running}))
        else:
            print(f"Traffic analyzer: {'✅ Running' if running else '⏸️ Stopped'}")
        return
    
    if args.stats:
        if is_running():
            stats = controller.get_stats()
        else:
            stats = {"running": False, "message": "Not running"}
        if args.json:
            print(json.dumps(stats, indent=2))
        else:
            print(f"\n📡 TRAFFIC ANALYZER STATISTICS")
            print(f"Running: {'✅' if stats.get('running') else '⏸️'}")
            print(f"Total connections: {stats.get('total_connections', 0)}")
            print(f"Suspicious IPs: {stats.get('suspicious_ips', 0)}")
            print(f"Active connections: {stats.get('active_connections', 0)}")
            print(f"Threat matches: {stats.get('threat_matches', 0)}")
            print(f"Total IPs seen: {stats.get('total_ips_seen', 0)}")
        return
    
    if args.anomalies:
        anomalies = controller.get_anomalies(20)
        if args.json:
            print(json.dumps(anomalies, indent=2))
        else:
            print(f"\n🚨 TRAFFIC ANOMALIES ({len(anomalies)})")
            for a in anomalies:
                threat = a.get('threat_info', {})
                threat_str = f" [THREAT: {threat.get('category', '')}]" if threat.get('malicious') else ""
                print(f"  • {a.get('ip')}:{a.get('port')} - {', '.join(a.get('reasons', []))}{threat_str}")
        return
    
    if args.start:
        if is_running():
            if args.json:
                print(json.dumps({"success": False, "error": "Already running"}))
            else:
                print("❌ Traffic analyzer already running")
            return
        
        pid = os.fork()
        if pid > 0:
            write_pid()
            write_status({"running": True, "start_time": datetime.now().isoformat()})
            if args.json:
                print(json.dumps({"success": True, "action": "start", "pid": pid}))
            else:
                print(f"✅ Traffic analyzer started (PID: {pid})")
                if not PSUTIL_AVAILABLE:
                    print("   ⚠️ psutil no disponible - instala: pip install psutil")
                if not SCAPY_AVAILABLE:
                    print("   ⚠️ scapy no disponible - instala: pip install scapy")
            return
        else:
            os.setsid()
            sys.stdin = open('/dev/null', 'r')
            sys.stdout = open('/dev/null', 'w')
            sys.stderr = open('/dev/null', 'w')
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    controller.start()
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
