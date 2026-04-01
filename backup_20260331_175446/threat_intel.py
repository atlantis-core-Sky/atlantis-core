#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ATLANTIS - THREAT INTELLIGENCE v1.1
• Descarga feeds de IPs maliciosas
• Bloqueo automático de IPs de alta confianza
• Alimenta Traffic Analyzer y Defender
• Coordinación con NEMESIS
• Rutas relativas automáticas
"""

import os
import sys
import json
import time
import argparse
import signal
import threading
import requests
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

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
THREAT_DIR = DATA_DIR / "threat_intel"
DB_FILE = THREAT_DIR / "threat_intel.db"
STATS_FILE = THREAT_DIR / "stats.json"
PID_FILE = DATA_DIR / "threat_intel.pid"
STATUS_FILE = DATA_DIR / "threat_intel_status.json"

THREAT_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================
# BASE DE DATOS SQLITE
# ============================================================
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS malicious_ips (
            ip TEXT PRIMARY KEY,
            source TEXT,
            category TEXT,
            first_seen TEXT,
            last_seen TEXT,
            confidence INTEGER,
            blocked INTEGER DEFAULT 0
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS updates (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            source TEXT,
            ips_added INTEGER,
            blocked INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()

# ============================================================
# FUENTES DE INTELIGENCIA
# ============================================================
class ThreatSources:
    
    @staticmethod
    def feodo_tracker():
        ips = []
        try:
            url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        ips.append({
                            "ip": line,
                            "source": "Feodo Tracker",
                            "category": "C2",
                            "confidence": 95
                        })
        except Exception as e:
            pass
        return ips
    
    @staticmethod
    def ssl_blacklist():
        ips = []
        try:
            url = "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        ips.append({
                            "ip": line,
                            "source": "SSL Blacklist",
                            "category": "Malicious SSL",
                            "confidence": 85
                        })
        except Exception as e:
            pass
        return ips
    
    @staticmethod
    def tor_exit_nodes():
        ips = []
        try:
            url = "https://check.torproject.org/torbulkexitlist"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        ips.append({
                            "ip": line,
                            "source": "Tor Exit Nodes",
                            "category": "Tor Exit",
                            "confidence": 70
                        })
        except Exception as e:
            pass
        return ips
    
    @staticmethod
    def manual_list():
        return [
            {"ip": "185.130.5.253", "source": "Manual", "category": "C2", "confidence": 95},
            {"ip": "94.102.61.78", "source": "Manual", "category": "C2", "confidence": 95},
            {"ip": "45.155.205.233", "source": "Manual", "category": "C2", "confidence": 95},
        ]

# ============================================================
# CONTROLADOR PRINCIPAL
# ============================================================
class ThreatIntelController:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.sources = ThreatSources()
        self.db_initialized = False
        self._init_db()
    
    def _init_db(self):
        try:
            init_db()
            self.db_initialized = True
        except Exception as e:
            print(f"⚠️ Error initializing database: {e}")
    
    def _save_ip(self, ip_data: Dict):
        if not self.db_initialized:
            return
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            now = datetime.now().isoformat()
            cursor.execute('''
                INSERT OR REPLACE INTO malicious_ips 
                (ip, source, category, first_seen, last_seen, confidence, blocked)
                VALUES (?, ?, ?, COALESCE((SELECT first_seen FROM malicious_ips WHERE ip=?), ?), ?, ?, 0)
            ''', (
                ip_data["ip"],
                ip_data.get("source", "Unknown"),
                ip_data.get("category", "Unknown"),
                ip_data["ip"],
                now,
                ip_data.get("confidence", 50),
                now
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            if self.verbose:
                print(f"⚠️ Error saving IP {ip_data['ip']}: {e}")
    
    def block_ip(self, ip: str) -> bool:
        """Bloquea IP usando Defender"""
        try:
            import subprocess
            result = subprocess.run(
            ["sudo", sys.executable,
                 str(BASE_PATH / "scripts/defensa/el_defensor.py"),
                 "--block", ip, "--json"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                conn = sqlite3.connect(DB_FILE)
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE malicious_ips SET blocked = 1 WHERE ip = ?
                ''', (ip,))
                conn.commit()
                conn.close()
                return True
        except Exception as e:
            if self.verbose:
                print(f"⚠️ Error blocking IP {ip}: {e}")
        return False
    
    def update(self) -> Tuple[bool, str]:
        """Actualiza todas las fuentes y bloquea automáticamente IPs de alta confianza"""
        all_ips = []
        sources_used = []
        blocked_count = 0
        
        # Feodo Tracker
        try:
            ips = self.sources.feodo_tracker()
            if ips:
                all_ips.extend(ips)
                sources_used.append("Feodo Tracker")
                if self.verbose:
                    print(f"✅ Feodo Tracker: {len(ips)} IPs")
        except Exception as e:
            if self.verbose:
                print(f"⚠️ Feodo Tracker error: {e}")
        
        # SSL Blacklist
        try:
            ips = self.sources.ssl_blacklist()
            if ips:
                all_ips.extend(ips)
                sources_used.append("SSL Blacklist")
                if self.verbose:
                    print(f"✅ SSL Blacklist: {len(ips)} IPs")
        except Exception as e:
            if self.verbose:
                print(f"⚠️ SSL Blacklist error: {e}")
        
        # Tor Exit Nodes
        try:
            ips = self.sources.tor_exit_nodes()
            if ips:
                all_ips.extend(ips)
                sources_used.append("Tor Exit Nodes")
                if self.verbose:
                    print(f"✅ Tor Exit Nodes: {len(ips)} IPs")
        except Exception as e:
            if self.verbose:
                print(f"⚠️ Tor Exit Nodes error: {e}")
        
        # Lista manual
        ips = self.sources.manual_list()
        all_ips.extend(ips)
        sources_used.append("Manual")
        if self.verbose:
            print(f"✅ Manual: {len(ips)} IPs")
        
        # Guardar en base de datos y bloquear automáticamente
        for ip_data in all_ips:
            self._save_ip(ip_data)
            
            # Bloquear automáticamente IPs de alta confianza (> 80)
            confidence = ip_data.get("confidence", 50)
            if confidence > 80:
                if self.block_ip(ip_data["ip"]):
                    blocked_count += 1
                    if self.verbose:
                        print(f"   🚫 Bloqueada automáticamente: {ip_data['ip']} ({ip_data.get('category', 'Unknown')})")
        
        # Registrar actualización
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO updates (timestamp, source, ips_added, blocked)
                VALUES (?, ?, ?, ?)
            ''', (datetime.now().isoformat(), ", ".join(sources_used), len(all_ips), blocked_count))
            conn.commit()
            conn.close()
        except:
            pass
        
        return True, f"Updated {len(all_ips)} IPs from {len(sources_used)} sources, blocked {blocked_count}"
    
    def check_ip(self, ip: str) -> Dict:
        if not self.db_initialized:
            return {"malicious": False, "reason": "DB not initialized"}
        
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT source, category, confidence, blocked
                FROM malicious_ips WHERE ip = ?
            ''', (ip,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    "malicious": True,
                    "source": row[0],
                    "category": row[1],
                    "confidence": row[2],
                    "blocked": bool(row[3])
                }
        except Exception as e:
            if self.verbose:
                print(f"⚠️ Error checking IP {ip}: {e}")
        
        return {"malicious": False}
    
    def get_stats(self) -> Dict:
        stats = {
            "total_ips": 0,
            "by_source": {},
            "by_category": {},
            "last_update": None,
            "blocked_count": 0,
            "last_update_blocked": 0
        }
        
        if not self.db_initialized or not DB_FILE.exists():
            return stats
        
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM malicious_ips")
            stats["total_ips"] = cursor.fetchone()[0]
            
            cursor.execute("SELECT source, COUNT(*) FROM malicious_ips GROUP BY source")
            for row in cursor.fetchall():
                stats["by_source"][row[0]] = row[1]
            
            cursor.execute("SELECT category, COUNT(*) FROM malicious_ips GROUP BY category")
            for row in cursor.fetchall():
                stats["by_category"][row[0]] = row[1]
            
            cursor.execute("SELECT COUNT(*) FROM malicious_ips WHERE blocked = 1")
            stats["blocked_count"] = cursor.fetchone()[0]
            
            cursor.execute("SELECT timestamp, blocked FROM updates ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                stats["last_update"] = row[0]
                stats["last_update_blocked"] = row[1]
            
            conn.close()
        except Exception as e:
            if self.verbose:
                print(f"⚠️ Error getting stats: {e}")
        
        return stats
    
    def get_status(self) -> Dict:
        stats = self.get_stats()
        return {
            "running": False,
            "total_ips": stats["total_ips"],
            "blocked_count": stats["blocked_count"],
            "last_update": stats["last_update"],
            "last_update_blocked": stats["last_update_blocked"]
        }

# ============================================================
# MAIN
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="ATLANTIS Threat Intelligence v1.1")
    parser.add_argument("--update", action="store_true", help="Update threat feeds")
    parser.add_argument("--check", metavar="IP", help="Check if IP is malicious")
    parser.add_argument("--block", metavar="IP", help="Block IP manually")
    parser.add_argument("--stats", action="store_true", help="Show statistics")
    parser.add_argument("--status", action="store_true", help="Show status")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    controller = ThreatIntelController(verbose=args.verbose)
    
    if args.update:
        success, msg = controller.update()
        if args.json:
            print(json.dumps({"success": success, "message": msg}))
        else:
            print(f"{'✅' if success else '❌'} {msg}")
        return
    
    if args.check:
        result = controller.check_ip(args.check)
        if args.json:
            print(json.dumps(result))
        else:
            if result["malicious"]:
                print(f"🚨 IP {args.check} is MALICIOUS")
                print(f"   Source: {result.get('source', 'Unknown')}")
                print(f"   Category: {result.get('category', 'Unknown')}")
                print(f"   Confidence: {result.get('confidence', 0)}%")
            else:
                print(f"✅ IP {args.check} is clean")
        return
    
    if args.block:
        success = controller.block_ip(args.block)
        if args.json:
            print(json.dumps({"success": success, "ip": args.block}))
        else:
            print(f"{'✅' if success else '❌'} IP {args.block} {'blocked' if success else 'block failed'}")
        return
    
    if args.stats:
        stats = controller.get_stats()
        if args.json:
            print(json.dumps(stats, indent=2))
        else:
            print(f"\n🛡️ THREAT INTELLIGENCE STATISTICS")
            print(f"Total malicious IPs: {stats['total_ips']}")
            print(f"Blocked: {stats['blocked_count']}")
            print(f"Last update: {stats['last_update'] or 'Never'}")
            print(f"Blocked in last update: {stats.get('last_update_blocked', 0)}")
            if stats['by_source']:
                print("\nBy source:")
                for source, count in stats['by_source'].items():
                    print(f"  • {source}: {count}")
            if stats['by_category']:
                print("\nBy category:")
                for cat, count in stats['by_category'].items():
                    print(f"  • {cat}: {count}")
        return
    
    if args.status:
        status = controller.get_status()
        if args.json:
            print(json.dumps(status))
        else:
            print(f"Running: ⏸️ (manual updates)")
            print(f"Total IPs: {status['total_ips']}")
            print(f"Blocked: {status['blocked_count']}")
            print(f"Last update: {status['last_update'] or 'Never'}")
        return
    
    parser.print_help()

if __name__ == "__main__":
    main()
