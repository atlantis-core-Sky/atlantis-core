#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ATLANTIS - IA CEREBRO v5.2 (Final - Smart Model Selection)
• Safe Mode: Free conversation about hacking, security, vulnerabilities
• Active Mode: ONLY Atlantis data (network stats, attacks, threats)
• Smart model selection: prioritizes uncensored models
• No external knowledge contamination in Active Mode
"""

import os
import sys
import json
import re
import time
import requests
import subprocess
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

# ============================================================
# BASE PATH DETECTION
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
    return script_dir.parent.parent

# ============================================================
# CONFIGURATION
# ============================================================
BASE_PATH = get_base_path()
DATA_DIR = BASE_PATH / "data"
MEMORY_DIR = DATA_DIR / "memory"
THREAT_DB = DATA_DIR / "threat_intel/threat_intel.db"
HONEYPOT_DIR = DATA_DIR / "advanced_honeypot_logs"
ZOMBIE_DIR = DATA_DIR / "zombie_logs"
TRAFFIC_DIR = DATA_DIR / "traffic_logs"
ML_DIR = DATA_DIR / "anomaly_data"
OLLAMA_URL = "http://localhost:11434"
DEFAULT_MODEL = "dolphin-phi"
SAFE_MODE_FILE = DATA_DIR / "ia_safe_mode"

# IPs that are NEVER blocked
NEVER_BLOCK_IPS = [
    "1.2.3.4", "8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9",
    "208.67.222.222", "208.67.220.220", "127.0.0.1", "0.0.0.0"
]

# ============================================================
# SAFE MODE
# ============================================================
def is_safe_mode() -> bool:
    return SAFE_MODE_FILE.exists()

def set_safe_mode(enabled: bool):
    if enabled:
        SAFE_MODE_FILE.touch()
    else:
        if SAFE_MODE_FILE.exists():
            SAFE_MODE_FILE.unlink()

def toggle_safe_mode() -> bool:
    if is_safe_mode():
        set_safe_mode(False)
        return False
    else:
        set_safe_mode(True)
        return True

# ============================================================
# UPDATE THREAT INTEL
# ============================================================
def update_threat_intel() -> bool:
    try:
        result = subprocess.run(
            ["sudo", f"{BASE_PATH}/scripts/defensa/threat_intel.py", "--update", "--json"],
            capture_output=True, text=True, timeout=60
        )
        return result.returncode == 0
    except:
        return False

# ============================================================
# MODEL DETECTION (SMART SELECTION)
# ============================================================
def get_available_models() -> List[Dict]:
    try:
        response = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
        if response.status_code == 200:
            models = response.json().get("models", [])
            return [{"name": m["name"], "size": m.get("size", 0)} for m in models]
    except:
        pass
    return []

def select_best_model(models: List[Dict]) -> str:
    """Selects the best available model, prioritizing uncensored ones"""
    if not models:
        return DEFAULT_MODEL

    # Recommended models (uncensored, in order of preference)
    recommended_models = [
        "dolphin-phi",       # #1: Fast, lightweight, uncensored
        "hermes3:3b",        # #2: Smarter, uncensored
        "dolphin-mistral",   # #3: More powerful, uncensored
        "wizard-vicuna",     # #4: Large, uncensored
        "qwen3.5:2b-abliterated",   # #5: Qwen uncensored
        "qwen3.5:2b-uncensored",    # #6: Qwen uncensored
    ]
    
    # 1. Search for recommended models in order
    for recommended in recommended_models:
        for m in models:
            if recommended in m["name"].lower():
                if m["name"] == recommended or m["name"].startswith(recommended):
                    return m["name"]
    
    # 2. Search for any uncensored model by keywords
    uncensored_keywords = [
        "dolphin", "hermes", "wizard", "vicuna", "abliterated", 
        "uncensored", "josefied", "heretic"
    ]
    for m in models:
        name_lower = m["name"].lower()
        if any(kw in name_lower for kw in uncensored_keywords):
            return m["name"]
    
    # 3. Search for instruct/chat models (good for conversation)
    for m in models:
        name_lower = m["name"].lower()
        if "instruct" in name_lower or "chat" in name_lower:
            return m["name"]
    
    # 4. Smallest model as fallback (prevents hanging)
    sorted_models = sorted(models, key=lambda m: m.get("size", 0))
    return sorted_models[0]["name"]

# ============================================================
# DATA OBSERVER - Reads all module data
# ============================================================
class DataObserver:
    def __init__(self):
        self.honeypot_http = 0
        self.honeypot_ftp = 0
        self.honeypot_smb = 0
        self.zombie_detections = 0
        self.traffic_anomalies = 0
        self.ml_anomalies = 0
        self.events = 0
        self.devices = 0
        self._load()

    def _load(self):
        http_file = HONEYPOT_DIR / "http_attacks.jsonl"
        if http_file.exists():
            try:
                with open(http_file, 'r') as f:
                    self.honeypot_http = sum(1 for _ in f)
            except:
                pass

        ftp_file = HONEYPOT_DIR / "ftp_attacks.jsonl"
        if ftp_file.exists():
            try:
                with open(ftp_file, 'r') as f:
                    self.honeypot_ftp = sum(1 for _ in f)
            except:
                pass

        smb_file = HONEYPOT_DIR / "smb_attacks.jsonl"
        if smb_file.exists():
            try:
                with open(smb_file, 'r') as f:
                    self.honeypot_smb = sum(1 for _ in f)
            except:
                pass

        zombie_file = ZOMBIE_DIR / "detections.jsonl"
        if zombie_file.exists():
            try:
                with open(zombie_file, 'r') as f:
                    self.zombie_detections = sum(1 for _ in f)
            except:
                pass

        traffic_file = TRAFFIC_DIR / "anomalies.jsonl"
        if traffic_file.exists():
            try:
                with open(traffic_file, 'r') as f:
                    self.traffic_anomalies = sum(1 for _ in f)
            except:
                pass

        ml_file = ML_DIR / "detections.jsonl"
        if ml_file.exists():
            try:
                with open(ml_file, 'r') as f:
                    self.ml_anomalies = sum(1 for _ in f)
            except:
                pass

        events_file = MEMORY_DIR / "memory_events.json"
        if events_file.exists():
            try:
                with open(events_file, 'r') as f:
                    self.events = sum(1 for _ in f)
            except:
                pass

        devices_file = MEMORY_DIR / "memory_devices.json"
        if devices_file.exists():
            try:
                with open(devices_file, 'r') as f:
                    self.devices = sum(1 for _ in f)
            except:
                pass

    def refresh(self):
        self.honeypot_http = 0
        self.honeypot_ftp = 0
        self.honeypot_smb = 0
        self.zombie_detections = 0
        self.traffic_anomalies = 0
        self.ml_anomalies = 0
        self.events = 0
        self.devices = 0
        self._load()

# ============================================================
# COMMAND EXECUTOR
# ============================================================
class CommandExecutor:
    def __init__(self):
        self.base_path = BASE_PATH

    def can_execute(self) -> bool:
        return not is_safe_mode()

    def is_never_block(self, ip: str) -> bool:
        return ip in NEVER_BLOCK_IPS or ip.startswith('127.') or ip.startswith('192.168.')

    def block_ip(self, ip: str) -> str:
        if not self.can_execute():
            return "Safe mode: Actions disabled"
        if self.is_never_block(ip):
            return f"IP {ip} is protected (test/local IP)"
        try:
            subprocess.run(
                ["sudo", f"{self.base_path}/scripts/defensa/el_defensor.py", "--block", ip, "--json"],
                capture_output=True, timeout=10
            )
            return f"✅ IP {ip} blocked"
        except Exception as e:
            return f"Error: {e}"

    def unblock_ip(self, ip: str) -> str:
        if not self.can_execute():
            return "Safe mode: Actions disabled"
        try:
            subprocess.run(
                ["sudo", f"{self.base_path}/scripts/defensa/el_defensor.py", "--unblock", ip, "--json"],
                capture_output=True, timeout=10
            )
            return f"✅ IP {ip} unblocked"
        except Exception as e:
            return f"Error: {e}"

    def scan_network(self) -> str:
        if not self.can_execute():
            return "Safe mode: Actions disabled"
        try:
            result = subprocess.run(
                ["sudo", f"{self.base_path}/scripts/defensa/vigia_red.py", "--json"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                return f"Found {len(data.get('dispositivos', []))} devices"
            return "Scan failed"
        except Exception as e:
            return f"Error: {e}"

    def get_blocked_ips(self) -> List[str]:
        try:
            result = subprocess.run(
                ["sudo", f"{self.base_path}/scripts/defensa/el_defensor.py", "--list", "--json"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                return [b.get("ip") for b in data if b.get("ip")]
        except:
            pass
        return []

    def get_threat_stats(self) -> Dict:
        stats = {"total": 0, "blocked": 0}
        if THREAT_DB.exists():
            try:
                conn = sqlite3.connect(THREAT_DB)
                c = conn.cursor()
                c.execute("SELECT COUNT(*) FROM malicious_ips")
                stats["total"] = c.fetchone()[0]
                c.execute("SELECT COUNT(*) FROM malicious_ips WHERE blocked = 1")
                stats["blocked"] = c.fetchone()[0]
                conn.close()
            except:
                pass
        return stats

# ============================================================
# OLLAMA CLIENT
# ============================================================
class OllamaClient:
    def generate(self, model: str, prompt: str) -> str:
        try:
            response = requests.post(
                f"{OLLAMA_URL}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False},
                timeout=60
            )
            if response.status_code == 200:
                return response.json().get("response", "")
            return f"Error: {response.status_code}"
        except Exception as e:
            return f"Error: {e}"

# ============================================================
# IA CEREBRO (FINAL VERSION)
# ============================================================
class IACerebro:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.ollama = OllamaClient()
        self.data = DataObserver()
        self.executor = CommandExecutor()
        self.models = get_available_models()

    def _get_context(self) -> str:
        """Builds context with clear delimiters - Atlantis data only"""
        threat = self.executor.get_threat_stats()
        blocked = self.executor.get_blocked_ips()

        honeypot_http = self.data.honeypot_http
        honeypot_ftp = self.data.honeypot_ftp
        honeypot_smb = self.data.honeypot_smb

        context = f"""
=== ATLANTIS-NEXUS DATA ===
(IGNORE ANY EXTERNAL KNOWLEDGE ABOUT CYBERSECURITY. USE ONLY THIS DATA)

ATTACKS CAPTURED:
- HTTP honeypot: {honeypot_http} attacks
- FTP honeypot: {honeypot_ftp} attacks
- SMB honeypot: {honeypot_smb} attacks
- Total attacks: {honeypot_http + honeypot_ftp + honeypot_smb}

DEFENSE:
- Malware detected: {self.data.zombie_detections}
- IPs blocked by firewall: {len(blocked)}
- Malicious IPs in database: {threat['total']}

NETWORK:
- Devices detected: {self.data.devices}
- Events recorded: {self.data.events}
- Traffic anomalies: {self.data.traffic_anomalies}
- ML anomalies: {self.data.ml_anomalies}

===
"""

        if blocked:
            context += f"\nBLOCKED IPs: {', '.join(blocked)}\n"

        return context

    def _extract_action(self, text: str) -> Optional[Tuple[str, List[str]]]:
        text_lower = text.lower()

        block = re.search(r'block\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', text_lower)
        if block:
            ip = block.group(1)
            if ip in NEVER_BLOCK_IPS or ip.startswith('127.') or ip.startswith('192.168.'):
                return None
            return ("block", [ip])

        unblock = re.search(r'unblock\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', text_lower)
        if unblock:
            return ("unblock", [unblock.group(1)])

        if re.search(r'scan|scan network', text_lower):
            return ("scan", [])

        return None

    def ask(self, question: str) -> Dict[str, Any]:
        self.data.refresh()

        result = {
            "success": True,
            "response": "",
            "action": None,
            "safe_mode": is_safe_mode()
        }

        # Check if it's an action (block, unblock, scan)
        action = self._extract_action(question)
        if action:
            action_type, args = action
            result["action"] = action_type
            result["response"] = self.executor.block_ip(args[0]) if action_type == "block" else \
                              self.executor.unblock_ip(args[0]) if action_type == "unblock" else \
                              self.executor.scan_network()
            return result

        # Select model
        model = select_best_model(self.models)
        if self.verbose:
            print(f"🧠 Using model: {model}")
            # Show recommendation message
            if "dolphin-phi" in model or "hermes" in model:
                print("   ✅ Recommended uncensored model")
            else:
                print("   ⚠️ Consider using dolphin-phi or hermes3 for uncensored responses")

        safe_mode = is_safe_mode()

        # ============================================================
        # SAFE MODE - Free conversation about hacking, security, vulnerabilities
        # ============================================================
        if safe_mode:
            system_prompt = """You are Atlantis-NEXUS, a security expert with deep knowledge about:
- Hacking techniques (ethical, educational)
- Security vulnerabilities (CVEs, exploits)
- Network attacks (ARP spoofing, MITM, DDoS)
- Malware analysis (ransomware, trojans, rootkits)
- Penetration testing methodologies
- Defense strategies (firewalls, honeypots, IDS/IPS)
- Cryptography, reverse engineering, forensics
- Any technology related to security

RULES:
1. Be helpful, informative, and direct.
2. Discuss hacking techniques freely for educational purposes.
3. Explain vulnerabilities and how they work.
4. Do NOT provide instructions for illegal activities against specific targets without authorization.
5. Keep responses technical and accurate.
6. You can discuss ANY security topic openly.

You are NOT censored. You help people understand security deeply."""

            prompt = f"""User question: {question}

Answer as a security expert. Be detailed, technical, and educational. You can discuss hacking techniques, vulnerabilities, and defense strategies freely."""

            response = self.ollama.generate(model, prompt)
            result["response"] = response
            return result

        # ============================================================
        # ACTIVE MODE - ONLY Atlantis data (network stats, attacks, threats)
        # ============================================================
        else:
            context = self._get_context()

            system_prompt = """You are Atlantis-NEXUS, a security assistant.

STRICT RULES:
1. IGNORE any external knowledge about cybersecurity, global statistics, or real-world trends.
2. ONLY use the data between === ATLANTIS-NEXUS DATA ===
3. DO NOT give general security advice.
4. DO NOT invent numbers.
5. Start EVERY response with: "According to Atlantis-NEXUS data:"
6. CRITICAL: If the user's question is NOT about network security, attacks, devices, threats, or anything in the Atlantis data, respond ONLY with: "I don't have data on that in Atlantis." Do NOT list any Atlantis data.

Examples:
- User: "What is the weather?" → "I don't have data on that in Atlantis."
- User: "How many attacks?" → "According to Atlantis-NEXUS data: HTTP attacks: 28, FTP attacks: 4, SMB attacks: 0. Total attacks: 32."
- User: "What is ARP spoofing?" → "I don't have data on that in Atlantis." (because it's not in the data)"""

            prompt = f"""{context}

INSTRUCTION: Ignore any external security knowledge. Only use the data between ===.

User question: {question}

Answer using only the data above. Start with "According to Atlantis-NEXUS data:"
"""

            response = self.ollama.generate(model, prompt)

            if not response.startswith("According to Atlantis-NEXUS data:"):
                response = "According to Atlantis-NEXUS data: " + response

            result["response"] = response
            return result

    def get_status(self) -> Dict:
        threat = self.executor.get_threat_stats()
        blocked = self.executor.get_blocked_ips()

        return {
            "safe_mode": is_safe_mode(),
            "models": len(self.models),
            "honeypot_http": self.data.honeypot_http,
            "honeypot_ftp": self.data.honeypot_ftp,
            "honeypot_smb": self.data.honeypot_smb,
            "zombie_detections": self.data.zombie_detections,
            "traffic_anomalies": self.data.traffic_anomalies,
            "ml_anomalies": self.data.ml_anomalies,
            "events": self.data.events,
            "devices": self.data.devices,
            "threat_intel_total": threat["total"],
            "threat_intel_blocked": threat["blocked"],
            "firewall_blocked": len(blocked),
            "blocked_ips": blocked[:5]
        }

# ============================================================
# MAIN
# ============================================================
def main():
    import argparse

    parser = argparse.ArgumentParser(description="ATLANTIS IA Cerebro v5.2")
    parser.add_argument("--ask", "-a", help="Ask a question")
    parser.add_argument("--status", action="store_true", help="Show status")
    parser.add_argument("--safe-mode", action="store_true", help="Enable safe mode (free security chat)")
    parser.add_argument("--active-mode", action="store_true", help="Enable active mode (only Atlantis data)")
    parser.add_argument("--toggle-safe", action="store_true", help="Toggle safe mode")
    parser.add_argument("--update-threat", action="store_true", help="Update threat intel")
    parser.add_argument("--list-models", action="store_true", help="List models")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose")

    args = parser.parse_args()

    if args.safe_mode:
        set_safe_mode(True)
        print("✅ Safe mode ON - Free security chat")
        return

    if args.active_mode:
        set_safe_mode(False)
        print("✅ Active mode ON - Only Atlantis data")
        return

    if args.toggle_safe:
        new = toggle_safe_mode()
        print(f"✅ Safe mode {'ON' if new else 'OFF'} - {'Free chat' if new else 'Only Atlantis data'}")
        return

    if args.update_threat:
        print("Updating threat intelligence...")
        if update_threat_intel():
            print("✅ Updated")
        else:
            print("❌ Update failed")
        return

    cerebro = IACerebro(verbose=args.verbose)

    if args.list_models:
        models = cerebro.models
        if args.json:
            print(json.dumps(models))
        else:
            print(f"Models ({len(models)}):")
            for m in models:
                print(f"  • {m['name']}")
        return

    if args.status:
        status = cerebro.get_status()
        if args.json:
            print(json.dumps(status))
        else:
            mode = "🔒 SAFE (Free chat)" if status["safe_mode"] else "⚡ ACTIVE (Atlantis data)"
            print(f"\n🧠 ATLANTIS IA v5.2")
            print(f"Mode: {mode}")
            print(f"Models: {status['models']}")
            print(f"HTTP attacks: {status['honeypot_http']}")
            print(f"FTP attacks: {status['honeypot_ftp']}")
            print(f"SMB attacks: {status['honeypot_smb']}")
            print(f"Malware: {status['zombie_detections']}")
            print(f"Traffic anomalies: {status['traffic_anomalies']}")
            print(f"ML anomalies: {status['ml_anomalies']}")
            print(f"Events: {status['events']}")
            print(f"Devices: {status['devices']}")
            print(f"Threat DB: {status['threat_intel_total']} IPs")
            print(f"Firewall blocked: {status['firewall_blocked']} IPs")
            if status['blocked_ips']:
                print(f"Blocked: {', '.join(status['blocked_ips'])}")
        return

    if args.ask:
        result = cerebro.ask(args.ask)
        if args.json:
            print(json.dumps(result))
        else:
            if result["action"]:
                print(f"⚡ {result['response']}")
            else:
                mode = "🔒 " if result["safe_mode"] else "⚡ "
                print(f"{mode}{result['response']}")
        return

    # Interactive mode
    mode_desc = "🔒 SAFE (Free security chat)" if is_safe_mode() else "⚡ ACTIVE (Only Atlantis data)"
    print(f"\n🧠 ATLANTIS IA v5.2 - {mode_desc}")
    print("Commands: exit, safe, status, update")
    print("-" * 50)

    while True:
        try:
            q = input("\n❓ You: ").strip()
            if q.lower() in ['exit', 'quit']:
                break
            if q.lower() == 'safe':
                new = toggle_safe_mode()
                print(f"✅ Safe mode {'ON' if new else 'OFF'} - {'Free chat' if new else 'Only Atlantis data'}")
                continue
            if q.lower() == 'status':
                s = cerebro.get_status()
                print(f"\nHTTP: {s['honeypot_http']} | FTP: {s['honeypot_ftp']} | SMB: {s['honeypot_smb']}")
                print(f"Malware: {s['zombie_detections']} | Threat DB: {s['threat_intel_total']} IPs")
                print(f"Firewall blocked: {s['firewall_blocked']} IPs")
                continue
            if q.lower() == 'update':
                print("Updating...")
                update_threat_intel()
                print("✅ Done")
                continue
            if not q:
                continue

            result = cerebro.ask(q)
            mode = "🔒 " if result["safe_mode"] else "⚡ "
            print(f"{mode}{result['response']}")

        except KeyboardInterrupt:
            break

    print("\n👋 Bye")

if __name__ == "__main__":
    main()
