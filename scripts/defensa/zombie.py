#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ATLANTIS - ZOMBIE MODULE v2.7 (Final - Fixed Permission Handling)
Detección automática, bloqueo, cuarentena
• Monitoreo de carpetas
• Bloqueo con confirmación
• Cuarentena de archivos sospechosos
• Coordinación con Defender
• Modo JSON para integración con NEMESIS
• Modo daemon para monitoreo continuo
• Validación de archivos (existencia, tamaño, tipo)
• Detección inteligente con pesos variables
• Balance entre detección y falsos positivos
• CORREGIDO: PID file ahora lo escribe el proceso hijo
• CORREGIDO: Stop mata procesos y limpia archivos
• CORREGIDO: is_running maneja PermissionError (root vs user)
"""

import os
import sys
import json
import time
import shutil
import hashlib
import argparse
import platform
import subprocess
import re
import threading
import signal
import socket
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

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
# CONFIGURACIÓN
# ============================================================
BASE_PATH = get_base_path()
DATA_DIR = BASE_PATH / "data"
ZOMBIE_DIR = DATA_DIR / "zombie_logs"
QUARANTINE_DIR = ZOMBIE_DIR / "quarantine"
RULES_FILE = BASE_PATH / "scripts/defensa/zombie_rules.json"
PID_FILE = DATA_DIR / "zombie.pid"
STATUS_FILE = DATA_DIR / "zombie_status.json"

# Directorios a monitorear (opcional, se pueden configurar)
WATCH_DIRS = [
    Path.home() / "Downloads",
    Path.home() / "Desktop",
    Path.home() / "Documents",
]

ZOMBIE_DIR.mkdir(parents=True, exist_ok=True)
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

DETECTIONS_FILE = ZOMBIE_DIR / "detections.jsonl"
LOG_FILE = ZOMBIE_DIR / "zombie.log"

stop_event = threading.Event()

# ============================================================
# LOGGER
# ============================================================
class ZombieLogger:
    def __init__(self, log_file: Path):
        self.log_file = log_file

    def _write(self, level: str, message: str):
        ts = datetime.now().isoformat()
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(f"{ts} | {level:8} | {message}\n")
        except:
            pass

    def info(self, msg): self._write("INFO", msg)
    def warning(self, msg): self._write("WARNING", msg)
    def error(self, msg): self._write("ERROR", msg)

    def detection(self, file_path: str, reason: str, score: float, quarantined: bool = False):
        detection = {
            "timestamp": datetime.now().isoformat(),
            "file": file_path,
            "reason": reason,
            "score": score,
            "quarantined": quarantined,
            "type": "malware_detection"
        }
        try:
            with open(DETECTIONS_FILE, 'a', encoding='utf-8') as f:
                f.write(json.dumps(detection, ensure_ascii=False) + '\n')
        except:
            pass
        status = "QUARANTINED" if quarantined else "DETECTED"
        self._write("DETECTION", f"{status}: {file_path} - {reason} (score: {score:.2f})")

# ============================================================
# ANALIZADORES DE ARCHIVOS
# ============================================================
class FileAnalyzer:
    def __init__(self, logger: ZombieLogger):
        self.logger = logger
        self._pil_available = self._check_pil()

    def _check_pil(self) -> bool:
        try:
            import PIL
            return True
        except ImportError:
            return False

    def analyze_zip(self, file_path: Path) -> Tuple[bool, str, float]:
        try:
            import zipfile
            with zipfile.ZipFile(file_path, 'r') as zf:
                test = zf.testzip()
                if test:
                    return True, f"Corrupt ZIP: {test}", 0.9
                return False, "", 0.0
        except zipfile.BadZipFile:
            return True, "Corrupt ZIP header", 0.95
        except:
            return False, "", 0.0

    def analyze_image(self, file_path: Path) -> Tuple[bool, str, float]:
        if not self._pil_available:
            return False, "", 0.0
        try:
            from PIL import Image
            import numpy as np
            img = Image.open(file_path)
            img_array = np.array(img)
            hist, _ = np.histogram(img_array, bins=256)
            hist = hist / (hist.sum() + 1e-10)
            entropy = -np.sum(hist * np.log2(hist + 1e-10))
            if entropy > 7.5:
                return True, f"High entropy: {entropy:.2f}", min(entropy / 8, 1.0)
            return False, "", 0.0
        except:
            return False, "", 0.0

    def analyze_script(self, file_path: Path) -> Tuple[bool, str, float]:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Patrones con pesos balanceados
            suspicious_patterns = [
                (r'eval\s*\(', 'eval()', 0.35),
                (r'exec\s*\(', 'exec()', 0.35),
                (r'base64\.b64decode\s*\(', 'base64.b64decode()', 0.25),
                (r'__import__\s*\(', '__import__()', 0.2),
                (r'powershell\s+-[eE]n[cC]', 'PowerShell -enc', 0.35),
                (r'Invoke-Expression', 'Invoke-Expression', 0.35),
                (r'\biex\b', 'iex (PowerShell)', 0.25),
                (r'curl\s+.*\|\s*(sh|bash)', 'curl | sh', 0.4),
                (r'wget\s+.*\|\s*(sh|bash)', 'wget | sh', 0.4),
                (r'subprocess\.\w+\s*\(', 'subprocess', 0.2),
                (r'os\.system\s*\(', 'os.system()', 0.3),
                (r'os\.popen\s*\(', 'os.popen()', 0.2),
                (r'socket\.', 'socket', 0.15),
                (r'urllib\.', 'urllib', 0.15),
            ]

            score = 0.0
            found = []

            for pattern, description, weight in suspicious_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    score += weight
                    found.append(description)

            # Normalizar score (máximo teórico ~3.0)
            normalized_score = min(score / 2.5, 1.0)

            # Detección inteligente:
            # 1. Al menos 2 patrones → detecta
            # 2. Patrón de alta severidad (peso >= 0.4) → detecta
            # 3. Patrón de media severidad (peso >= 0.3) Y score > 0.2 → detecta
            # 4. Score normalizado > 0.25 → detecta

            has_high_severity = False
            has_medium_severity = False
            for pattern, desc, weight in suspicious_patterns:
                if weight >= 0.4 and re.search(pattern, content, re.IGNORECASE):
                    has_high_severity = True
                    break
                if weight >= 0.3 and re.search(pattern, content, re.IGNORECASE):
                    has_medium_severity = True

            if len(found) >= 2:
                return True, f"Malware detected: {', '.join(found)}", normalized_score
            if has_high_severity:
                return True, f"Malware detected: {', '.join(found)}", normalized_score
            if has_medium_severity and score > 0.2:
                return True, f"Malware detected: {', '.join(found)}", normalized_score
            if normalized_score > 0.25:
                return True, f"Malware detected: {', '.join(found)}", normalized_score

            return False, "", 0.0
        except:
            return False, "", 0.0

    def analyze_document(self, file_path: Path) -> Tuple[bool, str, float]:
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            indicators = [b'Macros', b'VBA', b'ThisDocument', b'Sub ', b'Attribute VB_Name']
            score = 0.0
            found = []
            for ind in indicators:
                if ind in content:
                    score += 0.25
                    found.append(ind.decode('utf-8', errors='ignore'))
            if score > 0.5:
                return True, f"Macros detected: {', '.join(found)}", min(score, 1.0)
            return False, "", 0.0
        except:
            return False, "", 0.0

    def scan(self, file_path: Path) -> Tuple[bool, str, float]:
        ext = file_path.suffix.lower()
        if ext in ['.zip', '.rar', '.7z']:
            return self.analyze_zip(file_path)
        elif ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
            return self.analyze_image(file_path)
        elif ext in ['.py', '.ps1', '.sh', '.bat', '.cmd', '.js', '.vbs']:
            return self.analyze_script(file_path)
        elif ext in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']:
            return self.analyze_document(file_path)
        return False, "", 0.0

# ============================================================
# CONTROLADOR CON CUARENTENA Y VALIDACIONES
# ============================================================
class ZombieController:
    def __init__(self, verbose: bool = False, auto_quarantine: bool = False):
        self.logger = ZombieLogger(LOG_FILE)
        self.analyzer = FileAnalyzer(self.logger)
        self.verbose = verbose
        self.auto_quarantine = auto_quarantine

    def quarantine_file(self, file_path: Path, reason: str) -> bool:
        """Mueve archivo a cuarentena"""
        try:
            timestamp = int(time.time())
            quarantine_path = QUARANTINE_DIR / f"{file_path.name}_{timestamp}"
            shutil.move(str(file_path), str(quarantine_path))
            self.logger.info(f"Moved to quarantine: {quarantine_path}")
            return True
        except Exception as e:
            self.logger.error(f"Quarantine error: {e}")
            return False

    def _extract_ip_from_file(self, file_path: Path) -> Optional[str]:
        """Intenta extraer IP de archivo (para bloqueo)"""
        try:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
            ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', content)
            if ips:
                return ips[0]
        except:
            pass
        return None

    def _block_ip(self, ip: str):
        """Bloquea IP usando el defensor"""
        try:
            import el_defensor
            from el_defensor import DefenderController
            controller = DefenderController(verbose=False, json_output=True)
            if controller.block_ip(ip):
                self.logger.info(f"IP {ip} blocked by Zombie")
        except Exception as e:
            self.logger.error(f"IP block error {ip}: {e}")

    def scan_file(self, file_path: str, interactive: bool = True, json_output: bool = False) -> Dict[str, Any]:
        """Escanea un archivo individual con validaciones"""
        path = Path(file_path)

        # VALIDACIÓN 1: El archivo existe
        if not path.exists():
            error_result = {
                "success": False,
                "error": "File not found",
                "file": file_path,
                "detected": False
            }
            if json_output:
                return error_result
            print(f"❌ File not found: {file_path}")
            return error_result

        # VALIDACIÓN 2: Es un archivo, no un directorio
        if not path.is_file():
            error_result = {
                "success": False,
                "error": "Path is a directory, not a file",
                "file": file_path,
                "detected": False
            }
            if json_output:
                return error_result
            print(f"❌ Path is a directory, not a file: {file_path}")
            return error_result

        # VALIDACIÓN 3: Tamaño razonable (máximo 100 MB)
        try:
            file_size = path.stat().st_size
            if file_size > 100 * 1024 * 1024:  # 100 MB
                error_result = {
                    "success": False,
                    "error": f"File too large: {file_size} bytes (max 100MB)",
                    "file": file_path,
                    "detected": False
                }
                if json_output:
                    return error_result
                print(f"❌ File too large: {file_size} bytes (max 100MB)")
                return error_result
        except Exception as e:
            error_result = {
                "success": False,
                "error": f"Cannot access file: {e}",
                "file": file_path,
                "detected": False
            }
            if json_output:
                return error_result
            print(f"❌ Cannot access file: {e}")
            return error_result

        detected, reason, score = self.analyzer.scan(path)

        result = {
            "success": True,
            "file": str(path),
            "detected": detected,
            "reason": reason,
            "score": score,
            "quarantined": False
        }

        if detected:
            if json_output:
                self.logger.detection(str(path), reason, score, quarantined=False)
                return result

            print(f"\n🚨 ZOMBIE ALERT: {path.name}")
            print(f"   Reason: {reason}")
            print(f"   Score: {score:.2f}")

            if interactive and not self.auto_quarantine:
                print("\n   Options:")
                print("   1. Quarantine (recommended)")
                print("   2. Ignore")
                print("   3. Block associated IP (if detected)")
                choice = input("   ➤ Choose (1/2/3): ").strip()

                if choice == "1":
                    if self.quarantine_file(path, reason):
                        result["quarantined"] = True
                        self.logger.detection(str(path), reason, score, quarantined=True)
                elif choice == "3":
                    ip = self._extract_ip_from_file(path)
                    if ip:
                        print(f"   🔒 Blocking IP: {ip}")
                        self._block_ip(ip)
                    self.logger.detection(str(path), reason, score, quarantined=False)
                else:
                    self.logger.detection(str(path), reason, score, quarantined=False)
            elif self.auto_quarantine:
                if self.quarantine_file(path, reason):
                    result["quarantined"] = True
                    self.logger.detection(str(path), reason, score, quarantined=True)
            else:
                self.logger.detection(str(path), reason, score, quarantined=False)

        return result

    def scan_directory(self, directory: str, recursive: bool = True, json_output: bool = False) -> List[Dict]:
        """Escanea un directorio completo con validaciones"""
        results = []
        path = Path(directory)

        # VALIDACIÓN 1: El directorio existe
        if not path.exists():
            error_msg = f"Directory not found: {directory}"
            if json_output:
                return [{"success": False, "error": error_msg, "directory": directory}]
            print(f"❌ {error_msg}")
            return []

        # VALIDACIÓN 2: Es un directorio, no un archivo
        if not path.is_dir():
            error_msg = f"Path is a file, not a directory: {directory}"
            if json_output:
                return [{"success": False, "error": error_msg, "directory": directory}]
            print(f"❌ {error_msg}")
            return []

        files = list(path.rglob('*')) if recursive else list(path.glob('*'))
        total = len(files)

        for i, file_path in enumerate(files):
            if file_path.is_file():
                if self.verbose and not json_output:
                    print(f"🔍 [{i+1}/{total}] Scanning: {file_path}")
                result = self.scan_file(str(file_path), interactive=False, json_output=json_output)
                if result.get("detected"):
                    results.append(result)

        return results

    def get_stats(self, json_output: bool = False) -> Dict:
        """Obtiene estadísticas de detección"""
        detections = []
        if DETECTIONS_FILE.exists():
            with open(DETECTIONS_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        detections.append(json.loads(line))
                    except:
                        pass

        stats = {
            "total_detections": len(detections),
            "recent_detections": detections[-10:]
        }

        if json_output:
            return stats

        print(f"\n📊 ZOMBIE STATISTICS")
        print(f"Total detections: {stats['total_detections']}")
        if stats['recent_detections']:
            print("Recent detections:")
            for d in stats['recent_detections'][-5:]:
                print(f"   • {d['file']} - {d['reason']}")
        return stats

# ============================================================
# MONITORING DAEMON
# ============================================================
class ZombieWatcher:
    def __init__(self, controller: ZombieController):
        self.controller = controller
        self.processed_files = set()

    def watch_directory(self, directory: Path):
        """Monitor directory for new files"""
        try:
            if not directory.exists():
                return
            for file_path in directory.glob("*"):
                if file_path.is_file() and file_path not in self.processed_files:
                    self.processed_files.add(file_path)
                    self.controller.scan_file(str(file_path), interactive=False, json_output=False)
        except Exception as e:
            pass

    def start(self):
        print("👁️ Zombie Watcher started")
        print(f"   Monitoring: {', '.join(str(d) for d in WATCH_DIRS)}")
        print("   Press Ctrl+C to stop")

        while not stop_event.is_set():
            for directory in WATCH_DIRS:
                self.watch_directory(directory)
            time.sleep(5)

# ============================================================
# DAEMON FUNCTIONS (MEJORADAS)
# ============================================================
def write_pid():
    """Escribe el PID del proceso actual en el archivo"""
    try:
        with open(PID_FILE, 'w') as f:
            f.write(str(os.getpid()))
            f.flush()
    except:
        pass

def remove_pid():
    """Elimina el archivo PID"""
    try:
        if PID_FILE.exists():
            PID_FILE.unlink()
    except:
        pass

def is_running():
    """
    Verifica si el daemon/watcher está corriendo.
    Maneja correctamente el caso en que el proceso es de root y el usuario no tiene permiso.
    """
    if not PID_FILE.exists():
        return False
    try:
        with open(PID_FILE, 'r') as f:
            pid = int(f.read().strip())
        # Intentar enviar señal 0 para verificar existencia
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        # El proceso no existe
        remove_pid()
        return False
    except PermissionError:
        # El proceso existe pero no tenemos permiso para señalarlo (ej. root vs user)
        # Asumimos que está corriendo
        return True
    except:
        # Otro error: limpiar y asumir que no corre
        remove_pid()
        return False

def write_status(status: Dict):
    """Escribe el estado en el archivo de estado"""
    try:
        with open(STATUS_FILE, 'w') as f:
            json.dump(status, f)
            f.flush()
    except:
        pass

def signal_handler(sig, frame):
    print("\n🛑 Stopping Zombie module...")
    stop_event.set()
    remove_pid()
    sys.exit(0)

# ============================================================
# MAIN
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="ATLANTIS Zombie Module v2.7 - Malware Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Scan a file
  python zombie.py --scan /path/to/file

  # Scan a directory
  python zombie.py --scan /path/to/dir --recursive

  # JSON output (for NEMESIS)
  python zombie.py --scan file.zip --json

  # Start continuous monitoring
  python zombie.py --watch

  # Start as background daemon
  python zombie.py --daemon

  # Stop daemon
  python zombie.py --stop

  # Show statistics
  python zombie.py --stats
        """
    )

    parser.add_argument("--scan", metavar="PATH", help="Scan a file or directory")
    parser.add_argument("--recursive", "-r", action="store_true", help="Scan recursively")
    parser.add_argument("--watch", action="store_true", help="Start monitoring mode")
    parser.add_argument("--daemon", action="store_true", help="Run as background daemon")
    parser.add_argument("--stop", action="store_true", help="Stop running daemon")
    parser.add_argument("--status", action="store_true", help="Show daemon status")
    parser.add_argument("--stats", action="store_true", help="Show detection statistics")
    parser.add_argument("--auto-quarantine", action="store_true", help="Auto quarantine without asking")
    parser.add_argument("--json", action="store_true", help="JSON output mode for NEMESIS")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    # ============================================================
    # STOP COMMAND (mejorado)
    # ============================================================
    if args.stop:
        # Intentar matar aunque is_running() devuelva False (por permiso)
        killed = False
        if PID_FILE.exists():
            try:
                with open(PID_FILE, 'r') as f:
                    pid = int(f.read().strip())
                # Intentar matar con SIGTERM
                os.kill(pid, signal.SIGTERM)
                time.sleep(1)
                # Verificar si aún vive
                try:
                    os.kill(pid, 0)
                    # Si aún vive, matar con SIGKILL
                    os.kill(pid, signal.SIGKILL)
                except:
                    pass
                killed = True
            except Exception:
                pass
        # Limpiar archivos siempre
        remove_pid()
        if STATUS_FILE.exists():
            STATUS_FILE.unlink()
        if killed:
            print(json.dumps({"success": True, "action": "stop"}))
        else:
            print(json.dumps({"success": False, "action": "stop", "message": "Not running"}))
        return

    # ============================================================
    # STATUS COMMAND
    # ============================================================
    if args.status:
        if is_running():
            if STATUS_FILE.exists():
                with open(STATUS_FILE, 'r') as f:
                    status = json.load(f)
                print(json.dumps({"running": True, "status": status}))
            else:
                print(json.dumps({"running": True}))
        else:
            print(json.dumps({"running": False}))
        return

    # ============================================================
    # DAEMON OR WATCH COMMAND
    # ============================================================
    if args.daemon or args.watch:
        if is_running():
            print(json.dumps({"success": False, "error": "Zombie already running"}))
            return

        pid = os.fork()
        if pid > 0:
            # Parent process - wait for child to write PID
            time.sleep(1)
            # Check if child wrote PID file
            if PID_FILE.exists():
                with open(PID_FILE, 'r') as f:
                    child_pid = int(f.read().strip())
                print(json.dumps({"success": True, "action": "start", "pid": child_pid}))
            else:
                print(json.dumps({"success": False, "error": "Child failed to start"}))
            return
        else:
            # Child process (daemon) - THIS IS THE ACTUAL RUNNING PROCESS
            os.setsid()
            # Close stdin, stdout, stderr
            sys.stdin = open('/dev/null', 'r')
            sys.stdout = open('/dev/null', 'w')
            sys.stderr = open('/dev/null', 'w')

            # Write PID file from child process
            write_pid()
            write_status({"running": True, "start_time": datetime.now().isoformat()})

            # Continue to watch mode (no return, fall through)

    # ============================================================
    # SIGNAL HANDLERS
    # ============================================================
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    controller = ZombieController(verbose=args.verbose, auto_quarantine=args.auto_quarantine)

    # ============================================================
    # WATCH/DAEMON MODE (para el proceso hijo)
    # ============================================================
    if args.watch or args.daemon:
        watcher = ZombieWatcher(controller)
        watcher.start()
        return

    # ============================================================
    # SCAN MODE
    # ============================================================
    if args.scan:
        path = Path(args.scan)
        if path.is_file():
            result = controller.scan_file(str(path), interactive=not args.json, json_output=args.json)
            if args.json:
                print(json.dumps(result, indent=2))
            elif result["detected"]:
                print(f"\n✅ Scan complete. Score: {result['score']:.2f}")
        elif path.is_dir():
            results = controller.scan_directory(str(path), recursive=args.recursive, json_output=args.json)
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                print(f"\n🔍 Scanned: {path}")
                print(f"📊 Detections: {len(results)}")
                for r in results[:10]:
                    print(f"   🚨 {r['file']} - {r['reason']}")
        else:
            print(f"❌ Path not found: {args.scan}")
        return

    # ============================================================
    # STATS MODE
    # ============================================================
    if args.stats:
        stats = controller.get_stats(json_output=args.json)
        if args.json:
            print(json.dumps(stats, indent=2))
        return

    # No arguments, show help
    parser.print_help()

if __name__ == "__main__":
    main()
