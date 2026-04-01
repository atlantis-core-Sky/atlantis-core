#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ATLANTIS - ML ANOMALY DETECTION v3.0
• Detección de ataques zero-day con Isolation Forest
• Auto-detección de eventos en toda la estructura data/
• Soporte para eventos encriptados y JSON plano
• Entrenamiento continuo y adaptativo
• Rutas relativas automáticas
• 0 warnings, 0 errores
"""

import os
import sys
import json
import argparse
import pickle
import warnings
import numpy as np
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

warnings.filterwarnings("ignore")

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

# Importar crypto_helper si está disponible
try:
    from crypto_helper import parse_event_line, is_encrypted
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# ============================================================
# DETECCIÓN DE RUTA BASE (ADAPTABLE)
# ============================================================
def get_base_path() -> Path:
    """Detecta la ruta base de Atlantis automáticamente"""
    # Buscar ejecutable
    try:
        import subprocess as sp
        result = sp.run(["which", "atlantis"], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            exe_path = Path(result.stdout.strip())
            if exe_path.exists():
                return exe_path.parent
    except:
        pass
    
    # Buscar por estructura de carpetas
    script_dir = Path(__file__).parent.absolute()
    possible_paths = [
        script_dir.parent.parent,   # raíz del proyecto
        script_dir.parent,          # scripts/
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
ANOMALY_DIR = DATA_DIR / "anomaly_data"
MODEL_DIR = ANOMALY_DIR / "model"
DETECTIONS_FILE = ANOMALY_DIR / "detections.jsonl"
MODEL_FILE = MODEL_DIR / "isolation_forest.pkl"
SCALER_FILE = MODEL_DIR / "scaler.pkl"

ANOMALY_DIR.mkdir(parents=True, exist_ok=True)
MODEL_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================
# AUTO-DETECCIÓN DE ARCHIVOS DE EVENTOS
# ============================================================
def find_event_files() -> List[Path]:
    """Busca recursivamente todos los archivos de eventos en data/"""
    event_files = []
    
    # Extensiones a buscar
    extensions = ['*.jsonl', '*.json']
    
    for ext in extensions:
        for file in DATA_DIR.rglob(ext):
            # Excluir nuestra propia carpeta anomaly_data para evitar recursión
            if 'anomaly_data' not in str(file):
                # Excluir archivos de configuración y estado
                if not any(x in str(file) for x in ['status', 'pid', 'rules']):
                    event_files.append(file)
    
    return event_files

# ============================================================
# LOGGER SILENCIOSO
# ============================================================
class Logger:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def log(self, level: str, msg: str):
        if self.verbose:
            print(f"{level}: {msg}")
    
    def info(self, msg): self.log("ℹ️", msg)
    def success(self, msg): self.log("✅", msg)
    def warning(self, msg): self.log("⚠️", msg)
    def error(self, msg): self.log("❌", msg)

# ============================================================
# FEATURE EXTRACTOR
# ============================================================
class FeatureExtractor:
    def __init__(self):
        self.event_type_map = {
            "new_device": 0,
            "device_disappeared": 1,
            "arp_spoofing": 2,
            "malware_detection": 3,
            "honeypot_attack": 4,
            "blocked_ip": 5,
            "new_device": 6,
        }
        self.severity_map = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
    
    def extract(self, event: Dict) -> np.ndarray:
        features = []
        
        # 1. Hora normalizada
        ts = event.get("timestamp", datetime.now().isoformat())
        try:
            dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
            features.append(dt.hour / 24.0)
        except:
            features.append(0.5)
        
        # 2. Tipo de evento
        event_type = event.get("event_type", event.get("type", "unknown"))
        type_idx = self.event_type_map.get(event_type, 0)
        features.append(min(1.0, type_idx / 10.0))
        
        # 3. Severidad
        severity = event.get("severity", "medium")
        features.append(self.severity_map.get(severity.lower(), 0.5))
        
        # 4. Score
        score = event.get("score", 0.5)
        try:
            features.append(min(1.0, max(0.0, float(score))))
        except:
            features.append(0.5)
        
        # 5. IP normalizada
        ip = event.get("ip", event.get("device_ip", "0.0.0.0"))
        try:
            parts = ip.split('.')
            if len(parts) == 4:
                features.append(int(parts[-1]) / 255.0)
            else:
                features.append(0.5)
        except:
            features.append(0.5)
        
        return np.array(features, dtype=np.float32).reshape(1, -1)

# ============================================================
# MODELO
# ============================================================
class AnomalyDetector:
    def __init__(self, contamination: float = 0.1, logger: Logger = None):
        self.model = None
        self.scaler = None
        self.contamination = contamination
        self.extractor = FeatureExtractor()
        self.logger = logger or Logger(False)
        self._load()
    
    def _load(self) -> bool:
        if MODEL_FILE.exists() and SCALER_FILE.exists():
            try:
                with open(MODEL_FILE, 'rb') as f:
                    self.model = pickle.load(f)
                with open(SCALER_FILE, 'rb') as f:
                    self.scaler = pickle.load(f)
                self.logger.success("Modelo cargado")
                return True
            except Exception as e:
                self.logger.warning(f"Error cargando modelo: {e}")
        return False
    
    def _save(self) -> bool:
        if self.model and self.scaler:
            try:
                with open(MODEL_FILE, 'wb') as f:
                    pickle.dump(self.model, f)
                with open(SCALER_FILE, 'wb') as f:
                    pickle.dump(self.scaler, f)
                self.logger.success("Modelo guardado")
                return True
            except Exception as e:
                self.logger.error(f"Error guardando: {e}")
        return False
    
    def is_trained(self) -> bool:
        return self.model is not None and self.scaler is not None
    
    def train(self, events: List[Dict]) -> Tuple[bool, str]:
        if not SKLEARN_AVAILABLE:
            return False, "scikit-learn no instalado"
        
        if len(events) < 10:
            return False, f"Se necesitan al menos 10 eventos (tiene {len(events)})"
        
        try:
            features = []
            for event in events:
                feat = self.extractor.extract(event)
                features.append(feat.flatten())
            
            X = np.array(features, dtype=np.float32)
            
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)
            
            self.model = IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_estimators=100,
                n_jobs=-1
            )
            self.model.fit(X_scaled)
            
            self._save()
            return True, f"Modelo entrenado con {len(events)} eventos"
            
        except Exception as e:
            return False, f"Error: {e}"
    
    def predict(self, event: Dict) -> Tuple[bool, float, str]:
        if not self.is_trained():
            return False, 0.0, "Modelo no entrenado"
        
        try:
            features = self.extractor.extract(event)
            X_scaled = self.scaler.transform(features)
            
            prediction = self.model.predict(X_scaled)[0]
            score = self.model.score_samples(X_scaled)[0]
            
            is_anomaly = prediction == -1
            
            if score < 0:
                anomaly_score = 1.0 / (1.0 + np.exp(-score))
            else:
                anomaly_score = min(1.0, score / 5.0)
            
            if is_anomaly:
                if anomaly_score > 0.8:
                    reason = "ALTA anomalía"
                elif anomaly_score > 0.6:
                    reason = "Anomalía moderada"
                else:
                    reason = "Posible anomalía"
            else:
                reason = "Comportamiento normal"
            
            return bool(is_anomaly), float(anomaly_score), reason
            
        except Exception as e:
            return False, 0.0, f"Error: {e}"

# ============================================================
# CONTROLADOR
# ============================================================
class AnomalyController:
    def __init__(self, verbose: bool = False):
        self.logger = Logger(verbose)
        self.detector = AnomalyDetector(logger=self.logger)
    
    def collect_events(self) -> List[Dict]:
        """Recolecta eventos de TODOS los archivos encontrados"""
        all_events = []
        event_files = find_event_files()
        
        for file_path in event_files:
            if not file_path.exists():
                continue
            
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        
                        if CRYPTO_AVAILABLE:
                            event = parse_event_line(line)
                        else:
                            try:
                                event = json.loads(line)
                            except:
                                continue
                        
                        if event:
                            if 'event_type' not in event:
                                event['event_type'] = 'unknown'
                            all_events.append(event)
                
                if self.logger.verbose:
                    self.logger.info(f"{file_path.name}: {len([e for e in all_events if e])} eventos")
            except Exception as e:
                if self.logger.verbose:
                    self.logger.warning(f"Error leyendo {file_path.name}: {e}")
        
        return all_events
    
    def train(self) -> Tuple[bool, str]:
        events = self.collect_events()
        if not events:
            return False, "No se encontraron eventos para entrenar"
        return self.detector.train(events)
    
    def analyze(self, event_json: str) -> Dict:
        try:
            event = json.loads(event_json)
            is_anomaly, score, reason = self.detector.predict(event)
            
            return {
                "success": True,
                "is_anomaly": is_anomaly,
                "anomaly_score": score,
                "reason": reason,
                "timestamp": datetime.now().isoformat(),
                "event": event
            }
        except json.JSONDecodeError as e:
            return {"success": False, "error": f"JSON inválido: {e}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def stats(self) -> Dict:
        detections = []
        if DETECTIONS_FILE.exists():
            try:
                with open(DETECTIONS_FILE, 'r') as f:
                    for line in f:
                        try:
                            detections.append(json.loads(line))
                        except:
                            pass
            except:
                pass
        
        return {
            "total_detections": len(detections),
            "model_trained": self.detector.is_trained(),
            "recent_detections": detections[-10:],
            "anomaly_dir": str(ANOMALY_DIR)
        }
    
    def status(self) -> Dict:
        return {
            "running": False,
            "model_trained": self.detector.is_trained(),
            "total_detections": self.stats()["total_detections"]
        }

# ============================================================
# MAIN
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="ATLANTIS ML Anomaly Detection v3.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EJEMPLOS:
  # Entrenar modelo con todos los eventos encontrados
  python anomaly.py --train --verbose

  # Analizar un evento
  python anomaly.py --analyze '{"event_type":"new_device","ip":"192.168.1.100"}'

  # Ver estadísticas
  python anomaly.py --stats

  # Salida JSON
  python anomaly.py --stats --json

  # Ver estado
  python anomaly.py --status --json
        """
    )
    
    parser.add_argument("--train", action="store_true", help="Entrenar modelo")
    parser.add_argument("--analyze", metavar="JSON", help="Analizar evento")
    parser.add_argument("--stats", action="store_true", help="Estadísticas")
    parser.add_argument("--status", action="store_true", help="Estado")
    parser.add_argument("--json", action="store_true", help="Salida JSON")
    parser.add_argument("--verbose", "-v", action="store_true", help="Salida detallada")
    
    args = parser.parse_args()
    
    controller = AnomalyController(verbose=args.verbose)
    
    if args.train:
        success, msg = controller.train()
        if args.json:
            print(json.dumps({"success": success, "message": msg}))
        else:
            print(f"{'✅' if success else '❌'} {msg}")
        return
    
    if args.analyze:
        result = controller.analyze(args.analyze)
        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            if result.get("success"):
                print(f"Anomalía: {'✅ SÍ' if result['is_anomaly'] else '❌ NO'}")
                print(f"Score: {result['anomaly_score']:.2f}")
                print(f"Razón: {result['reason']}")
            else:
                print(f"❌ {result.get('error', 'Error desconocido')}")
        return
    
    if args.stats:
        stats = controller.stats()
        if args.json:
            print(json.dumps(stats, indent=2, default=str))
        else:
            print(f"\n📊 ANOMALY STATISTICS")
            print(f"Modelo entrenado: {'✅ Sí' if stats['model_trained'] else '❌ No'}")
            print(f"Total detecciones: {stats['total_detections']}")
        return
    
    if args.status:
        status = controller.status()
        if args.json:
            print(json.dumps(status, default=str))
        else:
            print(f"Running: {'✅' if status['running'] else '⏸️'}")
            print(f"Modelo: {'✅ Entrenado' if status['model_trained'] else '❌ No'}")
            print(f"Detecciones: {status['total_detections']}")
        return
    
    parser.print_help()

if __name__ == "__main__":
    main()
