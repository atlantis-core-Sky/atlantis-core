use std::error::Error;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use std::fs;
use std::collections::HashMap;

use crate::crypto::{encrypt, decrypt};
use crate::nemesis::Nemesis;

/// Representa un dispositivo en la red
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub ip: String,
    pub mac: String,
    pub vendor: String,
    pub hostname: String,
    pub first_seen: String,
    pub last_seen: String,
    pub appearances: u32,
    pub tags: Vec<String>,
    pub notes: String,
}

/// Representa un evento de seguridad
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub timestamp: String,
    pub device_ip: String,
    pub event_type: String,
    pub description: String,
    pub severity: String,
    pub resolved: bool,
}

/// Memory module - stores and retrieves devices and events with encryption
pub struct Memory {
    memory_dir: PathBuf,
    devices: HashMap<String, Device>,
    events: Vec<SecurityEvent>,
}

impl Memory {
    /// Create a new Memory instance
    pub fn new(memory_dir: &Path) -> Self {
        let mut memory = Self {
            memory_dir: memory_dir.to_path_buf(),
            devices: HashMap::new(),
            events: Vec::new(),
        };

        memory.load_devices();
        memory.load_events();

        memory
    }

    /// Helper: detecta si una línea está encriptada o es JSON plano
    fn is_encrypted(line: &str) -> bool {
        if line.trim_start().starts_with('{') {
            return false;
        }
        line.len() > 20 && line.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    }

    /// Helper: desencripta una línea si está encriptada
    fn decrypt_line(&self, line: &str) -> Result<String, Box<dyn Error>> {
        if Self::is_encrypted(line) {
            match decrypt(line) {
                Ok(decrypted) => Ok(decrypted),
                Err(e) => {
                    eprintln!("⚠️ Failed to decrypt event: {}", e);
                    Err(e)
                }
            }
        } else {
            Ok(line.to_string())
        }
    }

    /// Helper: encripta una línea
    fn encrypt_line(&self, plaintext: &str) -> Result<String, Box<dyn Error>> {
        encrypt(plaintext)
    }

    /// Load devices from file
    fn load_devices(&mut self) {
        let devices_file = self.memory_dir.join("memory_devices.json");

        if devices_file.exists() {
            match fs::read_to_string(&devices_file) {
                Ok(content) => {
                    for line in content.lines() {
                        let line = line.trim();
                        if line.is_empty() {
                            continue;
                        }

                        match self.decrypt_line(line) {
                            Ok(decrypted) => {
                                if let Ok(device) = serde_json::from_str::<Device>(&decrypted) {
                                    self.devices.insert(device.ip.clone(), device);
                                }
                            }
                            Err(_) => continue,
                        }
                    }
                    println!("📂 Loaded {} devices from memory", self.devices.len());
                }
                Err(e) => eprintln!("⚠️ Failed to read devices file: {}", e),
            }
        }
    }

    /// Load events from file and from module logs
    fn load_events(&mut self) {
        let events_file = self.memory_dir.join("memory_events.json");

        // 1. Cargar eventos guardados previamente (si existen)
        if events_file.exists() {
            match fs::read_to_string(&events_file) {
                Ok(content) => {
                    for line in content.lines() {
                        let line = line.trim();
                        if line.is_empty() {
                            continue;
                        }

                        match self.decrypt_line(line) {
                            Ok(decrypted) => {
                                if let Ok(event) = serde_json::from_str::<SecurityEvent>(&decrypted) {
                                    self.events.push(event);
                                }
                            }
                            Err(_) => continue,
                        }
                    }
                    println!("📂 Loaded {} events from memory", self.events.len());
                }
                Err(e) => eprintln!("⚠️ Failed to read events file: {}", e),
            }
        }

        // 2. Cargar eventos desde los logs de los módulos (solo si no están ya cargados)
        let data_dir = self.memory_dir.parent().unwrap();

        // Helper para procesar archivos JSONL
        fn parse_jsonl<P: AsRef<Path>>(path: P, mut f: impl FnMut(serde_json::Value) -> Option<SecurityEvent>) -> Vec<SecurityEvent> {
            let mut events = Vec::new();
            if let Ok(content) = fs::read_to_string(path) {
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                        if let Some(event) = f(json) {
                            events.push(event);
                        }
                    }
                }
            }
            events
        }

        // 2.1 HTTP honeypot attacks
        let http_log = data_dir.join("advanced_honeypot_logs/http_attacks.jsonl");
        let http_events = parse_jsonl(http_log, |json| {
            let ip = json.get("ip").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
            let timestamp = json.get("timestamp").and_then(|v| v.as_str()).unwrap_or(&chrono::Local::now().to_rfc3339()).to_string();
            let path = json.get("path").and_then(|v| v.as_str()).unwrap_or("unknown");
            let description = format!("HTTP request to {} from {}", path, ip);
            Some(SecurityEvent {
                timestamp,
                device_ip: ip,
                event_type: "HTTP Honeypot Attack".to_string(),
                description,
                severity: "medium".to_string(),
                resolved: false,
            })
        });

        // 2.2 FTP honeypot attacks
        let ftp_log = data_dir.join("advanced_honeypot_logs/ftp_attacks.jsonl");
        let ftp_events = parse_jsonl(ftp_log, |json| {
            let ip = json.get("ip").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
            let timestamp = json.get("timestamp").and_then(|v| v.as_str()).unwrap_or(&chrono::Local::now().to_rfc3339()).to_string();
            let user = json.get("username").and_then(|v| v.as_str()).unwrap_or("?");
            let _pass = json.get("password").and_then(|v| v.as_str()).unwrap_or("?");  // variable no usada intencionalmente
            let description = format!("FTP login attempt from {} with user '{}'", ip, user);
            Some(SecurityEvent {
                timestamp,
                device_ip: ip,
                event_type: "FTP Honeypot Attack".to_string(),
                description,
                severity: "medium".to_string(),
                resolved: false,
            })
        });

        // 2.3 SMB honeypot attacks
        let smb_log = data_dir.join("advanced_honeypot_logs/smb_attacks.jsonl");
        let smb_events = parse_jsonl(smb_log, |json| {
            let ip = json.get("ip").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
            let timestamp = json.get("timestamp").and_then(|v| v.as_str()).unwrap_or(&chrono::Local::now().to_rfc3339()).to_string();
            let description = format!("SMB connection attempt from {}", ip);
            Some(SecurityEvent {
                timestamp,
                device_ip: ip,
                event_type: "SMB Honeypot Attack".to_string(),
                description,
                severity: "medium".to_string(),
                resolved: false,
            })
        });

        // 2.4 SSH honeypot attacks (venom_logs/attacks.jsonl)
        let ssh_log = data_dir.join("venom_logs/attacks.jsonl");
        let ssh_events = parse_jsonl(ssh_log, |json| {
            let ip = json.get("ip").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
            let timestamp = json.get("timestamp").and_then(|v| v.as_str()).unwrap_or(&chrono::Local::now().to_rfc3339()).to_string();
            let user = json.get("username").and_then(|v| v.as_str()).unwrap_or("?");
            let _pass = json.get("password").and_then(|v| v.as_str()).unwrap_or("?");  // variable no usada intencionalmente
            let description = format!("SSH login attempt from {} with user '{}'", ip, user);
            Some(SecurityEvent {
                timestamp,
                device_ip: ip,
                event_type: "SSH Honeypot Attack".to_string(),
                description,
                severity: "medium".to_string(),
                resolved: false,
            })
        });

        // 2.5 ARP alerts
        let arp_alerts = data_dir.join("defensa/alertas_arp.json");
        let arp_events = parse_jsonl(arp_alerts, |json| {
            let ip = json.get("ip").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
            let timestamp = json.get("timestamp").and_then(|v| v.as_str()).unwrap_or(&chrono::Local::now().to_rfc3339()).to_string();
            let description = json.get("description").and_then(|v| v.as_str()).unwrap_or("ARP spoofing detected").to_string();
            Some(SecurityEvent {
                timestamp,
                device_ip: ip,
                event_type: "ARP Spoofing Alert".to_string(),
                description,
                severity: "high".to_string(),
                resolved: false,
            })
        });

        // 2.6 Malware detections (zombie)
        let zombie_log = data_dir.join("zombie_logs/detections.jsonl");
        let zombie_events = parse_jsonl(zombie_log, |json| {
            let file = json.get("file").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
            let timestamp = json.get("timestamp").and_then(|v| v.as_str()).unwrap_or(&chrono::Local::now().to_rfc3339()).to_string();
            let reason = json.get("reason").and_then(|v| v.as_str()).unwrap_or("unknown");
            let description = format!("Malware detected in {}: {}", file, reason);
            Some(SecurityEvent {
                timestamp,
                device_ip: "localhost".to_string(),
                event_type: "Malware Detection".to_string(),
                description,
                severity: "high".to_string(),
                resolved: false,
            })
        });

        // 2.7 Traffic anomalies
        let traffic_log = data_dir.join("traffic_logs/anomalies.jsonl");
        let traffic_events = parse_jsonl(traffic_log, |json| {
            let ip = json.get("ip").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
            let timestamp = json.get("timestamp").and_then(|v| v.as_str()).unwrap_or(&chrono::Local::now().to_rfc3339()).to_string();
            let reasons = json.get("reasons").and_then(|v| v.as_array()).map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default();
            let description = format!("Traffic anomaly from {}: {}", ip, reasons);
            let severity = json.get("severity").and_then(|v| v.as_str()).unwrap_or("medium").to_string();
            Some(SecurityEvent {
                timestamp,
                device_ip: ip,
                event_type: "Traffic Anomaly".to_string(),
                description,
                severity,
                resolved: false,
            })
        });

        // 2.8 ML anomalies (anomaly_data/detections.jsonl)
        let ml_log = data_dir.join("anomaly_data/detections.jsonl");
        let ml_events = parse_jsonl(ml_log, |json| {
            let ip = json.get("device_ip").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
            let timestamp = json.get("timestamp").and_then(|v| v.as_str()).unwrap_or(&chrono::Local::now().to_rfc3339()).to_string();
            let score = json.get("anomaly_score").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let description = format!("ML anomaly detected (score: {:.2})", score);
            Some(SecurityEvent {
                timestamp,
                device_ip: ip,
                event_type: "ML Anomaly".to_string(),
                description,
                severity: if score > 0.8 { "high".to_string() } else { "medium".to_string() },
                resolved: false,
            })
        });

        // Recopilar todos los eventos
        let all_new_events: Vec<SecurityEvent> = http_events
            .into_iter()
            .chain(ftp_events)
            .chain(smb_events)
            .chain(ssh_events)
            .chain(arp_events)
            .chain(zombie_events)
            .chain(traffic_events)
            .chain(ml_events)
            .collect();

        // Añadir a self.events
        self.events.extend(all_new_events);

        // Ordenar por timestamp descendente (más reciente primero)
        self.events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Mantener solo los últimos 1000 eventos
        if self.events.len() > 1000 {
            self.events = self.events[0..1000].to_vec();
        }

        println!("📂 Total events loaded: {}", self.events.len());
    }

    /// Save devices to file (private, solo para uso interno)
    #[allow(dead_code)]
    fn save_devices_internal(&self) -> Result<(), Box<dyn Error>> {
        let devices_file = self.memory_dir.join("memory_devices.json");
        let mut content = String::new();

        for device in self.devices.values() {
            let json = serde_json::to_string(device)?;
            let encrypted = self.encrypt_line(&json)?;
            content.push_str(&encrypted);
            content.push('\n');
        }

        fs::write(devices_file, content)?;
        Ok(())
    }

    /// Save events to file (private, solo para uso interno)
    #[allow(dead_code)]
    fn save_events_internal(&self) -> Result<(), Box<dyn Error>> {
        let events_file = self.memory_dir.join("memory_events.json");
        let mut content = String::new();

        for event in &self.events {
            let json = serde_json::to_string(event)?;
            let encrypted = self.encrypt_line(&json)?;
            content.push_str(&encrypted);
            content.push('\n');
        }

        fs::write(events_file, content)?;
        Ok(())
    }

    /// Store a device in memory
    pub fn store_device(&mut self, device: Device) -> Result<(), Box<dyn Error>> {
        let ip = device.ip.clone();

        if let Some(existing) = self.devices.get_mut(&ip) {
            existing.last_seen = device.last_seen;
            existing.appearances += 1;
            if device.hostname != "Unknown" && existing.hostname == "Unknown" {
                existing.hostname = device.hostname;
            }
            if device.vendor != "Desconocido" && existing.vendor == "Desconocido" {
                existing.vendor = device.vendor;
            }
        } else {
            self.devices.insert(ip, device);
        }

        self.save_devices_internal()?;
        Ok(())
    }

    /// Store a security event with automatic ML analysis
    #[allow(dead_code)]
    pub fn store_event(&mut self, event: SecurityEvent) -> Result<(), Box<dyn Error>> {
        // Guardar evento primero
        self.events.push(event.clone());

        // Mantener solo últimos 1000
        if self.events.len() > 1000 {
            self.events = self.events.split_off(self.events.len() - 1000);
        }

        self.save_events_internal()?;

        // ============================================================
        // ANÁLISIS AUTOMÁTICO CON ML
        // ============================================================
        let event_json = match serde_json::to_string(&event) {
            Ok(json) => json,
            Err(e) => {
                eprintln!("⚠️ Error serializando evento para ML: {}", e);
                return Ok(());
            }
        };

        // Crear instancia de Nemesis y analizar
        let nemesis = Nemesis::new();

        match nemesis.anomaly_analyze(&event_json) {
            Ok(result) => {
                if let Ok(analysis) = serde_json::from_str::<serde_json::Value>(&result) {
                    if analysis["is_anomaly"] == true {
                        let score = analysis["anomaly_score"].as_f64().unwrap_or(0.0);
                        let reason = analysis["reason"].as_str().unwrap_or("Desconocida");
                        println!("🚨 ANOMALÍA DETECTADA!");
                        println!("   Score: {:.2}", score);
                        println!("   Razón: {}", reason);
                        println!("   Evento: {} | {} | {}",
                            event.event_type,
                            event.device_ip,
                            event.description);
                        println!("   ────────────────────────────────────");
                    }
                }
            }
            Err(e) => {
                if cfg!(debug_assertions) {
                    eprintln!("⚠️ ML analysis failed: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Search devices by IP, MAC, vendor, or hostname
    pub fn search_devices(&self, query: &str) -> Vec<&Device> {
        let query_lower = query.to_lowercase();

        self.devices
            .values()
            .filter(|d| {
                d.ip.contains(&query_lower)
                    || d.mac.to_lowercase().contains(&query_lower)
                    || d.vendor.to_lowercase().contains(&query_lower)
                    || d.hostname.to_lowercase().contains(&query_lower)
            })
            .collect()
    }

    /// Get device history (events for a specific IP)
    pub fn device_history(&self, ip: &str) -> Vec<&SecurityEvent> {
        self.events
            .iter()
            .filter(|e| e.device_ip == ip)
            .collect()
    }

    /// Get recent events
    pub fn recent_events(&self, limit: usize) -> Vec<&SecurityEvent> {
        let start = if self.events.len() > limit {
            self.events.len() - limit
        } else {
            0
        };

        self.events[start..].iter().collect()
    }

    /// Get statistics
    pub fn get_stats(&self) -> serde_json::Value {
        let mut event_counts = HashMap::new();
        for event in &self.events {
            *event_counts.entry(event.event_type.clone()).or_insert(0) += 1;
        }

        serde_json::json!({
            "total_devices": self.devices.len(),
            "total_events": self.events.len(),
            "event_counts": event_counts
        })
    }
}
