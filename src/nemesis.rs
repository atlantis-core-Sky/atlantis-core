use std::process::Command;
use std::error::Error;
use serde::Deserialize;
use crate::memory::{Memory, Device};

/// NEMESIS Defense Module - Executes security scripts
#[derive(Clone)]
pub struct Nemesis {
    script_path: String,
}

#[derive(Debug, Deserialize)]
struct ScanResult {
    timestamp: String,
    network: String,
    devices: Vec<DeviceInfo>,
    total: usize,
}

#[derive(Debug, Deserialize)]
struct DeviceInfo {
    ip: String,
    mac: String,
    vendor: String,
    hostname: String,
    status: String,
    last_seen: String,
}

impl Nemesis {
    /// Create a new NEMESIS instance with automatic path detection
    pub fn new() -> Self {
        let exe_path = std::env::current_exe().expect("Failed to get executable path");
        let mut base_path = exe_path.parent().expect("Failed to get parent directory").to_path_buf();

        while base_path.ends_with("target") || base_path.ends_with("debug") || base_path.ends_with("release") {
            if let Some(parent) = base_path.parent() {
                base_path = parent.to_path_buf();
            } else {
                break;
            }
        }

        let script_path = base_path.join("scripts/defensa/");
        let _ = std::fs::create_dir_all(&script_path);

        println!("📁 Scripts path: {}", script_path.display());

        Self {
            script_path: script_path.to_string_lossy().to_string(),
        }
    }

    /// Detect Python path automatically
    fn get_python_path(&self) -> String {
        // 1. Try to use the active virtual environment
        if let Ok(venv) = std::env::var("VIRTUAL_ENV") {
            return format!("{}/bin/python3", venv);
        }
        // 2. Otherwise, use python3 from PATH
        "python3".to_string()
    }

    /// Helper: execute a command and return stdout
    fn run_python_script(&self, script: &str, args: &[&str]) -> Result<String, Box<dyn Error>> {
        let current_dir = std::env::current_dir()?;
        std::env::set_current_dir(&self.script_path)?;

        let output = Command::new("sudo")
            .arg(self.get_python_path())
            .arg(script)
            .args(args)
            .output()?;

        std::env::set_current_dir(current_dir)?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr).to_string();
            Err(format!("{} failed: {}", script, error_msg).into())
        }
    }

    /// Helper: spawn a command in the background (does not wait)
    fn spawn_python_script(&self, script: &str, args: &[&str]) -> Result<(), Box<dyn Error>> {
        let current_dir = std::env::current_dir()?;
        std::env::set_current_dir(&self.script_path)?;

        Command::new("sudo")
            .arg(self.get_python_path())
            .arg(script)
            .args(args)
            .spawn()?;

        std::env::set_current_dir(current_dir)?;
        Ok(())
    }

    // ============================================================
    // VIGÍA - NETWORK SCAN
    // ============================================================

    pub fn scan_network(&self, memory: Option<&mut Memory>) -> Result<String, Box<dyn Error>> {
        println!("🔍 NEMESIS: Scanning network...");
        let output = self.run_python_script("vigia_red.py", &["--json"])?;

        if let Ok(result) = serde_json::from_str::<ScanResult>(&output) {
            if let Some(mem) = memory {
                println!("💾 Saving {} devices to memory...", result.devices.len());
                for d in &result.devices {
                    let device = Device {
                        ip: d.ip.clone(),
                        mac: d.mac.clone(),
                        vendor: d.vendor.clone(),
                        hostname: d.hostname.clone(),
                        first_seen: chrono::Local::now().to_rfc3339(),
                        last_seen: chrono::Local::now().to_rfc3339(),
                        appearances: 1,
                        tags: Vec::new(),
                        notes: String::new(),
                    };
                    let _ = mem.store_device(device);
                }
                println!("✅ Devices saved to memory");
            }

            let mut formatted = format!("\n📡 SCAN RESULTS ({} devices found):\n", result.total);
            formatted.push_str("────────────────────────────────────\n");
            formatted.push_str(&format!("🕒 Time: {}\n", result.timestamp));
            formatted.push_str(&format!("🌐 Network: {}\n", result.network));
            formatted.push_str("────────────────────────────────────\n");

            for d in result.devices {
                formatted.push_str(&format!(
                    "  • IP: {:<15} | MAC: {:<17} | {}\n",
                    d.ip, d.mac, d.vendor
                ));
                if d.hostname != "Unknown" {
                    formatted.push_str(&format!("    📛 Hostname: {}\n", d.hostname));
                }
                if d.status != "up" {
                    formatted.push_str(&format!("    ⚠️  Status: {}\n", d.status));
                }
                let seen: Vec<&str> = d.last_seen.split('T').collect();
                if seen.len() > 1 {
                    formatted.push_str(&format!("    ⏱️  Last seen: {}\n", seen[0]));
                }
            }
            Ok(formatted)
        } else {
            Ok(format!("Raw output:\n{}", output))
        }
    }

    // ============================================================
    // RADAR - PASSIVE MONITORING
    // ============================================================

    pub fn get_radar(&self, command: &str, memory: Option<&mut Memory>) -> Result<String, Box<dyn Error>> {
        println!("📡 NEMESIS: Querying radar...");
        let output = self.run_python_script("radar.py", &[command, "--json"])?;

        if command == "--devices" {
            if let Ok(devices) = serde_json::from_str::<Vec<serde_json::Value>>(&output) {
                if let Some(mem) = memory {
                    for device_val in devices {
                        if let (Some(ip), Some(mac), Some(vendor), Some(first), Some(last)) = (
                            device_val.get("ip").and_then(|v| v.as_str()),
                            device_val.get("mac").and_then(|v| v.as_str()),
                            device_val.get("vendor").and_then(|v| v.as_str()),
                            device_val.get("first_seen").and_then(|v| v.as_str()),
                            device_val.get("last_seen").and_then(|v| v.as_str()),
                        ) {
                            let device = Device {
                                ip: ip.to_string(),
                                mac: mac.to_string(),
                                vendor: vendor.to_string(),
                                hostname: device_val.get("hostname").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string(),
                                first_seen: first.to_string(),
                                last_seen: last.to_string(),
                                appearances: device_val.get("appearances").and_then(|v| v.as_u64()).unwrap_or(1) as u32,
                                tags: Vec::new(),
                                notes: String::new(),
                            };
                            let _ = mem.store_device(device);
                        }
                    }
                }
            }
        }

        match serde_json::from_str::<serde_json::Value>(&output) {
            Ok(json_val) => Ok(serde_json::to_string_pretty(&json_val)?),
            Err(_) => Ok(output)
        }
    }

    // ============================================================
    // ARP DETECTIVE
    // ============================================================

    pub fn detect_arp(&self, continuous: bool, timeout: Option<u32>, auto_block: bool) -> Result<String, Box<dyn Error>> {
        println!("🕵️ NEMESIS: Running ARP spoofing detection...");

        let actual_timeout = timeout.unwrap_or(10);
        let mut args: Vec<String> = Vec::new();

        if continuous {
            args.push("--continuous".to_string());
        } else {
            args.push("--oneshot".to_string());
        }

        args.push("--timeout".to_string());
        args.push(actual_timeout.to_string());

        if !auto_block {
            args.push("--no-auto-block".to_string());
        }

        args.push("--json".to_string());

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        self.run_python_script("detective_arp.py", &args_refs)
    }

    // ============================================================
    // SSH HONEYPOT
    // ============================================================

    pub fn honeypot_stats(&self) -> Result<String, Box<dyn Error>> {
        println!("📊 NEMESIS: Getting honeypot statistics...");
        self.run_python_script("honeypot_ssh_final.py", &["--stats", "--json"])
    }

    pub fn start_honeypot(&self) -> Result<String, Box<dyn Error>> {
        println!("🍯 NEMESIS: Starting SSH Honeypot daemon...");
        self.spawn_python_script("honeypot_ssh_final.py", &["--start", "--ports", "2222,2223,2224", "--json"])?;
        Ok("{\"success\": true, \"message\": \"Honeypot starting in background\"}".to_string())
    }

    pub fn stop_honeypot(&self) -> Result<String, Box<dyn Error>> {
        println!("🍯 NEMESIS: Stopping SSH Honeypot...");
        self.run_python_script("honeypot_ssh_final.py", &["--stop", "--json"])
    }

    // ============================================================
    // ADVANCED HONEYPOTS (HTTP, FTP, SMB)
    // ============================================================

    pub fn advanced_honeypot_start(&self, http_port: u16, ftp_port: u16, smb_port: u16) -> Result<String, Box<dyn Error>> {
        println!("🍯 NEMESIS: Starting advanced honeypots...");

        let current_dir = std::env::current_dir()?;
        std::env::set_current_dir(&self.script_path)?;

        let _child = Command::new("sudo")
            .arg(self.get_python_path())
            .arg("honeypot_advanced.py")
            .arg("--start")
            .arg("--http-port")
            .arg(http_port.to_string())
            .arg("--ftp-port")
            .arg(ftp_port.to_string())
            .arg("--smb-port")
            .arg(smb_port.to_string())
            .arg("--json")
            .spawn()?;

        std::env::set_current_dir(current_dir)?;

        Ok("{\"success\": true, \"message\": \"Advanced honeypots starting in background\"}".to_string())
    }

    pub fn advanced_honeypot_stop(&self) -> Result<String, Box<dyn Error>> {
        println!("🍯 NEMESIS: Stopping advanced honeypots...");

        let current_dir = std::env::current_dir()?;
        std::env::set_current_dir(&self.script_path)?;

        let output = Command::new("sudo")
            .arg(self.get_python_path())
            .arg("honeypot_advanced.py")
            .arg("--stop")
            .arg("--json")
            .output()?;

        std::env::set_current_dir(current_dir)?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            Ok(stdout)
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr).to_string();
            Err(format!("Advanced honeypots stop failed: {}", error_msg).into())
        }
    }

    pub fn advanced_honeypot_stats(&self) -> Result<String, Box<dyn Error>> {
        println!("📊 NEMESIS: Getting advanced honeypot statistics...");

        let current_dir = std::env::current_dir()?;
        std::env::set_current_dir(&self.script_path)?;

        let output = Command::new("sudo")
            .arg(self.get_python_path())
            .arg("honeypot_advanced.py")
            .arg("--stats")
            .arg("--json")
            .output()?;

        std::env::set_current_dir(current_dir)?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            Ok(stdout)
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr).to_string();
            Err(format!("Advanced honeypot stats failed: {}", error_msg).into())
        }
    }

    pub fn advanced_honeypot_status(&self) -> Result<String, Box<dyn Error>> {
        println!("🍯 NEMESIS: Getting advanced honeypot status...");

        let current_dir = std::env::current_dir()?;
        std::env::set_current_dir(&self.script_path)?;

        let output = Command::new("sudo")
            .arg(self.get_python_path())
            .arg("honeypot_advanced.py")
            .arg("--status")
            .arg("--json")
            .output()?;

        std::env::set_current_dir(current_dir)?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            Ok(stdout)
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr).to_string();
            Err(format!("Advanced honeypot status failed: {}", error_msg).into())
        }
    }

    // ============================================================
    // TRAFFIC ANALYZER
    // ============================================================

    pub fn traffic_analyzer_start(&self) -> Result<String, Box<dyn Error>> {
        println!("📡 NEMESIS: Starting traffic analyzer...");

        let current_dir = std::env::current_dir()?;
        std::env::set_current_dir(&self.script_path)?;

        let _child = Command::new("sudo")
            .arg(self.get_python_path())
            .arg("traffic_analyzer.py")
            .arg("--start")
            .arg("--json")
            .spawn()?;

        std::env::set_current_dir(current_dir)?;

        Ok("{\"success\": true, \"message\": \"Traffic analyzer starting in background\"}".to_string())
    }

    pub fn traffic_analyzer_stop(&self) -> Result<String, Box<dyn Error>> {
        println!("📡 NEMESIS: Stopping traffic analyzer...");

        let current_dir = std::env::current_dir()?;
        std::env::set_current_dir(&self.script_path)?;

        let output = Command::new("sudo")
            .arg(self.get_python_path())
            .arg("traffic_analyzer.py")
            .arg("--stop")
            .arg("--json")
            .output()?;

        std::env::set_current_dir(current_dir)?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            Ok(stdout)
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr).to_string();
            Err(format!("Traffic analyzer stop failed: {}", error_msg).into())
        }
    }

    pub fn traffic_analyzer_stats(&self) -> Result<String, Box<dyn Error>> {
        println!("📊 NEMESIS: Getting traffic analyzer statistics...");

        let current_dir = std::env::current_dir()?;
        std::env::set_current_dir(&self.script_path)?;

        let output = Command::new("sudo")
            .arg(self.get_python_path())
            .arg("traffic_analyzer.py")
            .arg("--stats")
            .arg("--json")
            .output()?;

        std::env::set_current_dir(current_dir)?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            Ok(stdout)
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr).to_string();
            Err(format!("Traffic analyzer stats failed: {}", error_msg).into())
        }
    }

    pub fn traffic_analyzer_status(&self) -> Result<String, Box<dyn Error>> {
        println!("📡 NEMESIS: Getting traffic analyzer status...");

        let current_dir = std::env::current_dir()?;
        std::env::set_current_dir(&self.script_path)?;

        let output = Command::new("sudo")
            .arg(self.get_python_path())
            .arg("traffic_analyzer.py")
            .arg("--status")
            .arg("--json")
            .output()?;

        std::env::set_current_dir(current_dir)?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            Ok(stdout)
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr).to_string();
            Err(format!("Traffic analyzer status failed: {}", error_msg).into())
        }
    }

    pub fn traffic_analyzer_anomalies(&self) -> Result<String, Box<dyn Error>> {
        println!("🚨 NEMESIS: Getting traffic anomalies...");

        let current_dir = std::env::current_dir()?;
        std::env::set_current_dir(&self.script_path)?;

        let output = Command::new("sudo")
            .arg(self.get_python_path())
            .arg("traffic_analyzer.py")
            .arg("--anomalies")
            .arg("--json")
            .output()?;

        std::env::set_current_dir(current_dir)?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            Ok(stdout)
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr).to_string();
            Err(format!("Traffic anomalies failed: {}", error_msg).into())
        }
    }

    // ============================================================
    // DEFENDER (FIREWALL)
    // ============================================================

    pub fn block_ip(&self, ip: &str) -> Result<String, Box<dyn Error>> {
        println!("🛑 NEMESIS: Blocking IP {}...", ip);
        self.run_python_script("el_defensor.py", &["--block", ip, "--json"])
    }

    pub fn unblock_ip(&self, ip: &str) -> Result<String, Box<dyn Error>> {
        println!("🔄 NEMESIS: Unblocking IP {}...", ip);
        self.run_python_script("el_defensor.py", &["--unblock", ip, "--json"])
    }

    pub fn list_blocked(&self) -> Result<String, Box<dyn Error>> {
        println!("📋 NEMESIS: Listing blocked IPs...");
        self.run_python_script("el_defensor.py", &["--list", "--json"])
    }

    pub fn defender_stats(&self) -> Result<String, Box<dyn Error>> {
        println!("📊 NEMESIS: Getting defender statistics...");
        self.run_python_script("el_defensor.py", &["--stats", "--json"])
    }

    pub fn auto_defend(&self) -> Result<String, Box<dyn Error>> {
        println!("🤖 NEMESIS: Starting automatic defense mode...");
        self.run_python_script("el_defensor.py", &["--auto", "--json"])
    }

    // ============================================================
    // ZOMBIE MODULE (FIXED: sleep after spawn)
    // ============================================================

    pub fn zombie_scan_file(&self, file_path: &str) -> Result<String, Box<dyn Error>> {
        println!("🧟 NEMESIS: Scanning file with Zombie module...");
        self.run_python_script("zombie.py", &["--scan", file_path, "--json"])
    }

    pub fn zombie_scan_dir(&self, dir_path: &str, recursive: bool) -> Result<String, Box<dyn Error>> {
        println!("🧟 NEMESIS: Scanning directory with Zombie module...");
        if recursive {
            self.run_python_script("zombie.py", &["--scan", dir_path, "--recursive", "--json"])
        } else {
            self.run_python_script("zombie.py", &["--scan", dir_path, "--json"])
        }
    }

    pub fn zombie_stats(&self) -> Result<String, Box<dyn Error>> {
        println!("📊 NEMESIS: Getting Zombie statistics...");
        self.run_python_script("zombie.py", &["--stats", "--json"])
    }

    pub fn zombie_status(&self) -> Result<String, Box<dyn Error>> {
        println!("🧟 NEMESIS: Getting Zombie status...");
        self.run_python_script("zombie.py", &["--status", "--json"])
    }

    pub fn zombie_start_watcher(&self) -> Result<String, Box<dyn Error>> {
        println!("🧟 NEMESIS: Starting Zombie watcher...");
        self.spawn_python_script("zombie.py", &["--watch"])?;
        std::thread::sleep(std::time::Duration::from_secs(1));
        Ok("{\"success\": true, \"message\": \"Zombie watcher starting in background\"}".to_string())
    }

    pub fn zombie_start_daemon(&self) -> Result<String, Box<dyn Error>> {
        println!("🧟 NEMESIS: Starting Zombie daemon...");
        self.spawn_python_script("zombie.py", &["--daemon"])?;
        std::thread::sleep(std::time::Duration::from_secs(1));
        Ok("{\"success\": true, \"message\": \"Zombie daemon starting in background\"}".to_string())
    }

    pub fn zombie_stop_watcher(&self) -> Result<String, Box<dyn Error>> {
        println!("🧟 NEMESIS: Stopping Zombie watcher...");
        self.run_python_script("zombie.py", &["--stop"])
    }

    // ============================================================
    // ML ANOMALY DETECTION
    // ============================================================

    pub fn anomaly_train(&self) -> Result<String, Box<dyn Error>> {
        println!("🧠 NEMESIS: Training anomaly detection model...");
        self.run_python_script("anomaly.py", &["--train", "--json"])
    }

    pub fn anomaly_analyze(&self, event_json: &str) -> Result<String, Box<dyn Error>> {
        println!("🧠 NEMESIS: Analyzing event for anomalies...");
        self.run_python_script("anomaly.py", &["--analyze", event_json, "--json"])
    }

    pub fn anomaly_stats(&self) -> Result<String, Box<dyn Error>> {
        println!("📊 NEMESIS: Getting anomaly detection statistics...");
        self.run_python_script("anomaly.py", &["--stats", "--json"])
    }

    pub fn anomaly_status(&self) -> Result<String, Box<dyn Error>> {
        println!("🧠 NEMESIS: Getting anomaly detection status...");
        self.run_python_script("anomaly.py", &["--status", "--json"])
    }

    // ============================================================
    // THREAT INTELLIGENCE
    // ============================================================

    pub fn threat_intel_update(&self) -> Result<String, Box<dyn Error>> {
        println!("🛡️ NEMESIS: Updating threat intelligence feeds...");
        self.run_python_script("threat_intel.py", &["--update", "--json"])
    }

    pub fn threat_intel_check(&self, ip: &str) -> Result<String, Box<dyn Error>> {
        println!("🔍 NEMESIS: Checking IP {} against threat intel...", ip);
        self.run_python_script("threat_intel.py", &["--check", ip, "--json"])
    }

    pub fn threat_intel_block(&self, ip: &str) -> Result<String, Box<dyn Error>> {
        println!("🚫 NEMESIS: Blocking IP {} via threat intel...", ip);
        self.run_python_script("threat_intel.py", &["--block", ip, "--json"])
    }

    pub fn threat_intel_stats(&self) -> Result<String, Box<dyn Error>> {
        println!("📊 NEMESIS: Getting threat intelligence statistics...");
        self.run_python_script("threat_intel.py", &["--stats", "--json"])
    }

    pub fn threat_intel_status(&self) -> Result<String, Box<dyn Error>> {
        println!("🛡️ NEMESIS: Getting threat intelligence status...");
        self.run_python_script("threat_intel.py", &["--status", "--json"])
    }

    // ============================================================
    // IA CEREBRO
    // ============================================================

    pub fn ia_ask(&self, question: &str) -> Result<String, Box<dyn Error>> {
        println!("🧠 NEMESIS: Asking IA Cerebro...");

        let escaped_question = question.replace('"', "\\\"");

        self.run_python_script("ia_cerebro.py", &["--ask", &escaped_question, "--json"])
    }

    pub fn ia_safe_mode_status(&self) -> Result<String, Box<dyn Error>> {
        println!("🧠 NEMESIS: Getting IA safe mode status...");

        let exe_path = std::env::current_exe()?;
        let base_path = exe_path.parent().unwrap();

        let mut root = base_path.to_path_buf();
        while root.ends_with("target") || root.ends_with("debug") || root.ends_with("release") {
            root = root.parent().unwrap().to_path_buf();
        }

        let safe_mode_file = root.join("data/ia_safe_mode");
        let safe_mode = safe_mode_file.exists();

        Ok(format!("{{\"safe_mode\": {}}}", safe_mode))
    }

    pub fn ia_toggle_safe_mode(&self) -> Result<String, Box<dyn Error>> {
        println!("🧠 NEMESIS: Toggling IA safe mode...");

        let exe_path = std::env::current_exe()?;
        let base_path = exe_path.parent().unwrap();

        let mut root = base_path.to_path_buf();
        while root.ends_with("target") || root.ends_with("debug") || root.ends_with("release") {
            root = root.parent().unwrap().to_path_buf();
        }

        let safe_mode_file = root.join("data/ia_safe_mode");

        let new_state = if safe_mode_file.exists() {
            std::fs::remove_file(&safe_mode_file)?;
            false
        } else {
            std::fs::File::create(&safe_mode_file)?;
            true
        };

        Ok(format!("{{\"safe_mode\": {}, \"message\": \"Safe mode {}\"}}",
            new_state,
            if new_state { "enabled" } else { "disabled" }))
    }
}
