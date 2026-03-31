use std::collections::HashMap;
use std::error::Error;
use serde::Deserialize;

mod nemesis;
mod memory;
mod api;
mod crypto;
mod task_manager;

use nemesis::Nemesis;
use memory::Memory;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("🛡️ ATLANTIS-NEXUS CORE v2.0.0 - COMPLETE DEFENSE SUITE + WEB INTERFACE");
    println!("=========================================================================");

    // Check Ollama connection
    match check_ollama().await {
        Ok(version) => println!("✅ Ollama daemon: v{} (running)", version),
        Err(e) => {
            println!("❌ Ollama not reachable: {}", e);
            return Ok(());
        }
    }

    // Get available models
    let models = match fetch_models().await {
        Ok(models) => models,
        Err(e) => {
            println!("❌ Failed to fetch models: {}", e);
            return Ok(());
        }
    };

    println!("\n📦 Available models: {} found", models.len());

    // Show largest model
    if let Some(largest) = models.iter().max_by_key(|m| m.size.unwrap_or(0)) {
        let size_gb = largest.size.unwrap_or(0) as f64 / 1_073_741_824.0;
        println!("📊 Largest model: {} ({:.2} GB)", largest.name, size_gb);
    }

    // Show most recent model
    if let Some(newest) = models.iter()
        .filter(|m| m.modified_at.is_some())
        .max_by_key(|m| &m.modified_at)
    {
        println!("🆕 Most recent: {} ({})", newest.name, newest.modified_at.as_ref().unwrap());
    }

    // Initialize Model Router with dynamic model detection
    let mut router = ModelRouter::new();
    router.load_models(models);

    // Test router with different tasks
    println!("\n🧠 Model Router Recommendations:");
    println!("--------------------------------");

    let test_tasks = vec![
        ("chat", TaskType::Chat),
        ("security scan", TaskType::Security),
        ("deep research", TaskType::Research),
        ("execute NEMESIS", TaskType::Execution),
        ("complex reasoning", TaskType::Reasoning),
        ("uncensored query", TaskType::Uncensored),
    ];

    for (description, task) in test_tasks {
        let recommended = router.recommend(task);
        println!("🔹 {:<20} → {}", description, recommended);
    }

    // Initialize Memory module with relative paths
    let exe_path = std::env::current_exe()?;
    let mut base_path = exe_path.parent().ok_or("Failed to get parent directory")?.to_path_buf();

    while base_path.ends_with("target") || base_path.ends_with("debug") || base_path.ends_with("release") {
        if let Some(parent) = base_path.parent() {
            base_path = parent.to_path_buf();
        } else {
            break;
        }
    }

    let data_dir = base_path.join("data");
    let memory_dir = data_dir.join("memory");

    std::fs::create_dir_all(&data_dir)?;
    std::fs::create_dir_all(&memory_dir)?;

    println!("📁 Data directory: {}", data_dir.display());
    println!("📁 Memory directory: {}", memory_dir.display());

    let mut memory = Memory::new(&memory_dir);

    println!("\n🛡️ NEMESIS Defense Module:");
    println!("------------------------");

    let nemesis = Nemesis::new();

    println!("\n🌐 Do you want to start the web interface (EL OJO 2.0)? (y/n)");
    let mut web_choice = String::new();
    std::io::stdin().read_line(&mut web_choice)?;

    if web_choice.trim().eq_ignore_ascii_case("y") {
        println!("\n🚀 Starting web server in foreground...");

        // ============================================================
        // INICIAR HONEYPOTS AVANZADOS AUTOMÁTICAMENTE
        // ============================================================
        println!("🍯 Starting advanced honeypots...");
        if let Err(e) = nemesis.advanced_honeypot_start(8081, 21, 445) {
            eprintln!("⚠️ Failed to start advanced honeypots: {}", e);
        } else {
            println!("✅ Advanced honeypots started (HTTP:8081, FTP:21, SMB:445)");
        }

        // ============================================================
        // INICIAR TRAFFIC ANALYZER AUTOMÁTICAMENTE
        // ============================================================
        println!("📡 Starting traffic analyzer...");
        if let Err(e) = nemesis.traffic_analyzer_start() {
            eprintln!("⚠️ Failed to start traffic analyzer: {}", e);
        } else {
            println!("✅ Traffic analyzer started");
        }

        // ============================================================
        // ACTUALIZAR THREAT INTELLIGENCE AUTOMÁTICAMENTE
        // ============================================================
        println!("🛡️ Updating threat intelligence feeds...");
        if let Err(e) = nemesis.threat_intel_update() {
            eprintln!("⚠️ Failed to update threat intel: {}", e);
        } else {
            println!("✅ Threat intelligence updated");
        }

        // Pequeña pausa para que los daemons inicien completamente
        std::thread::sleep(std::time::Duration::from_secs(1));

        println!("✅ Web interface available at: http://localhost:8080");
        println!("   API endpoints:");
        println!("   • GET  /health");
        println!("   • POST /api/scan (sync - fast operations)");
        println!("   • POST /api/scan/async (async - long operations)");
        println!("   • GET  /api/task/{{id}} (check task status)");
        println!("   • GET  /api/tasks (list all tasks)");
        println!("   • POST /api/search");
        println!("   • POST /api/history");
        println!("   • GET  /api/events");
        println!("   • GET  /api/memory/stats");
        println!("   • POST /api/defender/block");
        println!("   • POST /api/defender/unblock");
        println!("\n📡 Server running. Press Ctrl+C to stop.\n");

        if let Err(e) = api::run_server().await {
            eprintln!("❌ Server error: {}", e);
        }

        // ============================================================
        // DETENER TODO AL SALIR (CUANDO SE CIERRA NORMALMENTE)
        // ============================================================
        println!("🍯 Stopping advanced honeypots...");
        if let Err(e) = nemesis.advanced_honeypot_stop() {
            eprintln!("⚠️ Failed to stop advanced honeypots: {}", e);
        } else {
            println!("✅ Advanced honeypots stopped");
        }

        println!("📡 Stopping traffic analyzer...");
        if let Err(e) = nemesis.traffic_analyzer_stop() {
            eprintln!("⚠️ Failed to stop traffic analyzer: {}", e);
        } else {
            println!("✅ Traffic analyzer stopped");
        }

    } else {
        // ============================================================
        // MENÚ INTERACTIVO (sin web interface)
        // ============================================================
        println!("⏸️ Web interface skipped.");

        loop {
            println!("\n📋 Select NEMESIS action:");
            println!("  1. Network scan (vigía)");
            println!("  2. Radar - List devices (stores in memory)");
            println!("  3. Radar - Show alerts");
            println!("  4. Radar - Status");
            println!("  5. ARP Detective");
            println!("  6. SSH Honeypot");
            println!("  7. Firewall Defender");
            println!("  8. Memory - Search devices");
            println!("  9. Memory - Device history");
            println!(" 10. Memory - Recent events");
            println!(" 11. Memory - Statistics");
            println!(" 12. Zombie Module (Malware Detection)");
            println!(" 13. ML Anomaly Detection");
            println!(" 14. Advanced Honeypots (HTTP, FTP, SMB)");
            println!(" 15. Traffic Analyzer (Network Monitoring)");
            println!(" 16. Threat Intelligence");
            println!("  0. Exit");

            let mut choice = String::new();
            std::io::stdin().read_line(&mut choice)?;

            match choice.trim() {
                "1" => {
                    match nemesis.scan_network(Some(&mut memory)) {
                        Ok(result) => println!("\n📡 Scan Results:\n{}", result),
                        Err(e) => println!("❌ Scan failed: {}", e),
                    }
                }
                "2" => {
                    match nemesis.get_radar("--devices", Some(&mut memory)) {
                        Ok(result) => println!("\n📋 RADAR DEVICES (saved to memory):\n{}", result),
                        Err(e) => println!("❌ Radar error: {}", e),
                    }
                }
                "3" => {
                    match nemesis.get_radar("--alerts", None) {
                        Ok(result) => println!("\n🚨 RADAR ALERTS:\n{}", result),
                        Err(e) => println!("❌ Radar error: {}", e),
                    }
                }
                "4" => {
                    match nemesis.get_radar("--status", None) {
                        Ok(result) => println!("\n📡 RADAR STATUS:\n{}", result),
                        Err(e) => println!("❌ Radar error: {}", e),
                    }
                }
                "5" => {
                    println!("\n🕵️ ARP Detective:");
                    println!("  1. Quick scan (10s timeout)");
                    println!("  2. Continuous monitoring (Ctrl+C to stop)");
                    println!("  3. Custom timeout (seconds)");
                    println!("  0. Back");

                    let mut arp_choice = String::new();
                    std::io::stdin().read_line(&mut arp_choice)?;

                    match arp_choice.trim() {
                        "1" => {
                            match nemesis.detect_arp(false, Some(10), true) {
                                Ok(result) => println!("\n📋 ARP SCAN RESULTS:\n{}", result),
                                Err(e) => println!("❌ ARP Detective error: {}", e),
                            }
                        }
                        "2" => {
                            println!("\n⏳ Continuous ARP monitoring started.");
                            match nemesis.detect_arp(true, None, true) {
                                Ok(result) => println!("\n📋 ARP MONITORING RESULTS:\n{}", result),
                                Err(e) => println!("❌ ARP Detective error: {}", e),
                            }
                        }
                        "3" => {
                            println!("⏱️ Enter timeout in seconds:");
                            let mut timeout_str = String::new();
                            std::io::stdin().read_line(&mut timeout_str)?;
                            if let Ok(timeout) = timeout_str.trim().parse::<u32>() {
                                match nemesis.detect_arp(false, Some(timeout), true) {
                                    Ok(result) => println!("\n📋 ARP SCAN RESULTS ({}s timeout):\n{}", timeout, result),
                                    Err(e) => println!("❌ ARP Detective error: {}", e),
                                }
                            } else {
                                println!("❌ Invalid timeout. Using default 10s.");
                                match nemesis.detect_arp(false, Some(10), true) {
                                    Ok(result) => println!("\n📋 ARP SCAN RESULTS:\n{}", result),
                                    Err(e) => println!("❌ ARP Detective error: {}", e),
                                }
                            }
                        }
                        _ => println!("⏸️ Back to main menu."),
                    }
                }
                "6" => {
                    println!("\n🍯 SSH Honeypot:");
                    println!("  1. Start on default ports (2222,2223,2224)");
                    println!("  2. Show statistics");
                    println!("  3. Stop honeypot");
                    println!("  0. Back");

                    let mut honey_choice = String::new();
                    std::io::stdin().read_line(&mut honey_choice)?;

                    match honey_choice.trim() {
                        "1" => {
                            match nemesis.start_honeypot() {
                                Ok(result) => println!("\n📋 HONEYPOT START RESULT:\n{}", result),
                                Err(e) => println!("❌ Honeypot start error: {}", e),
                            }
                        }
                        "2" => {
                            match nemesis.honeypot_stats() {
                                Ok(result) => println!("\n📊 HONEYPOT STATISTICS:\n{}", result),
                                Err(e) => println!("❌ Honeypot stats error: {}", e),
                            }
                        }
                        "3" => {
                            match nemesis.stop_honeypot() {
                                Ok(result) => println!("\n📋 HONEYPOT STOP RESULT:\n{}", result),
                                Err(e) => println!("❌ Honeypot stop error: {}", e),
                            }
                        }
                        _ => println!("⏸️ Back to main menu."),
                    }
                }
                "7" => {
                    println!("\n🛡️ Firewall Defender:");
                    println!("  1. Block an IP");
                    println!("  2. Unblock an IP");
                    println!("  3. List blocked IPs");
                    println!("  4. Show statistics");
                    println!("  5. Start automatic defense");
                    println!("  0. Back");

                    let mut def_choice = String::new();
                    std::io::stdin().read_line(&mut def_choice)?;

                    match def_choice.trim() {
                        "1" => {
                            println!("🔌 Enter IP to block:");
                            let mut ip = String::new();
                            std::io::stdin().read_line(&mut ip)?;
                            let ip = ip.trim();
                            match nemesis.block_ip(ip) {
                                Ok(result) => println!("\n📋 BLOCK RESULT:\n{}", result),
                                Err(e) => println!("❌ Block error: {}", e),
                            }
                        }
                        "2" => {
                            println!("🔌 Enter IP to unblock:");
                            let mut ip = String::new();
                            std::io::stdin().read_line(&mut ip)?;
                            let ip = ip.trim();
                            match nemesis.unblock_ip(ip) {
                                Ok(result) => println!("\n📋 UNBLOCK RESULT:\n{}", result),
                                Err(e) => println!("❌ Unblock error: {}", e),
                            }
                        }
                        "3" => {
                            match nemesis.list_blocked() {
                                Ok(result) => println!("\n📋 BLOCKED IPS:\n{}", result),
                                Err(e) => println!("❌ List error: {}", e),
                            }
                        }
                        "4" => {
                            match nemesis.defender_stats() {
                                Ok(result) => println!("\n📊 DEFENDER STATISTICS:\n{}", result),
                                Err(e) => println!("❌ Stats error: {}", e),
                            }
                        }
                        "5" => {
                            println!("🤖 Starting automatic defense mode...");
                            match nemesis.auto_defend() {
                                Ok(result) => println!("\n📋 AUTO DEFENSE RESULTS:\n{}", result),
                                Err(e) => println!("❌ Auto defense error: {}", e),
                            }
                        }
                        _ => println!("⏸️ Back to main menu."),
                    }
                }
                "8" => {
                    println!("\n🔍 Enter search query (IP, MAC, vendor, hostname):");
                    let mut query = String::new();
                    std::io::stdin().read_line(&mut query)?;
                    let query = query.trim();
                    let results = memory.search_devices(query);
                    if results.is_empty() {
                        println!("📭 No devices found matching '{}'", query);
                    } else {
                        println!("\n📋 SEARCH RESULTS ({} found):", results.len());
                        println!("────────────────────────────────────");
                        for device in results {
                            println!("  • {} | {} | {}", device.ip, device.mac, device.vendor);
                            println!("    First seen: {} | Last seen: {}",
                                &device.first_seen[..16],
                                &device.last_seen[..16]);
                            println!();
                        }
                    }
                }
                "9" => {
                    println!("\n🔌 Enter IP to see history:");
                    let mut ip = String::new();
                    std::io::stdin().read_line(&mut ip)?;
                    let ip = ip.trim();
                    let history = memory.device_history(ip);
                    if history.is_empty() {
                        println!("📭 No history found for IP: {}", ip);
                    } else {
                        println!("\n📋 DEVICE HISTORY ({} events):", history.len());
                        println!("────────────────────────────────────");
                        for event in history {
                            let status = if event.resolved { "✅" } else { "⏳" };
                            println!("  {} [{}] {} - {}",
                                status,
                                &event.timestamp[..16],
                                event.event_type,
                                event.description);
                        }
                    }
                }
                "10" => {
                    let events = memory.recent_events(20);
                    println!("\n📋 RECENT EVENTS ({}):", events.len());
                    println!("────────────────────────────────────");
                    for event in events {
                        let severity_color = match event.severity.as_str() {
                            "critical" => "🔴",
                            "high" => "🟠",
                            "medium" => "🟡",
                            "low" => "🟢",
                            _ => "⚪",
                        };
                        println!("  {} [{}] {} - {}",
                            severity_color,
                            &event.timestamp[..16],
                            event.device_ip,
                            event.description);
                    }
                }
                "11" => {
                    let stats = memory.get_stats();
                    println!("\n📊 MEMORY STATISTICS:");
                    println!("────────────────────────────────────");
                    println!("{}", serde_json::to_string_pretty(&stats)?);
                }
                "12" => {
                    loop {
                        println!("\n🧟 ZOMBIE MODULE - Malware Detection");
                        println!("  ────────────────────────────────────");
                        println!("  1. Scan file");
                        println!("  2. Scan directory");
                        println!("  3. Show statistics");
                        println!("  4. Start watcher (monitoring)");
                        println!("  5. Start daemon (background)");
                        println!("  6. Stop watcher/daemon");
                        println!("  7. Show watcher status");
                        println!("  0. Back to main menu");

                        let mut zombie_choice = String::new();
                        std::io::stdin().read_line(&mut zombie_choice)?;

                        match zombie_choice.trim() {
                            "1" => {
                                println!("📁 Enter file path to scan:");
                                let mut file_path = String::new();
                                std::io::stdin().read_line(&mut file_path)?;
                                let file_path = file_path.trim();
                                match nemesis.zombie_scan_file(file_path) {
                                    Ok(result) => println!("\n📊 SCAN RESULT:\n{}", result),
                                    Err(e) => println!("❌ Scan failed: {}", e),
                                }
                            }
                            "2" => {
                                println!("📁 Enter directory path to scan:");
                                let mut dir_path = String::new();
                                std::io::stdin().read_line(&mut dir_path)?;
                                let dir_path = dir_path.trim();
                                println!("🔍 Scan recursively? (y/n):");
                                let mut recursive_choice = String::new();
                                std::io::stdin().read_line(&mut recursive_choice)?;
                                let recursive = recursive_choice.trim().eq_ignore_ascii_case("y");
                                match nemesis.zombie_scan_dir(dir_path, recursive) {
                                    Ok(result) => println!("\n📊 SCAN RESULT:\n{}", result),
                                    Err(e) => println!("❌ Scan failed: {}", e),
                                }
                            }
                            "3" => {
                                match nemesis.zombie_stats() {
                                    Ok(result) => println!("\n📊 ZOMBIE STATISTICS:\n{}", result),
                                    Err(e) => println!("❌ Failed to get stats: {}", e),
                                }
                            }
                            "4" => {
                                println!("🧟 Starting Zombie watcher...");
                                match nemesis.zombie_start_watcher() {
                                    Ok(result) => println!("{}", result),
                                    Err(e) => println!("❌ Failed to start watcher: {}", e),
                                }
                            }
                            "5" => {
                                println!("🧟 Starting Zombie daemon...");
                                match nemesis.zombie_start_daemon() {
                                    Ok(result) => println!("{}", result),
                                    Err(e) => println!("❌ Failed to start daemon: {}", e),
                                }
                            }
                            "6" => {
                                println!("🛑 Stopping Zombie watcher/daemon...");
                                match nemesis.zombie_stop_watcher() {
                                    Ok(result) => println!("{}", result),
                                    Err(e) => println!("❌ Failed to stop: {}", e),
                                }
                            }
                            "7" => {
                                match nemesis.zombie_status() {
                                    Ok(result) => println!("\n🧟 ZOMBIE STATUS:\n{}", result),
                                    Err(e) => println!("❌ Failed to get status: {}", e),
                                }
                            }
                            "0" => {
                                println!("⏸️ Back to main menu.");
                                break;
                            }
                            _ => println!("❌ Invalid option. Please choose 0-7."),
                        }
                    }
                }
                "13" => {
                    loop {
                        println!("\n🧠 ML ANOMALY DETECTION");
                        println!("  ────────────────────────────────────");
                        println!("  1. Train model (with existing events)");
                        println!("  2. Analyze event");
                        println!("  3. Show statistics");
                        println!("  4. Show status");
                        println!("  0. Back to main menu");

                        let mut ml_choice = String::new();
                        std::io::stdin().read_line(&mut ml_choice)?;

                        match ml_choice.trim() {
                            "1" => {
                                println!("🧠 Training anomaly detection model...");
                                match nemesis.anomaly_train() {
                                    Ok(result) => println!("\n📊 TRAINING RESULT:\n{}", result),
                                    Err(e) => println!("❌ Training failed: {}", e),
                                }
                            }
                            "2" => {
                                println!("📝 Enter event JSON to analyze:");
                                let mut event_json = String::new();
                                std::io::stdin().read_line(&mut event_json)?;
                                let event_json = event_json.trim();
                                match nemesis.anomaly_analyze(event_json) {
                                    Ok(result) => println!("\n📊 ANALYSIS RESULT:\n{}", result),
                                    Err(e) => println!("❌ Analysis failed: {}", e),
                                }
                            }
                            "3" => {
                                match nemesis.anomaly_stats() {
                                    Ok(result) => println!("\n📊 ANOMALY STATISTICS:\n{}", result),
                                    Err(e) => println!("❌ Failed to get stats: {}", e),
                                }
                            }
                            "4" => {
                                match nemesis.anomaly_status() {
                                    Ok(result) => println!("\n🧠 ANOMALY STATUS:\n{}", result),
                                    Err(e) => println!("❌ Failed to get status: {}", e),
                                }
                            }
                            "0" => {
                                println!("⏸️ Back to main menu.");
                                break;
                            }
                            _ => println!("❌ Invalid option. Please choose 0-4."),
                        }
                    }
                }
                "14" => {
                    loop {
                        println!("\n🍯 ADVANCED HONEYPOTS (HTTP, FTP, SMB)");
                        println!("  ────────────────────────────────────");
                        println!("  1. Start all honeypots");
                        println!("  2. Stop all honeypots");
                        println!("  3. Show statistics");
                        println!("  4. Show status");
                        println!("  0. Back to main menu");

                        let mut honey_advanced_choice = String::new();
                        std::io::stdin().read_line(&mut honey_advanced_choice)?;

                        match honey_advanced_choice.trim() {
                            "1" => {
                                println!("🍯 Starting advanced honeypots...");
                                match nemesis.advanced_honeypot_start(8081, 21, 445) {
                                    Ok(result) => println!("\n📋 START RESULT:\n{}", result),
                                    Err(e) => println!("❌ Failed to start: {}", e),
                                }
                            }
                            "2" => {
                                println!("🍯 Stopping advanced honeypots...");
                                match nemesis.advanced_honeypot_stop() {
                                    Ok(result) => println!("\n📋 STOP RESULT:\n{}", result),
                                    Err(e) => println!("❌ Failed to stop: {}", e),
                                }
                            }
                            "3" => {
                                match nemesis.advanced_honeypot_stats() {
                                    Ok(result) => println!("\n📊 ADVANCED HONEYPOT STATISTICS:\n{}", result),
                                    Err(e) => println!("❌ Failed to get stats: {}", e),
                                }
                            }
                            "4" => {
                                match nemesis.advanced_honeypot_status() {
                                    Ok(result) => println!("\n🍯 ADVANCED HONEYPOT STATUS:\n{}", result),
                                    Err(e) => println!("❌ Failed to get status: {}", e),
                                }
                            }
                            "0" => {
                                println!("⏸️ Back to main menu.");
                                break;
                            }
                            _ => println!("❌ Invalid option. Please choose 0-4."),
                        }
                    }
                }
                "15" => {
                    loop {
                        println!("\n📡 TRAFFIC ANALYZER (Network Monitoring)");
                        println!("  ────────────────────────────────────");
                        println!("  1. Start traffic analyzer");
                        println!("  2. Stop traffic analyzer");
                        println!("  3. Show statistics");
                        println!("  4. Show anomalies");
                        println!("  5. Show status");
                        println!("  0. Back to main menu");

                        let mut traffic_choice = String::new();
                        std::io::stdin().read_line(&mut traffic_choice)?;

                        match traffic_choice.trim() {
                            "1" => {
                                println!("📡 Starting traffic analyzer...");
                                match nemesis.traffic_analyzer_start() {
                                    Ok(result) => println!("\n📋 START RESULT:\n{}", result),
                                    Err(e) => println!("❌ Failed to start: {}", e),
                                }
                            }
                            "2" => {
                                println!("📡 Stopping traffic analyzer...");
                                match nemesis.traffic_analyzer_stop() {
                                    Ok(result) => println!("\n📋 STOP RESULT:\n{}", result),
                                    Err(e) => println!("❌ Failed to stop: {}", e),
                                }
                            }
                            "3" => {
                                match nemesis.traffic_analyzer_stats() {
                                    Ok(result) => println!("\n📊 TRAFFIC ANALYZER STATISTICS:\n{}", result),
                                    Err(e) => println!("❌ Failed to get stats: {}", e),
                                }
                            }
                            "4" => {
                                match nemesis.traffic_analyzer_anomalies() {
                                    Ok(result) => println!("\n🚨 TRAFFIC ANOMALIES:\n{}", result),
                                    Err(e) => println!("❌ Failed to get anomalies: {}", e),
                                }
                            }
                            "5" => {
                                match nemesis.traffic_analyzer_status() {
                                    Ok(result) => println!("\n📡 TRAFFIC ANALYZER STATUS:\n{}", result),
                                    Err(e) => println!("❌ Failed to get status: {}", e),
                                }
                            }
                            "0" => {
                                println!("⏸️ Back to main menu.");
                                break;
                            }
                            _ => println!("❌ Invalid option. Please choose 0-5."),
                        }
                    }
                }
                "16" => {
                    loop {
                        println!("\n🛡️ THREAT INTELLIGENCE");
                        println!("  ────────────────────────────────────");
                        println!("  1. Update threat feeds");
                        println!("  2. Check IP");
                        println!("  3. Block IP");
                        println!("  4. Show statistics");
                        println!("  5. Show status");
                        println!("  0. Back to main menu");

                        let mut threat_choice = String::new();
                        std::io::stdin().read_line(&mut threat_choice)?;

                        match threat_choice.trim() {
                            "1" => {
                                println!("🛡️ Updating threat intelligence feeds...");
                                match nemesis.threat_intel_update() {
                                    Ok(result) => println!("\n📋 UPDATE RESULT:\n{}", result),
                                    Err(e) => println!("❌ Failed to update: {}", e),
                                }
                            }
                            "2" => {
                                println!("🔍 Enter IP to check:");
                                let mut ip = String::new();
                                std::io::stdin().read_line(&mut ip)?;
                                let ip = ip.trim();
                                match nemesis.threat_intel_check(ip) {
                                    Ok(result) => println!("\n📋 CHECK RESULT:\n{}", result),
                                    Err(e) => println!("❌ Failed to check IP: {}", e),
                                }
                            }
                            "3" => {
                                println!("🚫 Enter IP to block:");
                                let mut ip = String::new();
                                std::io::stdin().read_line(&mut ip)?;
                                let ip = ip.trim();
                                match nemesis.threat_intel_block(ip) {
                                    Ok(result) => println!("\n📋 BLOCK RESULT:\n{}", result),
                                    Err(e) => println!("❌ Failed to block IP: {}", e),
                                }
                            }
                            "4" => {
                                match nemesis.threat_intel_stats() {
                                    Ok(result) => println!("\n📊 THREAT INTELLIGENCE STATISTICS:\n{}", result),
                                    Err(e) => println!("❌ Failed to get stats: {}", e),
                                }
                            }
                            "5" => {
                                match nemesis.threat_intel_status() {
                                    Ok(result) => println!("\n🛡️ THREAT INTELLIGENCE STATUS:\n{}", result),
                                    Err(e) => println!("❌ Failed to get status: {}", e),
                                }
                            }
                            "0" => {
                                println!("⏸️ Back to main menu.");
                                break;
                            }
                            _ => println!("❌ Invalid option. Please choose 0-5."),
                        }
                    }
                }
                "0" => {
                    println!("\n👋 Exiting NEMESIS module.");
                    break;
                }
                _ => {
                    println!("❌ Invalid option. Please choose 0-16.");
                }
            }
        }
    }

    Ok(())
}

/// Check Ollama version
async fn check_ollama() -> Result<String, Box<dyn Error>> {
    let client = reqwest::Client::new();
    let response = client
        .get("http://localhost:11434/api/version")
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await?;

    let version_info: serde_json::Value = response.json().await?;
    Ok(version_info["version"].as_str().unwrap_or("unknown").to_string())
}

/// Fetch all models from Ollama
async fn fetch_models() -> Result<Vec<Model>, Box<dyn Error>> {
    let client = reqwest::Client::new();
    let response = client
        .get("http://localhost:11434/api/tags")
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await?;

    let models_response: ModelsResponse = response.json().await?;
    Ok(models_response.models)
}

/// Task types for routing decisions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TaskType {
    Chat,
    Security,
    Research,
    Execution,
    Reasoning,
    Uncensored,
}

/// Model information from Ollama
#[derive(Debug, Deserialize, Clone)]
struct Model {
    name: String,
    modified_at: Option<String>,
    size: Option<u64>,
}

/// API response structure
#[derive(Debug, Deserialize)]
struct ModelsResponse {
    models: Vec<Model>,
}

/// Performance metrics for each model
#[derive(Debug, Clone)]
struct ModelMetrics {
    speed_score: u8,
    quality_score: u8,
    security_score: u8,
    uncensored: bool,
}

/// The Model Router - adapts to available models
struct ModelRouter {
    models: Vec<Model>,
    metrics: HashMap<String, ModelMetrics>,
}

impl ModelRouter {
    fn new() -> Self {
        Self {
            models: Vec::new(),
            metrics: HashMap::new(),
        }
    }

    fn load_models(&mut self, models: Vec<Model>) {
        self.models = models;
        self.initialize_metrics();
    }

    fn initialize_metrics(&mut self) {
        for model in &self.models {
            let metrics = self.analyze_model(&model.name);
            self.metrics.insert(model.name.clone(), metrics);
        }
    }

    fn analyze_model(&self, model_name: &str) -> ModelMetrics {
        let name = model_name.to_lowercase();

        let speed_score = if name.contains("0.5b") || name.contains("0.8b") || name.contains("1.5b") || name.contains("2b") {
            9
        } else if name.contains("3b") || name.contains("4b") {
            7
        } else if name.contains("7b") || name.contains("8b") || name.contains("9b") {
            5
        } else if name.contains("27b") || name.contains("32b") {
            3
        } else {
            5
        };

        let quality_score = if name.contains("27b") || name.contains("32b") {
            10
        } else if name.contains("9b") || name.contains("8b") {
            8
        } else if name.contains("7b") {
            7
        } else if name.contains("4b") || name.contains("3b") {
            6
        } else if name.contains("2b") {
            5
        } else if name.contains("0.8b") || name.contains("0.5b") {
            4
        } else {
            4
        };

        let security_score = if name.contains("atlantis") || name.contains("security") || name.contains("sec") {
            9
        } else {
            3
        };

        let uncensored = name.contains("abliterated") ||
                         name.contains("uncensored") ||
                         name.contains("josefied") ||
                         name.contains("lfm") ||
                         name.contains("wizard") ||
                         name.contains("vicuna");

        ModelMetrics {
            speed_score,
            quality_score,
            security_score,
            uncensored,
        }
    }

    fn recommend(&self, task: TaskType) -> String {
        match task {
            TaskType::Chat => self.recommend_by_speed(),
            TaskType::Security => self.recommend_by_security(),
            TaskType::Research => self.recommend_by_quality(),
            TaskType::Execution => self.recommend_by_speed(),
            TaskType::Reasoning => self.recommend_by_quality(),
            TaskType::Uncensored => self.recommend_uncensored(),
        }
    }

    fn recommend_by_speed(&self) -> String {
        self.models.iter()
            .filter_map(|m| {
                self.metrics.get(&m.name)
                    .map(|metrics| (m, metrics.speed_score))
            })
            .max_by_key(|(_, speed)| *speed)
            .map(|(m, _)| m.name.clone())
            .unwrap_or_else(|| {
                self.models.first().map(|m| m.name.clone()).unwrap_or_else(|| "unknown".to_string())
            })
    }

    fn recommend_by_quality(&self) -> String {
        self.models.iter()
            .filter_map(|m| {
                self.metrics.get(&m.name)
                    .map(|metrics| (m, metrics.quality_score))
            })
            .max_by_key(|(_, quality)| *quality)
            .map(|(m, _)| m.name.clone())
            .unwrap_or_else(|| {
                self.models.first().map(|m| m.name.clone()).unwrap_or_else(|| "unknown".to_string())
            })
    }

    fn recommend_by_security(&self) -> String {
        self.models.iter()
            .filter_map(|m| {
                self.metrics.get(&m.name)
                    .map(|metrics| (m, metrics.security_score))
            })
            .max_by_key(|(_, security)| *security)
            .map(|(m, _)| m.name.clone())
            .unwrap_or_else(|| {
                self.recommend_by_quality()
            })
    }

    fn recommend_uncensored(&self) -> String {
        self.models.iter()
            .filter(|m| {
                self.metrics.get(&m.name)
                    .map(|metrics| metrics.uncensored)
                    .unwrap_or(false)
            })
            .next()
            .map(|m| m.name.clone())
            .unwrap_or_else(|| {
                self.recommend_by_quality()
            })
    }
}
