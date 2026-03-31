use actix_web::{web, App, HttpResponse, HttpServer, Responder, HttpRequest};
use actix_cors::Cors;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::path::PathBuf;
use std::sync::Arc;
use std::net::TcpListener;

use crate::nemesis::Nemesis;
use crate::memory::Memory;
use crate::task_manager::TaskManager;

pub struct AppState {
    pub nemesis: Mutex<Nemesis>,
    pub memory: Mutex<Memory>,
    pub tasks: Arc<TaskManager>,
}

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
    timestamp: String,
}

const API_TOKEN: &str = "ATLANTIS_SECURE_2026";

fn validate_token(req: &HttpRequest) -> bool {
    if let Some(auth_header) = req.headers().get("X-API-Token") {
        if let Ok(token) = auth_header.to_str() {
            return token == API_TOKEN;
        }
    }
    false
}

async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(ApiResponse::<String> {
        success: true,
        data: Some("ATLANTIS-NEXUS API is running".to_string()),
        error: None,
        timestamp: chrono::Local::now().to_rfc3339(),
    })
}

#[derive(Deserialize)]
struct ScanRequest {
    scan_type: String,
    #[allow(dead_code)]
    #[serde(default)]
    file_path: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    dir_path: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    recursive: Option<bool>,
}

#[derive(Deserialize)]
struct AsyncScanRequest {
    scan_type: String,
    #[serde(default)]
    file_path: Option<String>,
    #[serde(default)]
    dir_path: Option<String>,
    #[serde(default)]
    recursive: Option<bool>,
}

#[derive(Deserialize)]
struct ChatRequest {
    question: String,
}

fn get_base_path() -> PathBuf {
    let exe_path = std::env::current_exe()
        .expect("Failed to get executable path");
    let mut base_path = exe_path.parent().expect("Failed to get parent directory").to_path_buf();

    while base_path.ends_with("target") || base_path.ends_with("debug") || base_path.ends_with("release") {
        if let Some(parent) = base_path.parent() {
            base_path = parent.to_path_buf();
        } else {
            break;
        }
    }

    base_path
}

// ============================================================
// IA CEREBRO ENDPOINTS
// ============================================================

async fn ia_ask(
    state: web::Data<AppState>,
    req: web::Json<ChatRequest>,
    http_req: HttpRequest,
) -> impl Responder {
    if !validate_token(&http_req) {
        return HttpResponse::Unauthorized().json(ApiResponse::<String> {
            success: false,
            data: None,
            error: Some("Invalid or missing API token".to_string()),
            timestamp: chrono::Local::now().to_rfc3339(),
        });
    }

    let nemesis = state.nemesis.lock().unwrap();
    
    match nemesis.ia_ask(&req.question) {
        Ok(data) => {
            match serde_json::from_str::<serde_json::Value>(&data) {
                Ok(json_data) => HttpResponse::Ok().json(ApiResponse {
                    success: true,
                    data: Some(json_data),
                    error: None,
                    timestamp: chrono::Local::now().to_rfc3339(),
                }),
                Err(_) => HttpResponse::Ok().json(ApiResponse {
                    success: true,
                    data: Some(data),
                    error: None,
                    timestamp: chrono::Local::now().to_rfc3339(),
                }),
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<String> {
            success: false,
            data: None,
            error: Some(e.to_string()),
            timestamp: chrono::Local::now().to_rfc3339(),
        }),
    }
}

async fn ia_safe_mode_status(
    state: web::Data<AppState>,
    http_req: HttpRequest,
) -> impl Responder {
    if !validate_token(&http_req) {
        return HttpResponse::Unauthorized().json(ApiResponse::<String> {
            success: false,
            data: None,
            error: Some("Invalid or missing API token".to_string()),
            timestamp: chrono::Local::now().to_rfc3339(),
        });
    }

    let nemesis = state.nemesis.lock().unwrap();
    
    match nemesis.ia_safe_mode_status() {
        Ok(data) => HttpResponse::Ok().json(ApiResponse {
            success: true,
            data: Some(data),
            error: None,
            timestamp: chrono::Local::now().to_rfc3339(),
        }),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<String> {
            success: false,
            data: None,
            error: Some(e.to_string()),
            timestamp: chrono::Local::now().to_rfc3339(),
        }),
    }
}

async fn ia_toggle_safe_mode(
    state: web::Data<AppState>,
    http_req: HttpRequest,
) -> impl Responder {
    if !validate_token(&http_req) {
        return HttpResponse::Unauthorized().json(ApiResponse::<String> {
            success: false,
            data: None,
            error: Some("Invalid or missing API token".to_string()),
            timestamp: chrono::Local::now().to_rfc3339(),
        });
    }

    let nemesis = state.nemesis.lock().unwrap();
    
    match nemesis.ia_toggle_safe_mode() {
        Ok(data) => HttpResponse::Ok().json(ApiResponse {
            success: true,
            data: Some(data),
            error: None,
            timestamp: chrono::Local::now().to_rfc3339(),
        }),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<String> {
            success: false,
            data: None,
            error: Some(e.to_string()),
            timestamp: chrono::Local::now().to_rfc3339(),
        }),
    }
}

// ============================================================
// TAREAS ASÍNCRONAS
// ============================================================

async fn run_scan_async(
    state: web::Data<AppState>,
    req: web::Json<AsyncScanRequest>,
    http_req: HttpRequest,
) -> impl Responder {
    if !validate_token(&http_req) {
        return HttpResponse::Unauthorized().json(ApiResponse::<String> {
            success: false,
            data: None,
            error: Some("Invalid or missing API token".to_string()),
            timestamp: chrono::Local::now().to_rfc3339(),
        });
    }

    let scan_type = req.scan_type.clone();
    let file_path = req.file_path.clone();
    let dir_path = req.dir_path.clone();
    let recursive = req.recursive.unwrap_or(false);

    let task_id = match state.tasks.create_task(&scan_type) {
        Ok(id) => id,
        Err(e) => {
            return HttpResponse::TooManyRequests().json(ApiResponse::<String> {
                success: false,
                data: None,
                error: Some(format!("Task queue full: {}", e)),
                timestamp: chrono::Local::now().to_rfc3339(),
            });
        }
    };

    let task_id_clone = task_id.clone();
    let nemesis = state.nemesis.lock().unwrap().clone();
    let tasks = state.tasks.clone();

    tokio::spawn(async move {
        tasks.start_task(&task_id_clone);

        let result = match scan_type.as_str() {
            "vigia" => nemesis.scan_network(None),
            "radar_devices" => nemesis.get_radar("--devices", None),
            "radar_alerts" => nemesis.get_radar("--alerts", None),
            "radar_status" => nemesis.get_radar("--status", None),
            "arp_quick" => nemesis.detect_arp(false, Some(10), true),
            "honeypot_stats" => nemesis.honeypot_stats(),
            "honeypot_start" => nemesis.start_honeypot(),
            "honeypot_stop" => nemesis.stop_honeypot(),
            "defender_stats" => nemesis.defender_stats(),
            "blocked_ips" => nemesis.list_blocked(),
            "zombie_scan_file" => {
                if let Some(path) = file_path {
                    nemesis.zombie_scan_file(&path)
                } else {
                    Err("Missing file_path parameter".into())
                }
            }
            "zombie_scan_dir" => {
                if let Some(path) = dir_path {
                    nemesis.zombie_scan_dir(&path, recursive)
                } else {
                    Err("Missing dir_path parameter".into())
                }
            }
            "zombie_stats" => nemesis.zombie_stats(),
            "zombie_status" => nemesis.zombie_status(),
            "zombie_start_watcher" => nemesis.zombie_start_watcher(),
            "zombie_start_daemon" => nemesis.zombie_start_daemon(),
            "zombie_stop_watcher" => nemesis.zombie_stop_watcher(),
            "anomaly_train" => nemesis.anomaly_train(),
            "anomaly_stats" => nemesis.anomaly_stats(),
            "anomaly_status" => nemesis.anomaly_status(),
            "traffic_analyzer_start" => nemesis.traffic_analyzer_start(),
            "traffic_analyzer_stop" => nemesis.traffic_analyzer_stop(),
            "advanced_honeypot_start" => nemesis.advanced_honeypot_start(8081, 21, 445),
            "advanced_honeypot_stop" => nemesis.advanced_honeypot_stop(),
            "threat_intel_update" => nemesis.threat_intel_update(),
            "threat_intel_stats" => nemesis.threat_intel_stats(),
            "threat_intel_status" => nemesis.threat_intel_status(),
            _ => Err("Invalid scan type".into()),
        };

        match result {
            Ok(data) => tasks.complete_task(&task_id_clone, data),
            Err(e) => tasks.fail_task(&task_id_clone, e.to_string()),
        }
    });

    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(serde_json::json!({
            "task_id": task_id,
            "status": "pending"
        })),
        error: None,
        timestamp: chrono::Local::now().to_rfc3339(),
    })
}

async fn get_task_status(
    state: web::Data<AppState>,
    path: web::Path<String>,
    http_req: HttpRequest,
) -> impl Responder {
    if !validate_token(&http_req) {
        return HttpResponse::Unauthorized().json(ApiResponse::<String> {
            success: false,
            data: None,
            error: Some("Invalid or missing API token".to_string()),
            timestamp: chrono::Local::now().to_rfc3339(),
        });
    }

    let task_id = path.into_inner();
    if let Some(task) = state.tasks.get_task(&task_id) {
        HttpResponse::Ok().json(ApiResponse {
            success: true,
            data: Some(serde_json::json!({
                "id": task.id,
                "task_type": task.task_type,
                "status": task.status,
                "result": task.result,
                "error": task.error,
                "created_at": task.created_at,
                "started_at": task.started_at,
                "completed_at": task.completed_at
            })),
            error: None,
            timestamp: chrono::Local::now().to_rfc3339(),
        })
    } else {
        HttpResponse::NotFound().json(ApiResponse::<String> {
            success: false,
            data: None,
            error: Some("Task not found".to_string()),
            timestamp: chrono::Local::now().to_rfc3339(),
        })
    }
}

async fn list_tasks(
    state: web::Data<AppState>,
    http_req: HttpRequest,
) -> impl Responder {
    if !validate_token(&http_req) {
        return HttpResponse::Unauthorized().json(ApiResponse::<String> {
            success: false,
            data: None,
            error: Some("Invalid or missing API token".to_string()),
            timestamp: chrono::Local::now().to_rfc3339(),
        });
    }

    let tasks = state.tasks.get_all_tasks();
    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(tasks),
        error: None,
        timestamp: chrono::Local::now().to_rfc3339(),
    })
}

// ============================================================
// ENDPOINTS SINCRÓNICOS
// ============================================================

async fn run_scan_sync(
    state: web::Data<AppState>,
    req: web::Json<ScanRequest>,
    http_req: HttpRequest,
) -> impl Responder {
    if !validate_token(&http_req) {
        return HttpResponse::Unauthorized().json(ApiResponse::<String> {
            success: false,
            data: None,
            error: Some("Invalid or missing API token".to_string()),
            timestamp: chrono::Local::now().to_rfc3339(),
        });
    }

    let nemesis = state.nemesis.lock().unwrap();

    let result = match req.scan_type.as_str() {
        "blocked_ips" => nemesis.list_blocked(),
        "zombie_stats" => nemesis.zombie_stats(),
        "zombie_status" => nemesis.zombie_status(),
        "anomaly_stats" => nemesis.anomaly_stats(),
        "anomaly_status" => nemesis.anomaly_status(),
        "advanced_honeypot_stats" => nemesis.advanced_honeypot_stats(),
        "advanced_honeypot_status" => nemesis.advanced_honeypot_status(),
        "traffic_analyzer_stats" => nemesis.traffic_analyzer_stats(),
        "traffic_analyzer_anomalies" => nemesis.traffic_analyzer_anomalies(),
        "traffic_analyzer_status" => nemesis.traffic_analyzer_status(),
        "threat_intel_stats" => nemesis.threat_intel_stats(),
        "threat_intel_status" => nemesis.threat_intel_status(),
        "ia_safe_mode_status" => nemesis.ia_safe_mode_status(),
        "vigia" => {
            let mut memory = state.memory.lock().unwrap();
            nemesis.scan_network(Some(&mut memory))
        }
        "radar_devices" => {
            let mut memory = state.memory.lock().unwrap();
            nemesis.get_radar("--devices", Some(&mut memory))
        }
        "radar_alerts" => nemesis.get_radar("--alerts", None),
        "radar_status" => nemesis.get_radar("--status", None),
        "arp_quick" => nemesis.detect_arp(false, Some(10), true),
        "honeypot_attacks" => {
            // ... resto igual
            let base_path = get_base_path();
            let attacks_file = base_path.join("data/venom_logs/attacks.jsonl");
            let mut attacks = Vec::new();
            if attacks_file.exists() {
                match std::fs::read_to_string(&attacks_file) {
                    Ok(content) => {
                        for line in content.lines() {
                            if let Ok(attack) = serde_json::from_str::<serde_json::Value>(line) {
                                attacks.push(attack);
                            }
                        }
                    }
                    Err(e) => {
                        return HttpResponse::InternalServerError().json(ApiResponse::<String> {
                            success: false,
                            data: None,
                            error: Some(format!("Failed to read attacks file: {}", e)),
                            timestamp: chrono::Local::now().to_rfc3339(),
                        });
                    }
                }
            }
            if attacks.len() > 50 {
                attacks = attacks[attacks.len()-50..].to_vec();
            }
            match serde_json::to_string(&attacks) {
                Ok(json) => Ok(json),
                Err(e) => {
                    return HttpResponse::InternalServerError().json(ApiResponse::<String> {
                        success: false,
                        data: None,
                        error: Some(format!("Failed to serialize attacks: {}", e)),
                        timestamp: chrono::Local::now().to_rfc3339(),
                    });
                }
            }
        }
        "honeypot_status" => {
            let base_path = get_base_path();
            let status_file = base_path.join("data/honeypot_status.json");
            if status_file.exists() {
                match std::fs::read_to_string(&status_file) {
                    Ok(content) => Ok(content),
                    Err(e) => {
                        return HttpResponse::InternalServerError().json(ApiResponse::<String> {
                            success: false,
                            data: None,
                            error: Some(format!("Failed to read status file: {}", e)),
                            timestamp: chrono::Local::now().to_rfc3339(),
                        });
                    }
                }
            } else {
                Ok("{\"running\": false, \"total_connections\": 0, \"ports\": []}".to_string())
            }
        }
        "advanced_honeypot_start" => {
            nemesis.advanced_honeypot_start(8081, 21, 445)
        }
        "advanced_honeypot_stop" => {
            nemesis.advanced_honeypot_stop()
        }
        "traffic_analyzer_start" => {
            nemesis.traffic_analyzer_start()
        }
        "traffic_analyzer_stop" => {
            nemesis.traffic_analyzer_stop()
        }
        "threat_intel_update" => {
            nemesis.threat_intel_update()
        }
        "ia_toggle_safe_mode" => {
            nemesis.ia_toggle_safe_mode()
        }
        _ => Err("Operation not supported in sync mode".into()),
    };

    match result {
        Ok(data) => HttpResponse::Ok().json(ApiResponse {
            success: true,
            data: Some(data),
            error: None,
            timestamp: chrono::Local::now().to_rfc3339(),
        }),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<String> {
            success: false,
            data: None,
            error: Some(e.to_string()),
            timestamp: chrono::Local::now().to_rfc3339(),
        }),
    }
}

// ============================================================
// ENDPOINTS DE MEMORIA Y DEFENSA
// ============================================================

#[derive(Deserialize)]
struct SearchRequest {
    query: String,
}

async fn search_devices(
    state: web::Data<AppState>,
    req: web::Json<SearchRequest>,
    http_req: HttpRequest,
) -> impl Responder {
    if !validate_token(&http_req) {
        return HttpResponse::Unauthorized().json(ApiResponse::<String> {
            success: false,
            data: None,
            error: Some("Invalid or missing API token".to_string()),
            timestamp: chrono::Local::now().to_rfc3339(),
        });
    }

    let memory = state.memory.lock().unwrap();
    let results = memory.search_devices(&req.query);
    let devices: Vec<_> = results.into_iter().cloned().collect();

    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(devices),
        error: None,
        timestamp: chrono::Local::now().to_rfc3339(),
    })
}

#[derive(Deserialize)]
struct HistoryRequest {
    ip: String,
}

async fn device_history(
    state: web::Data<AppState>,
    req: web::Json<HistoryRequest>,
    http_req: HttpRequest,
) -> impl Responder {
    if !validate_token(&http_req) {
        return HttpResponse::Unauthorized().json(ApiResponse::<String> {
            success: false,
            data: None,
            error: Some("Invalid or missing API token".to_string()),
            timestamp: chrono::Local::now().to_rfc3339(),
        });
    }

    let memory = state.memory.lock().unwrap();
    let history = memory.device_history(&req.ip);
    let events: Vec<_> = history.into_iter().cloned().collect();

    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(events),
        error: None,
        timestamp: chrono::Local::now().to_rfc3339(),
    })
}

async fn recent_events(
    state: web::Data<AppState>,
    http_req: HttpRequest,
) -> impl Responder {
    if !validate_token(&http_req) {
        return HttpResponse::Unauthorized().json(ApiResponse::<String> {
            success: false,
            data: None,
            error: Some("Invalid or missing API token".to_string()),
            timestamp: chrono::Local::now().to_rfc3339(),
        });
    }

    let memory = state.memory.lock().unwrap();
    let events = memory.recent_events(50);
    let events: Vec<_> = events.into_iter().cloned().collect();

    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(events),
        error: None,
        timestamp: chrono::Local::now().to_rfc3339(),
    })
}

async fn memory_stats(
    state: web::Data<AppState>,
    http_req: HttpRequest,
) -> impl Responder {
    if !validate_token(&http_req) {
        return HttpResponse::Unauthorized().json(ApiResponse::<String> {
            success: false,
            data: None,
            error: Some("Invalid or missing API token".to_string()),
            timestamp: chrono::Local::now().to_rfc3339(),
        });
    }

    let memory = state.memory.lock().unwrap();
    let stats = memory.get_stats();

    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(stats),
        error: None,
        timestamp: chrono::Local::now().to_rfc3339(),
    })
}

#[derive(Deserialize)]
struct IpRequest {
    ip: String,
}

async fn block_ip(
    state: web::Data<AppState>,
    req: web::Json<IpRequest>,
    http_req: HttpRequest,
) -> impl Responder {
    if !validate_token(&http_req) {
        return HttpResponse::Unauthorized().json(ApiResponse::<String> {
            success: false,
            data: None,
            error: Some("Invalid or missing API token".to_string()),
            timestamp: chrono::Local::now().to_rfc3339(),
        });
    }

    let nemesis = state.nemesis.lock().unwrap();

    match nemesis.block_ip(&req.ip) {
        Ok(data) => HttpResponse::Ok().json(ApiResponse {
            success: true,
            data: Some(data),
            error: None,
            timestamp: chrono::Local::now().to_rfc3339(),
        }),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<String> {
            success: false,
            data: None,
            error: Some(e.to_string()),
            timestamp: chrono::Local::now().to_rfc3339(),
        }),
    }
}

async fn unblock_ip(
    state: web::Data<AppState>,
    req: web::Json<IpRequest>,
    http_req: HttpRequest,
) -> impl Responder {
    if !validate_token(&http_req) {
        return HttpResponse::Unauthorized().json(ApiResponse::<String> {
            success: false,
            data: None,
            error: Some("Invalid or missing API token".to_string()),
            timestamp: chrono::Local::now().to_rfc3339(),
        });
    }

    let nemesis = state.nemesis.lock().unwrap();

    match nemesis.unblock_ip(&req.ip) {
        Ok(data) => HttpResponse::Ok().json(ApiResponse {
            success: true,
            data: Some(data),
            error: None,
            timestamp: chrono::Local::now().to_rfc3339(),
        }),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<String> {
            success: false,
            data: None,
            error: Some(e.to_string()),
            timestamp: chrono::Local::now().to_rfc3339(),
        }),
    }
}

// ============================================================
// SERVER
// ============================================================

pub async fn run_server() -> std::io::Result<()> {
    // Verificar puerto - SOLO VERIFICAR, NO MATAR
    println!("🔍 Checking port 8080...");
    
    match TcpListener::bind(("127.0.0.1", 8080)) {
        Ok(_) => {
            println!("✅ Port 8080 is free.");
        }
        Err(_) => {
            eprintln!("\n╔════════════════════════════════════════════════════════════════╗");
            eprintln!("║  ❌ ERROR: Port 8080 is already in use!                         ║");
            eprintln!("╠════════════════════════════════════════════════════════════════╣");
            eprintln!("║  This means another Atlantis instance or another program      ║");
            eprintln!("║  is using port 8080.                                          ║");
            eprintln!("╠════════════════════════════════════════════════════════════════╣");
            eprintln!("║  To fix this, run these commands:                             ║");
            eprintln!("║                                                                ║");
            eprintln!("║    sudo pkill -9 -f atlantis-core                             ║");
            eprintln!("║    sudo pkill -9 -f python3                                   ║");
            eprintln!("║    sudo rm -f ~/atlantis-core/data/*.pid                      ║");
            eprintln!("║                                                                ║");
            eprintln!("║  Then run 'cargo run' again.                                  ║");
            eprintln!("╚════════════════════════════════════════════════════════════════╝\n");
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "Port 8080 is already in use. Please free it manually and restart."
            ));
        }
    }

    let base_path = get_base_path();
    let data_dir = base_path.join("data");
    let memory_dir = data_dir.join("memory");

    std::fs::create_dir_all(&data_dir)?;
    std::fs::create_dir_all(&memory_dir)?;

    let state = web::Data::new(AppState {
        nemesis: Mutex::new(Nemesis::new()),
        memory: Mutex::new(Memory::new(&memory_dir)),
        tasks: Arc::new(TaskManager::new(100)),
    });

    let tasks_clone = state.tasks.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
            tasks_clone.cleanup_old_tasks(3600);
        }
    });

    println!("🌐 Starting EL OJO 2.0 API server at http://localhost:8080");
    println!("🔑 API Token: X-API-Token: ATLANTIS_SECURE_2026");

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header();

        App::new()
            .wrap(cors)
            .app_data(state.clone())
            .route("/health", web::get().to(health_check))
            .route("/api/scan", web::post().to(run_scan_sync))
            .route("/api/scan/async", web::post().to(run_scan_async))
            .route("/api/task/{id}", web::get().to(get_task_status))
            .route("/api/tasks", web::get().to(list_tasks))
            .route("/api/search", web::post().to(search_devices))
            .route("/api/history", web::post().to(device_history))
            .route("/api/events", web::get().to(recent_events))
            .route("/api/memory/stats", web::get().to(memory_stats))
            .route("/api/defender/block", web::post().to(block_ip))
            .route("/api/defender/unblock", web::post().to(unblock_ip))
            .route("/api/ia/ask", web::post().to(ia_ask))
            .route("/api/ia/safe-mode", web::get().to(ia_safe_mode_status))
            .route("/api/ia/toggle-safe-mode", web::post().to(ia_toggle_safe_mode))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
