# Atlantis-NEXUS – Technical Details

## System Requirements

- **Operating System**: Linux or WSL (Windows Subsystem for Linux).  
- **Python**: 3.8 or later.  
- **Rust**: 1.70 or later (installed automatically if missing).  
- **System tools**: `nmap`, `tcpdump`, `arp-scan`, `iptables` (installed by the installer).  
- **Ollama** (optional, for AI features).  

### Hardware Recommendations

- **Minimal** (without AI): 1 GB RAM, 1 CPU core, 2 GB disk.  
- **Typical** (with AI and honeypots): 4 GB RAM, 2 CPU cores, 4 GB disk.  
- **Recommended** (with large AI models): 8 GB RAM, 4 CPU cores, 10 GB disk.

## Performance & Resource Usage

| Component         | Idle (no AI) | Active (AI) | Notes |
|-------------------|--------------|-------------|-------|
| Rust backend      | ~50 MB RAM   | ~50 MB      | Always running. |
| Python scripts    | ~50 MB RAM   | ~100 MB     | Scripts run on demand or as daemons. |
| Ollama + model    | –            | ~2–3 GB RAM | Only when AI is used. |
| Disk (code)       | ~1.5 GB      | ~1.5 GB     | Includes Rust target and Python scripts. |
| Disk (data)       | ~10 MB       | grows over time | Logs, threat DB, ML model. |

- **CPU**: Idle < 5%; active scans or analysis may spike to 20–40% temporarily.  
- **Network**: Minimal background traffic; honeypots open ports 8081, 21, 445, 2222–2224.

## Module Details

| Module | Description | Dependencies | Optional? |
|--------|-------------|--------------|-----------|
| Vigía | Active network scan (nmap) | `nmap` | No |
| Radar | Passive ARP monitoring | `arp-scan` | No |
| ARP Detective | Spoofing detection & auto‑block | `scapy` | No |
| Defender | Firewall management (iptables/netsh) | – | No |
| SSH Honeypot | Simulates SSH on ports 2222‑2224 | `paramiko` | No |
| Advanced Honeypots | HTTP (8081), FTP (21), SMB (445) | `pyftpdlib`, `impacket` | Yes (FTP/SMB require libs) |
| Zombie | Malware detection (scripts, images, documents) | `Pillow`, `numpy` | No |
| ML Anomaly | Isolation Forest for zero‑day detection | `numpy`, `scikit-learn` | No |
| Traffic Analyzer | Exfiltration & C2 detection | `psutil`, `scapy` | No |
| Threat Intelligence | Malicious IP feeds | `requests`, `sqlite3` | No |
| IA Cerebro | Local assistant with Ollama | `requests`, Ollama | Yes (AI works without Ollama, but chat fails) |
| Memory | Encrypted storage (AES‑256‑GCM) | Rust crate | No |

## Limitations & Caveats

- **OS**: Only Linux and WSL are supported. Windows native is not supported.  
- **Root privileges**: Many modules require `sudo` (nmap, iptables, packet capture). Without sudo, those modules will not work.  
- **Optional dependencies**: FTP and SMB honeypots require additional Python libraries; if they are not installed, those honeypots are disabled (the rest still work).  
- **AI**: Requires Ollama to be installed and running. If Ollama is not present, the chat interface will show an error.  
- **Threat Intelligence**: The database is pre‑populated with ~1300 IPs; it can be updated manually via `threat_intel.py --update`. Automatic updates are not scheduled.  
- **Event storage**: Events are loaded from module logs on startup; they are not persisted in `memory_events.json`. This avoids duplication.  
- **Scalability**: Not designed for large enterprise networks (hundreds of devices). It works best for home, small office, or lab environments.

## Ethical Use Statement

Atlantis‑NEXUS is designed exclusively for defensive purposes: protecting your own network, detecting intrusions, and understanding security threats. The creators do not condone or support any illegal, offensive, or unethical use of this software. Users are solely responsible for complying with all applicable laws and for any consequences arising from their use of the software.

## Customization

- **API Token**: Change `API_TOKEN` in `src/api.rs` and recompile.  
- **Threat Intelligence feeds**: Edit `threat_intel.py` to add new sources.  
- **Honeypot ports**: Modify the `advanced_honeypot_start` calls in `main.rs` (the default uses HTTP:8081, FTP:21, SMB:445).  
- **AI model**: The IA Cerebro automatically picks the best available uncensored model (dolphin‑phi, hermes3, etc.). You can force a model by editing `DEFAULT_MODEL` in `ia_cerebro.py`.

## Troubleshooting

- **Port 8080 already in use**: Kill the process using that port (see the error message for commands) and restart.  
- **Zombie watcher not stopping**: Check that the PID file exists (`data/zombie.pid`) and that the process is running. If not, run `sudo pkill -f zombie.py` and remove the PID file manually.  
- **AI not responding**: Ensure Ollama is running (`ollama serve`) and that at least one model is downloaded (`ollama pull dolphin-phi`).  
- **Modules need sudo**: If you prefer to run without sudo, you can modify the scripts to run as root, but this is not recommended.

## Support & Contributing

Issues and pull requests are welcome. Please include detailed logs and describe your environment.

---

*Last updated: March 2026*
