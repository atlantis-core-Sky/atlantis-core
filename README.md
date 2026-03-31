# 🛡️ ATLANTIS-NEXUS
### The only 100% local, AI-powered cybersecurity suite

Atlantis-NEXUS is an autonomous defense platform that runs entirely on your machine.  
No cloud, no subscriptions, no data leaving your network.

---

## 📖 What is Atlantis-NEXUS?

Atlantis-NEXUS is a modular cybersecurity system that combines:

- **Active & passive network monitoring** (Vigía, Radar)
- **ARP spoofing detection & automatic blocking**
- **Firewall management** (iptables / netsh) with manual and automatic IP blocking
- **Multi‑protocol honeypots**: SSH, HTTP, FTP, SMB
- **Malware detection** (Zombie) for scripts, documents, and images
- **Machine Learning anomaly detection** (Isolation Forest) for zero‑day threats
- **Traffic analysis** to detect data exfiltration and C2 communication
- **Threat intelligence** with 1300+ malicious IP feeds
- **Uncensored local AI** (Safe mode for free security chat, Active mode for answering with your data)
- **Encrypted memory** (AES‑256‑GCM) for storing devices and events
- **Modern web dashboard** (React) for real‑time control

All components run **100% locally**. No telemetry, no external servers, no subscriptions.

---

## ⚙️ How it works

- **Rust backend** (`cargo run`) orchestrates Python defense scripts, handles API requests, and manages tasks.
- **Python modules** (in `scripts/defensa/`) perform low‑level operations: network scanning, honeypots, malware detection, etc.
- **Frontend** (React) communicates via REST API secured with a static token.
- **Data** is stored encrypted in `data/` (devices, events, logs). The encryption key is embedded in the Rust binary.
- **AI** uses Ollama locally (models like `dolphin-phi` recommended). It can be disabled if not needed.

---

## 🚀 Installation

### Requirements
- **Linux** or **WSL** (Windows Subsystem for Linux)
- **Python 3.8+** (with `pip` and `venv`)
- **Rust 1.70+** (will be installed automatically if missing)
- **npm** (for frontend)
- **Ollama** (optional – for AI features)

### Quick install
```bash
git clone https://github.com/your-alias/atlantis-core.git
cd atlantis-core
chmod +x install.sh
./install.sh
