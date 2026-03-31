#!/bin/bash
# Atlantis-NEXUS Installer v1.0
set -e
echo "🛡️  ATLANTIS-NEXUS INSTALLER"
echo "============================="

if [[ "$OSTYPE" == "linux-gnu"* ]] || grep -q Microsoft /proc/version 2>/dev/null; then
    echo "✅ Linux/WSL detected"
    INSTALL_CMD="sudo apt-get update && sudo apt-get install -y"
else
    echo "❌ Unsupported OS. Only Linux/WSL is supported."
    exit 1
fi

echo "📦 Installing system dependencies (nmap, tcpdump, arp-scan, iptables)..."
eval $INSTALL_CMD nmap tcpdump arp-scan iptables

if ! command -v cargo &> /dev/null; then
    echo "🦀 Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

if ! command -v python3 &> /dev/null; then
    echo "🐍 Python3 not found. Please install Python 3.8+ and re-run."
    exit 1
fi

echo "🐍 Creating Python virtual environment..."
python3 -m venv atlantis-venv
source atlantis-venv/bin/activate

echo "📦 Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "🦀 Compiling Atlantis core..."
cargo build --release

echo "🌐 Installing frontend dependencies..."
cd atlantis-ui
npm install
cd ..

mkdir -p data/memory data/defensa data/advanced_honeypot_logs data/zombie_logs data/traffic_logs data/threat_intel data/anomaly_data

echo "✅ Installation complete!"
echo ""
echo "To start Atlantis:"
echo "  source atlantis-venv/bin/activate"
echo "  cd ~/atlantis-core && cargo run"
echo ""
echo "Then open http://localhost:5173 in your browser."
