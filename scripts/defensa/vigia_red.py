#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
EL VIGÍA DE ATLANTIS v5.8 - RUTAS RELATIVAS
• Detecta automáticamente la red donde está conectado
• Obtiene MACs reales de dispositivos (ping + arp -n)
• Resuelve nombres de dispositivos (Nothing Phone, Samsung TV, etc.)
• Funciona en cualquier WiFi (casa, trabajo, café, hotel)
• RUTAS RELATIVAS al ejecutable de Atlantis
• Detecta automáticamente si está en WSL o Windows
• Usa sudo internamente con ruta completa de nmap
• En modo JSON, NO imprime texto de depuración
• Sanitización de inputs para evitar inyección de comandos
"""

import json
import subprocess
import platform
import os
import time
import socket
import sys
import argparse
import shlex
from pathlib import Path
from datetime import datetime

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
    
    # Fallback: usar la ubicación del script
    script_dir = Path(__file__).parent.absolute()
    # Subir 3 niveles: scripts/defensa/ -> atlantis/
    return script_dir.parent.parent

# ============================================================
# CONFIGURACIÓN - RUTAS RELATIVAS
# ============================================================
BASE_PATH = get_base_path()
DATA_DIR = BASE_PATH / "data"
DEFENSA_DIR = DATA_DIR / "defensa"

# Crear directorios
DATA_DIR.mkdir(parents=True, exist_ok=True)
DEFENSA_DIR.mkdir(parents=True, exist_ok=True)

# Archivos de datos
ARCHIVO_LINEA_BASE = DEFENSA_DIR / "linea_base.json"
ARCHIVO_LOG = DEFENSA_DIR / "vigia_log.txt"
ARCHIVO_FABRICANTES = DEFENSA_DIR / "fabricantes.json"

print(f"📁 Data directory: {DATA_DIR}", file=sys.stderr)

# ============================================================
# SANITIZACIÓN DE INPUTS
# ============================================================
def sanitize_input(input_str):
    """Sanitiza entrada para evitar inyección de comandos"""
    if not input_str:
        return ""
    return shlex.quote(str(input_str))

# ============================================================
# FIX DE ENCODING PARA WINDOWS
# ============================================================
if platform.system() == "Windows":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# ============================================================
# DETECCIÓN DE WSL
# ============================================================
def is_wsl():
    """Detecta si el script se está ejecutando dentro de WSL."""
    try:
        release = platform.uname().release.lower()
        return 'microsoft' in release or 'wsl' in release
    except:
        return False

# ============================================================
# DETECCIÓN DE ENTORNO
# ============================================================
def get_environment():
    """Devuelve el entorno actual: 'wsl', 'windows', o 'linux'."""
    if is_wsl():
        return "wsl"
    elif platform.system() == "Windows":
        return "windows"
    else:
        return "linux"

# ============================================================
# RESOLUCIÓN DE HOSTNAME
# ============================================================
def resolve_hostname(ip):
    """Intenta resolver el nombre del dispositivo por DNS inverso"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if '.' in hostname:
            hostname = hostname.split('.')[0]
        return hostname
    except:
        return None

# ============================================================
# OBTENER MAC REAL DE UNA IP
# ============================================================
def get_mac_from_ip(ip):
    """Obtiene la MAC real de una IP usando ping + arp -n"""
    mac = "00:00:00:00:00:00"
    try:
        subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True, timeout=2)
        arp_result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=5)
        for line in arp_result.stdout.split('\n'):
            if ip in line:
                parts = line.split()
                for part in parts:
                    if ':' in part and len(part) == 17:
                        mac = part.lower()
                        break
    except:
        pass
    return mac

# ============================================================
# DETECCIÓN AUTOMÁTICA DE RED
# ============================================================
def detectar_red_actual():
    """Detecta la red actual automáticamente (casa, trabajo, café, hotel)"""
    try:
        import ipaddress
        import netifaces

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_local = s.getsockname()[0]
        s.close()

        gateways = netifaces.gateways()
        iface = gateways['default'][netifaces.AF_INET][1]
        addrs = netifaces.ifaddresses(iface)
        netmask = addrs[netifaces.AF_INET][0]['netmask']

        red = ipaddress.IPv4Network(f"{ip_local}/{netmask}", strict=False)
        return str(red)
    except Exception as e:
        return "192.168.1.0/24"

# ============================================================
# BASE DE DATOS DE FABRICANTES (MAC -> Empresa)
# ============================================================
def cargar_fabricantes():
    if ARCHIVO_FABRICANTES.exists():
        with open(ARCHIVO_FABRICANTES, 'r', encoding='utf-8') as f:
            return json.load(f)
    else:
        fabricantes = {
            "00:00:0C": "Cisco", "00:14:22": "Dell", "00:17:F2": "Apple",
            "00:1E:52": "Apple", "00:1F:F3": "Apple", "00:21:E9": "Samsung",
            "00:23:76": "HP", "00:25:00": "Apple", "00:26:BB": "Apple",
            "00:30:65": "Motorola", "04:0E:3C": "Intel", "08:00:27": "Oracle (VirtualBox)",
            "0C:9D:92": "Huawei", "10:9F:C9": "Intel", "1C:6F:65": "TP-Link",
            "20:4E:7F": "Asus", "24:4B:FE": "Microsoft", "28:6D:CD": "Xiaomi",
            "2C:33:7A": "Google", "30:9C:23": "Amazon", "34:96:72": "Intel",
            "38:0B:40": "Apple", "3C:5C:24": "Intel", "40:B0:76": "Apple",
            "44:65:0D": "Samsung", "48:5D:36": "Intel", "4C:1B:86": "Nothing Technology",
            "4C:7F:62": "Huawei", "50:2F:5E": "Intel", "54:60:09": "Intel",
            "5C:CF:7F": "Apple", "60:33:4B": "Intel", "64:66:B3": "Intel",
            "68:DB:F5": "Intel", "6C:88:14": "Apple", "70:8B:CD": "Apple",
            "74:85:2A": "Apple", "78:4F:43": "Intel", "7C:11:CB": "Intel",
            "7C:70:DB": "ASIX Electronics", "80:56:F2": "Intel", "80:9D:65": "FN-Link Technology",
            "84:7B:EB": "Apple", "88:66:5A": "Apple", "8C:85:90": "Intel",
            "8E:7A:67": "Shark Robotics", "90:0C:27": "Samsung", "94:65:2D": "Apple",
            "98:03:A0": "Apple", "9C:29:EF": "Intel", "A0:51:0B": "Intel",
            "A4:83:E7": "Intel", "A8:7E:EA": "Intel", "AC:1F:74": "Intel",
            "B0:7D:64": "Intel", "B4:0E:DE": "Intel", "B8:8A:EC": "Intel",
            "BC:76:70": "Intel", "C0:25:A5": "Intel", "C4:41:1E": "Apple",
            "C8:69:CD": "Intel", "CC:3D:82": "Intel", "D0:17:6A": "Intel",
            "D4:3D:7E": "Intel", "D8:5B:2A": "Apple", "DC:2B:2A": "Intel",
            "E0:1C:FC": "Intel", "E4:70:B8": "Intel", "E8:48:1F": "Intel",
            "EC:8E:AE": "Intel", "F0:6E:0B": "Intel", "F4:69:42": "Askey Computer",
            "F4:6B:EF": "Intel", "F8:32:E4": "Intel", "FC:15:B4": "Intel",
        }
        with open(ARCHIVO_FABRICANTES, 'w', encoding='utf-8') as f:
            json.dump(fabricantes, f, indent=2, ensure_ascii=False)
        return fabricantes

FABRICANTES = cargar_fabricantes()

def obtener_fabricante(mac):
    if not mac or mac == "Desconocida" or mac == "00:00:00:00:00:00":
        return "Desconocido"
    prefijo = mac.upper()[:8]
    if prefijo in FABRICANTES:
        return FABRICANTES[prefijo]
    prefijo_corto = mac.upper()[:5]
    if prefijo_corto in FABRICANTES:
        return FABRICANTES[prefijo_corto]
    return "Desconocido"

def obtener_mi_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "0.0.0.0"

# ============================================================
# RED LOCAL DETECTADA AUTOMÁTICAMENTE
# ============================================================
RED_LOCAL = detectar_red_actual()

# ============================================================
# ESCANEO CON NMAP (VERSIÓN CON MACs Y HOSTNAMES REALES)
# ============================================================
def escanear_con_nmap(red=RED_LOCAL, quiet=False):
    env = get_environment()

    if not quiet:
        print(f"🔍 Escaneando red {red} con Nmap...")
        print(f"   📡 Entorno detectado: {env.upper()}")

    try:
        red_sanitizada = sanitize_input(red)
        hosts = []
        ip_list = []

        if env == "wsl":
            cmd = ["sudo", "/usr/bin/nmap", "-sn", "-PE", "-PS443,4070", "-PA80", "-PP", red_sanitizada]
            if not quiet:
                print("   🌐 Usando modo avanzado para WSL")
        else:
            cmd = ["nmap", "-sn", red_sanitizada]

        resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        for linea in resultado.stdout.split('\n'):
            if "Nmap scan report for" in linea:
                partes = linea.split()
                ip_candidata = partes[-1].strip('()')
                if ip_candidata and '.' in ip_candidata:
                    ip_actual = ip_candidata
                    mi_ip = obtener_mi_ip()
                    if ip_actual != mi_ip:
                        ip_list.append(ip_actual)

        if not quiet:
            print(f"   📍 Encontradas {len(ip_list)} IPs activas")

        for ip in ip_list:
            mac = get_mac_from_ip(ip)
            hostname = resolve_hostname(ip)
            fabricante = obtener_fabricante(mac) if mac != "00:00:00:00:00:00" else "Desconocido"
            
            if mac == "00:00:00:00:00:00" and hostname:
                hostname_lower = hostname.lower()
                if "nothing" in hostname_lower:
                    fabricante = "Nothing Technology"
                elif "samsung" in hostname_lower:
                    fabricante = "Samsung"
                elif "apple" in hostname_lower or "iphone" in hostname_lower:
                    fabricante = "Apple"
                elif "xiaomi" in hostname_lower:
                    fabricante = "Xiaomi"
            
            hosts.append({
                "ip": ip,
                "mac": mac,
                "fabricante": fabricante if fabricante != "Desconocido" else "Dispositivo",
                "hostname": hostname if hostname else "Desconocido",
                "estado": "up",
                "ultima_vez_visto": datetime.now().isoformat()
            })
            
            if not quiet:
                host_str = f" ({hostname})" if hostname else ""
                print(f"   ✅ {ip:15} | {mac:17} | {fabricante}{host_str}")

        if not hosts and env == "wsl":
            if not quiet:
                print("   🔄 Fallback: Intentando con ARP...")
            try:
                arp_result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
                for line in arp_result.stdout.split('\n'):
                    parts = line.split()
                    if len(parts) >= 2 and '.' in parts[0]:
                        ip = parts[0]
                        mac = parts[1].replace('-', ':').lower() if len(parts) > 1 else "00:00:00:00:00:00"
                        mi_ip = obtener_mi_ip()
                        if ip != mi_ip and not ip.startswith("224.") and not ip.startswith("239."):
                            hostname = resolve_hostname(ip)
                            fabricante = obtener_fabricante(mac) if mac != "00:00:00:00:00:00" else "Desconocido"
                            hosts.append({
                                "ip": ip,
                                "mac": mac,
                                "fabricante": fabricante,
                                "hostname": hostname if hostname else "Desconocido",
                                "estado": "up",
                                "ultima_vez_visto": datetime.now().isoformat()
                            })
                            if not quiet:
                                print(f"   ✅ {ip:15} | {mac:17} | {hostname or 'Desconocido'} ({fabricante})")
            except Exception as e:
                if not quiet:
                    print(f"   ⚠️ Error en ARP fallback: {e}")

        return hosts

    except subprocess.TimeoutExpired:
        if not quiet:
            print("❌ Timeout en escaneo Nmap")
        return []
    except Exception as e:
        if not quiet:
            print(f"❌ Error en Nmap: {e}")
        return []

def escanear_red(red=RED_LOCAL, quiet=False):
    return escanear_con_nmap(red, quiet)

def cargar_linea_base():
    if ARCHIVO_LINEA_BASE.exists():
        with open(ARCHIVO_LINEA_BASE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def guardar_linea_base(dispositivos):
    with open(ARCHIVO_LINEA_BASE, 'w', encoding='utf-8') as f:
        json.dump(dispositivos, f, indent=2, ensure_ascii=False)

def registrar_alerta(mensaje):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(ARCHIVO_LOG, 'a', encoding='utf-8') as f:
        f.write(f"[{timestamp}] {mensaje}\n")

def detectar_cambios(hosts_actuales, linea_base):
    ips_conocidas = {d['ip'] for d in linea_base}
    ips_actuales = {h['ip'] for h in hosts_actuales}

    nuevas_ips = ips_actuales - ips_conocidas
    desaparecidas_ips = ips_conocidas - ips_actuales

    nuevas = [h for h in hosts_actuales if h['ip'] in nuevas_ips]
    desaparecidas = [d for d in linea_base if d['ip'] in desaparecidas_ips]

    return {"nuevas": nuevas, "desaparecidas": desaparecidas}

def main():
    parser = argparse.ArgumentParser(description="ATLANTIS Vigía - Network Scanner")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--red", default=RED_LOCAL, help="Network to scan (CIDR)")
    args = parser.parse_args()

    if args.json:
        hosts_actuales = escanear_red(args.red, quiet=True)
        output = {"timestamp": datetime.now().isoformat(), "red": args.red, "dispositivos": hosts_actuales, "total": len(hosts_actuales)}
        print(json.dumps(output, ensure_ascii=False))
        return

    print("╔" + "═"*68 + "╗")
    print("║     ATLANTIS - EL VIGÍA v5.8 (RUTAS RELATIVAS)        ║")
    print("╚" + "═"*68 + "╝")

    env = get_environment()
    mi_ip = obtener_mi_ip()
    print(f"🖥️  Tu IP: {mi_ip}")
    print(f"🌐 Red detectada: {RED_LOCAL}")
    print(f"📡 Entorno: {env.upper()}")
    print()

    hosts_actuales = escanear_red(RED_LOCAL, quiet=False)

    if not hosts_actuales:
        print("❌ No se detectaron dispositivos.")
        return

    print(f"\n📡 Dispositivos encontrados: {len(hosts_actuales)}")
    print("\n📋 LISTA DE DISPOSITIVOS DETECTADOS:")
    print("-" * 85)
    for h in hosts_actuales:
        host_str = f" ({h['hostname']})" if h['hostname'] != "Desconocido" else ""
        print(f"   IP: {h['ip']:<15} | MAC: {h['mac']:<17} | {h['fabricante']:<20}{host_str}")

    linea_base = cargar_linea_base()

    if not linea_base:
        print("\n🆕 Primera ejecución. Creando línea base...")
        guardar_linea_base(hosts_actuales)
        registrar_alerta("Línea base inicial creada")
        print("✅ Línea base creada.")
        return

    cambios = detectar_cambios(hosts_actuales, linea_base)

    if cambios["nuevas"] or cambios["desaparecidas"]:
        print("\n" + "="*70)
        print("🚨 ¡ALERTA! CAMBIOS DETECTADOS:")
        print("="*70)

        if cambios["nuevas"]:
            print("\n🆕 NUEVOS DISPOSITIVOS:")
            for d in cambios["nuevas"]:
                print(f"   + {d['ip']} | {d['mac']} | {d['fabricante']} | {d['hostname']}")
                registrar_alerta(f"Nuevo dispositivo: {d['ip']} - {d['mac']} - {d['fabricante']}")

        if cambios["desaparecidas"]:
            print("\n⚠️ DISPOSITIVOS DESAPARECIDOS:")
            for d in cambios["desaparecidas"]:
                print(f"   - {d['ip']} | {d['mac']} | {d['fabricante']}")
                registrar_alerta(f"Dispositivo desaparecido: {d['ip']} - {d['mac']} - {d['fabricante']}")

        respuesta = input("\n¿Actualizar línea base? (s/n): ").lower()
        if respuesta == 's':
            guardar_linea_base(hosts_actuales)
            print("✅ Línea base actualizada.")
    else:
        print("\n✅ Todo en orden.")

if __name__ == "__main__":
    main()
