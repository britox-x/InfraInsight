#!/usr/bin/env python3
"""
InfraInsight - Scanner de Rede Simplificado
"""

import sys
import os
import json
import subprocess
import re
import socket
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.persistence import init_database, salvar_scan
from core.exporter import exportar_csv
from core.utils import detectar_ambiente_por_rede

init_database()

def obter_ip_real():
    """Obtém o IP real da máquina (não localhost)"""
    try:
        # Usar ip addr show
        resultado = subprocess.check_output(['ip', 'addr', 'show'], text=True)
        # Procurar IPs que não sejam 127.0.0.1
        matches = re.findall(r'inet (\d+\.\d+\.\d+\.\d+)/\d+', resultado)
        for ip in matches:
            if not ip.startswith('127.'):
                return ip
    except:
        pass
    
    # Fallback
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return '172.20.119.205'

def obter_gateway_real():
    """Obtém o gateway real"""
    try:
        resultado = subprocess.check_output(['ip', 'route', 'show', 'default'], text=True)
        match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', resultado)
        if match:
            return match.group(1)
    except:
        pass
    return '172.20.0.1'

def obter_rede(ip):
    """Obtém a rede a partir do IP"""
    partes = ip.split('.')
    return f"{partes[0]}.{partes[1]}.{partes[2]}.0/24"

def obter_wifi_real():
    """Obtém o nome da rede Wi-Fi"""
    try:
        resultado = subprocess.check_output(['iwgetid', '-r'], text=True)
        return resultado.strip() or 'Cabeada/Ethernet'
    except:
        return 'Cabeada/Ethernet'

def obter_hostname(ip):
    """Tenta resolver o nome por DNS reverso, NetBIOS e mDNS."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        pass

    try:
        resultado = subprocess.run(
            ['nbtscan', '-q', ip], capture_output=True, text=True,
            timeout=3, check=False
        )
        for linha in resultado.stdout.splitlines():
            partes = linha.split()
            if len(partes) >= 2 and partes[0] == ip:
                return partes[1]
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    try:
        resultado = subprocess.run(
            ['avahi-resolve', '-a', ip], capture_output=True, text=True,
            timeout=3, check=False
        )
        partes = resultado.stdout.strip().split()
        if len(partes) >= 2 and partes[0] == ip:
            return partes[1].rstrip('.')
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    return ''

def scan_hosts(rede):
    """Escaneia hosts usando nmap"""
    dispositivos = []
    try:
        import nmap
        nm = nmap.PortScanner()
        print(f"🔍 Escaneando: {rede}")
        # Keep reverse DNS enabled so devices that advertise a hostname are named.
        nm.scan(hosts=rede, arguments='-sn -PR')
        
        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                mac = nm[host]['addresses'].get('mac', '')
                vendor = nm[host].get('vendor', {}).get(mac, '')
                hostname = nm[host].hostname() or obter_hostname(host)
                
                tipo = 'computador_conhecido'
                if 'router' in hostname.lower() or 'gateway' in hostname.lower():
                    tipo = 'roteador'
                elif 'iphone' in hostname.lower() or 'android' in hostname.lower():
                    tipo = 'smartphone'
                elif 'tv' in hostname.lower():
                    tipo = 'smarttv'
                elif 'camera' in hostname.lower():
                    tipo = 'camera_ip'
                
                # Tentar determinar tipo por MAC
                if vendor and 'apple' in vendor.lower():
                    tipo = 'smartphone'
                elif vendor and 'tp-link' in vendor.lower():
                    tipo = 'roteador'
                
                dispositivo = {
                    'ip': host,
                    'mac': mac,
                    'fabricante': vendor or 'local',
                    'hostname': hostname,
                    'tipo': tipo,
                    'risco': 0,
                    'severity': 'Baixo',
                    'open_ports': []
                }
                dispositivos.append(dispositivo)
        return dispositivos
    except Exception as e:
        print(f"⚠️ Erro no scan: {e}")
        return []

# --- MAIN ---
print("\n🔍 InfraInsight Scanner")
print("=" * 40)

# Detectar rede real
ip_local = obter_ip_real()
gateway = obter_gateway_real()
rede = obter_rede(ip_local)
wifi = obter_wifi_real()

print(f"🖥️  IP Local: {ip_local}")
print(f"🌐 Rede: {rede}")
print(f"📡 Gateway: {gateway}")
print(f"📶 Wi-Fi: {wifi}")

# Detectar ambiente
try:
    ambiente = detectar_ambiente_por_rede(gateway, rede, wifi, perguntar=sys.stdin.isatty())
except:
    ambiente = "Casa"

# Escanear
print(f"\n📊 Iniciando scan no ambiente: {ambiente}")
dispositivos = scan_hosts(rede)

if dispositivos:
    print(f"\n✅ {len(dispositivos)} dispositivos encontrados:")
    print("=" * 50)
    for d in dispositivos[:10]:  # Mostrar apenas os 10 primeiros
        print(f"  📱 {d['ip']} - {d['tipo']} ({d['fabricante']})")
    if len(dispositivos) > 10:
        print(f"  ... e mais {len(dispositivos) - 10} dispositivos")
    
    # Salvar (corrigido - salvar_scan espera apenas o dict)
    resultado = {
        'dispositivos': dispositivos,
        'ips_ativos': len(dispositivos),
        'risco_medio': 0,
        'desconhecidos': 0,
        'ambiente': ambiente,
        'gateway': gateway,
        'rede': rede,
        'timestamp': datetime.now().isoformat()
    }
    
    try:
        scan_id = salvar_scan(resultado)
        print(f"\n💾 Scan salvo com ID: {scan_id}")
    except TypeError as e:
        print(f"⚠️ Erro ao salvar: {e}")
        # Tentar com outro formato
        try:
            scan_id = salvar_scan(ambiente)
            print(f"💾 Scan salvo (formato alternativo) ID: {scan_id}")
        except:
            print("⚠️ Não foi possível salvar no banco")
    
    # Exportar CSV
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        csv_path = f"exports/dispositivos_{timestamp}.csv"
        exportar_csv(dispositivos, csv_path)
        print(f"📊 CSV: {csv_path}")
    except Exception as e:
        print(f"⚠️ Erro ao exportar CSV: {e}")
else:
    print("\n⚠️ Nenhum dispositivo encontrado (verifique o firewall)")

print("\n✅ Scanner finalizado!")
