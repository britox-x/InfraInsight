#!/usr/bin/env python3
"""
InfraInsight - Scanner de Rede Simplificado
"""

import sys
import os
import json
import csv
import subprocess
import re
import socket
from datetime import datetime
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
load_dotenv()

from core.persistence import DB_NAME, init_database, salvar_scan
from core.exporter import exportar_csv, exportar_software_csv
from core.utils import detectar_ambiente_por_rede
from core.fingerprint.nmap_parser import parsear_servicos_nmap
from core.scan_config import obter_portas_scan

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

def scan_hosts(rede, detect_services=False):
    """Descobre hosts e, opcionalmente, enumera serviços TCP/UDP."""
    dispositivos = []
    import nmap

    nm = nmap.PortScanner()
    print(f"🔍 Escaneando: {rede}")
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

            if vendor and 'apple' in vendor.lower():
                tipo = 'smartphone'
            elif vendor and 'tp-link' in vendor.lower():
                tipo = 'roteador'

            dispositivos.append({
                'ip': host,
                'mac': mac,
                'fabricante': vendor or 'local',
                'hostname': hostname,
                'tipo': tipo,
                'risco': 0,
                'severity': 'Baixo',
                'open_ports': [],
                'services': [],
            })

    if detect_services and dispositivos:
        hosts = ' '.join(device['ip'] for device in dispositivos)
        print("🔎 Identificando serviços e versões (Nmap -sV)...")
        ports = ",".join(str(port) for port in obter_portas_scan())
        nm.scan(
            hosts=hosts,
            arguments=f'-sV --version-all -p {ports}',
        )
        for device in dispositivos:
            if device['ip'] in nm.all_hosts() and nm[device['ip']].state() == 'up':
                services = parsear_servicos_nmap(nm[device['ip']])
                device['services'] = services
                device['open_ports'] = sorted({service['port'] for service in services})

    return dispositivos

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
scan_services = os.getenv('INFRA_SCAN_SERVICES', '').strip().lower() in {
    '1', 'true', 'yes', 'on'
}
dispositivos = scan_hosts(rede, detect_services=scan_services)

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

    if scan_services and os.getenv('INFRA_CVE_LOOKUP', '').strip().lower() in {
        '1', 'true', 'yes', 'on'
    }:
        from requests.exceptions import (
            ConnectionError as RequestsConnectionError,
            HTTPError,
            Timeout,
        )

        from core.cve_client import NvdClient, enriquecer_servicos_com_cves

        client = NvdClient(
            api_key=os.getenv('INFRA_NVD_API_KEY'),
            db_path=DB_NAME,
        )
        service_groups = [device.get('services', []) for device in dispositivos]
        all_services = [service for group in service_groups for service in group]
        try:
            enriched_services = enriquecer_servicos_com_cves(all_services, client)
        except (RequestsConnectionError, HTTPError, Timeout) as error:
            print(f"⚠️ Consulta ao NVD falhou; CVEs não foram atualizadas: {error}")
        else:
            offset = 0
            for device, services in zip(dispositivos, service_groups):
                device['services'] = enriched_services[offset:offset + len(services)]
                offset += len(services)

    scan_id = salvar_scan(resultado)
    print(f"\n💾 Scan salvo com ID: {scan_id}")
    
    # Exportar CSV
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    try:
        csv_path = f"exports/dispositivos_{timestamp}.csv"
        exportar_csv(dispositivos, csv_path)
        print(f"📊 CSV: {csv_path}")
    except Exception as e:
        print(f"⚠️ Erro ao exportar CSV: {e}")
    if scan_services:
        try:
            software_csv_path = f"exports/software_{timestamp}.csv"
            exportar_software_csv(dispositivos, software_csv_path)
        except (OSError, csv.Error) as error:
            print(f"⚠️ Erro ao exportar inventário de software: {error}")
else:
    print("\n⚠️ Nenhum dispositivo encontrado (verifique o firewall)")

print("\n✅ Scanner finalizado!")
