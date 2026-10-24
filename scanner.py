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
import time
from datetime import datetime
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
load_dotenv()

from core.persistence import DB_NAME, init_database, salvar_scan
from core.exporter import exportar_csv, exportar_software_csv
from core.utils import detectar_ambiente_por_rede
from core.classifier import (
    classificar_dispositivo,
    contar_dispositivos_desconhecidos,
    mac_localmente_administrado,
    normalizar_fabricante,
    normalizar_hostname,
)
from core.fingerprint.nmap_parser import parsear_servicos_nmap
from core.scan_config import obter_portas_scan
from core.snmp_scanner import (
    consultar_hosts_snmp,
    integrar_dados_snmp,
)

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
    nm.scan(
        hosts=rede,
        arguments='-sn -n -PR -PE -PS80,443 -T4 --max-retries 1',
    )

    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            mac = nm[host]['addresses'].get('mac', '')
            vendor_raw = nm[host].get('vendor', {}).get(mac, '')
            hostname_raw = nm[host].hostname() or obter_hostname(host)
            vendor = normalizar_fabricante(vendor_raw)
            hostname = normalizar_hostname(hostname_raw)
            tipo, confidence = classificar_dispositivo(
                hostname=hostname,
                vendor=vendor,
                ip=host,
                mac=mac,
            )

            dispositivos.append({
                'ip': host,
                'mac': mac,
                'fabricante': vendor or 'Desconhecido',
                'hostname': hostname,
                'tipo': tipo,
                'classificacao_confianca': confidence,
                'classificacao_evidencia': (
                    [f"Hostname: {hostname}"] if hostname else []
                ) + ([f"Fabricante/OUI: {vendor}"] if vendor else [])
                + (
                    ["MAC localmente administrado"]
                    if mac_localmente_administrado(mac) else []
                ),
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

    for device in dispositivos:
        device['classificacao_evidencia'].extend(
            f"Porta aberta: {port}" for port in device['open_ports']
        )
        if not device['classificacao_evidencia']:
            device['classificacao_evidencia'] = ["Sem evidência suficiente"]

    return dispositivos

# --- MAIN ---
print("\n🔍 InfraInsight Scanner")
print("=" * 40)
scan_started = time.monotonic()

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
cve_lookup = os.getenv('INFRA_CVE_LOOKUP', '').strip().lower() in {
    '1', 'true', 'yes', 'on'
}
snmp_enabled = os.getenv('INFRA_SCAN_SNMP', '').strip().lower() in {
    '1', 'true', 'yes', 'on'
}
snmp_community = os.getenv('INFRA_SNMP_COMMUNITY', '').strip()
snmp_port = 161
if snmp_enabled:
    if not snmp_community:
        raise ValueError(
            "INFRA_SCAN_SNMP está ativo, mas INFRA_SNMP_COMMUNITY não foi "
            "definido. Configure uma comunidade somente leitura."
        )
    try:
        snmp_port = int(os.getenv('INFRA_SNMP_PORT', '161'))
    except ValueError as error:
        raise ValueError("INFRA_SNMP_PORT deve ser um número inteiro") from error
    if not 1 <= snmp_port <= 65535:
        raise ValueError("INFRA_SNMP_PORT deve estar entre 1 e 65535")

dispositivos = scan_hosts(rede, detect_services=scan_services)
if snmp_enabled:
    snmp_results = consultar_hosts_snmp(
        [device['ip'] for device in dispositivos],
        snmp_community,
        port=snmp_port,
    )
    for device in dispositivos:
        snmp_data = snmp_results.get(device['ip'])
        if snmp_data:
            integrar_dados_snmp(device, snmp_data)
    print(
        f"ℹ️ SNMP consultou {len(dispositivos)} host(s); "
        f"{len(snmp_results)} responderam com dados do sistema."
    )

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
        'desconhecidos': contar_dispositivos_desconhecidos(dispositivos),
        'ambiente': ambiente,
        'gateway': gateway,
        'rede': rede,
        'presence_scan_complete': True,
        'snmp_enabled': snmp_enabled,
        'timestamp': datetime.now().isoformat()
    }
    if scan_services and cve_lookup:
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

    all_services = [
        service
        for device in dispositivos
        for service in device.get('services', [])
    ]
    cve_services = [service for service in all_services if service.get('cpe')]
    verified_statuses = {
        'verified', 'verified_cached', 'verified_stale_cache'
    }
    cve_coverage_complete = (
        bool(cve_services)
        and len(cve_services) == len(all_services)
        and all(
            service.get('cve_status') in verified_statuses
            for service in cve_services
        )
    )
    resultado.update({
        'modo': 'servicos' if scan_services else 'rapido',
        'scan_services': scan_services,
        'snmp_enabled': snmp_enabled,
        'cve_lookup': cve_lookup and scan_services,
        'classifier_version': (
            'v2-conservador-snmp' if snmp_enabled else 'v2-conservador'
        ),
        'formula_version': 'normalizada-7-v1',
        'cve_coverage_complete': cve_coverage_complete,
        'duracao_s': round(time.monotonic() - scan_started, 2),
    })
    from core.infra_score import decompor_infra_score

    resultado['componentes'] = decompor_infra_score(
        resultado,
        scan_services=scan_services,
        cve_lookup=cve_lookup and scan_services,
        cve_coverage_complete=cve_coverage_complete,
    )['components']
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
    scan_id = salvar_scan({
        'dispositivos': [],
        'ips_ativos': 0,
        'ambiente': ambiente,
        'gateway': gateway,
        'rede': rede,
        'presence_scan_complete': True,
        'modo': 'servicos' if scan_services else 'rapido',
        'scan_services': scan_services,
        'snmp_enabled': snmp_enabled,
        'timestamp': datetime.now().isoformat(),
        'duracao_s': round(time.monotonic() - scan_started, 2),
    })
    print(f"💾 Scan vazio salvo com ID: {scan_id}")

print("\n✅ Scanner finalizado!")
