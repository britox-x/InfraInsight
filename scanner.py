#!/usr/bin/env python3
# scanner.py - InfraInsight Network Scanner

import subprocess
import re
import json
import os
import socket


# Wi-Fi Scanner
try:
    from core.wifi_scanner import scan_wifi_simples, listar_interfaces_wifi, verificar_aircrack
    WIFI_AVAILABLE = True
except ImportError:
    WIFI_AVAILABLE = False
    print("[INFO] Módulo Wi-Fi não disponível")


from datetime import datetime

from core.host_local import obter_host_local
from core.classifier import classificar_dispositivo
from core.risk_scorer import calcular_risco_avancado, classificar_severidade, gerar_recomendacoes
from core.persistence import init_database, salvar_scan, carregar_historico
from core.graph_generator import gerar_graficos
from core.utils import obter_mac_por_ip, fabricante_por_mac, detectar_rede, obter_nome_wifi, obter_gateway, detectar_ambiente_por_rede

# Configuração
CONFIG_PATH = "config.json"
if os.path.exists(CONFIG_PATH):
    with open(CONFIG_PATH, "r") as f:
        CONFIG = json.load(f)
else:
    CONFIG = {}

# ============================================================
# DETECTAR AMBIENTE (colocar AQUI, depois do CONFIG)
# ============================================================
gateway = CONFIG.get("gateway_ip") or obter_gateway()
rede = detectar_rede()
nome_wifi = obter_nome_wifi()

# Verificar se deve forçar detecção de ambiente
if CONFIG.get("ambiente_force_detect", False) or not CONFIG.get("ambiente"):
    AMBIENTE = detectar_ambiente_por_rede(gateway, rede, nome_wifi)
else:
    AMBIENTE = CONFIG.get("ambiente", "Casa")

print(f"[INFO] Ambiente: {AMBIENTE}")

agora = datetime.now().isoformat()
print(f"[INFO] Timestamp: {agora}")

# ============================================================
# INICIALIZAR BANCO E HOST LOCAL
# ============================================================
init_database()
host_local = obter_host_local()
print(f"[INFO] Host local identificado: {host_local.get('ip')} - {host_local.get('mac')}")
print(f"[INFO] Rede detectada: {rede}")
print(f"[INFO] Wi-Fi: {nome_wifi}")
print(f"[INFO] Gateway: {gateway}")


# ============================================================
# CONTINUA O RESTO DO CÓDIGO
# ============================================================

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_port(ip, port, timeout=0.3):
    """Escaneia uma única porta (para uso em paralelo)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port if result == 0 else None
    except:
        return None

def scan_ports(ip, ports=None, timeout=0.3, max_workers=20):
    """
    Escaneia portas em PARALELO (muito mais rápido)
    
    Args:
        ip: Endereço IP
        ports: Lista de portas (padrão: portas comuns)
        timeout: Timeout em segundos
        max_workers: Número máximo de threads paralelas
    
    Returns:
        Lista de portas abertas
    """
    if ports is None:
        ports = [22, 23, 80, 443, 445, 3389, 5900, 8080, 554, 1900, 
                 21, 25, 110, 143, 993, 995, 1723, 3306, 5432, 27017]
    
    open_ports = []
    
    # Escanear em paralelo
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    
    return sorted(open_ports)

# Versão com cache para não re-escanear o mesmo IP
PORTS_CACHE = {}

def scan_ports_with_cache(ip, ports=None, force=False):
    """
    Versão com cache para evitar re-escaneamento
    """
    if not force and ip in PORTS_CACHE:
        return PORTS_CACHE[ip]
    
    open_ports = scan_ports(ip, ports)
    PORTS_CACHE[ip] = open_ports
    return open_ports

# Carregar histórico
historical_scans = carregar_historico(limit=50)
all_historical_devices = []
for scan in historical_scans:
    all_historical_devices.extend(scan.get('devices', []))

print(f"[INFO] Carregados {len(historical_scans)} scans históricos")

# Executar Nmap
print("[INFO] Executando scan Nmap...")
resultado = subprocess.check_output(["sudo", "nmap", "-sn", "-n", "-PR", rede]).decode()
linhas = resultado.split("\n")
dispositivos = []

for linha in linhas:
    if "Nmap scan report for" in linha:
        nome = "desconhecido"
        ip = None
        match = re.search(r"for (.+) \((\d+\.\d+\.\d+\.\d+)\)", linha)
        if match:
            nome = match.group(1)
            ip = match.group(2)
        else:
            match = re.search(r"for (\d+\.\d+\.\d+\.\d+)", linha)
            if match:
                ip = match.group(1)
        if ip:
            dispositivos.append({
                "ip": ip,
                "nome": nome,
                "mac": "desconhecido",
                "fabricante": "desconhecido"
            })
    elif "MAC Address" in linha:
        match = re.search(r"MAC Address: ([\w:]+) \((.+)\)", linha)
        if match and dispositivos:
            dispositivos[-1]["mac"] = match.group(1).lower()
            dispositivos[-1]["fabricante"] = match.group(2)

# Carregar histórico JSON
historico_arquivo = "storage/historico_dispositivos.json"
if os.path.exists(historico_arquivo):
    with open(historico_arquivo, "r") as f:
        historico_legado = json.load(f)
else:
    historico_legado = {}

# Processar dispositivos
novos_dispositivos = []
dispositivos_processados = []

for d in dispositivos:
    if d["mac"] == "desconhecido":
        d["mac"] = obter_mac_por_ip(d["ip"])
    
    if d["fabricante"].lower() in ["unknown", "desconhecido"]:
        fabricante_mac = fabricante_por_mac(d["mac"])
        if fabricante_mac != "desconhecido":
            d["fabricante"] = fabricante_mac
    
    ip = d.get("ip") or ""
    mac = d.get("mac") or ""
    
    if ip == host_local.get("ip") or mac == host_local.get("mac"):
        d["tipo"] = "computador_conhecido"
        if d["mac"] == "desconhecido":
            d["mac"] = host_local.get("mac")
        d["fabricante"] = "local"
        d["open_ports"] = scan_ports(d["ip"])
        
        risk_score, risk_details = calcular_risco_avancado(d, all_historical_devices)
        d["risco"] = risk_score
        severity, _ = classificar_severidade(risk_score)
        d["severity"] = severity
        d["recommendations"] = gerar_recomendacoes(risk_score, risk_details, d)
        
        print(f"[INFO] Host local: {d['ip']} (Risco: {risk_score}/10)")
        dispositivos_processados.append(d)
        continue
    
    novo = (d["mac"] not in historico_legado and d["mac"] != "desconhecido")
    d["open_ports"] = scan_ports(d["ip"])
    
        # Classificação
    tipo, _ = classificar_dispositivo(
        hostname=d["nome"],
        vendor=d["fabricante"],
        ip=d["ip"],
        mac=d["mac"],
        open_ports=d.get("open_ports", [])
    )
    d["tipo"] = tipo
    
    # Forçar gateway como roteador
    if d["ip"] == "192.168.0.1" or d["ip"] == gateway:
        d["tipo"] = "roteador"
        print(f"[INFO] Gateway forçado como roteador: {d['ip']}")

    risk_score, risk_details = calcular_risco_avancado(d, all_historical_devices)
    d["risco"] = risk_score
    severity, _ = classificar_severidade(risk_score)
    d["severity"] = severity
    d["recommendations"] = gerar_recomendacoes(risk_score, risk_details, d)
    
    if novo:
        novos_dispositivos.append({
            "ip": d["ip"],
            "nome": d["nome"],
            "mac": d["mac"],
            "fabricante": d["fabricante"],
            "tipo": d["tipo"],
            "risco": d["risco"],
            "severity": severity
        })
    
    if d["mac"] != "desconhecido":
        if d["mac"] not in historico_legado:
            historico_legado[d["mac"]] = {}
        historico_legado[d["mac"]].update({
            "tipo": d["tipo"],
            "ultima_vista": agora,
            "frequencia": historico_legado[d["mac"]].get("frequencia", 0) + 1
        })
    
    dispositivos_processados.append(d)

# Métricas
ativos = len(dispositivos_processados)
uso = (ativos / 254) * 100
desconhecidos = sum(1 for d in dispositivos_processados if d["tipo"] == "desconhecido")
mac_randomizados = sum(1 for d in dispositivos_processados if "privado" in d["fabricante"].lower())
risco_medio = round(sum(d["risco"] for d in dispositivos_processados) / ativos, 2) if ativos > 0 else 0

print("\n" + "="*50)
print("RESUMO DO SCAN")
print("="*50)
print(f"IPs ativos: {ativos}")
print(f"Uso da rede: {round(uso, 2)}%")
print(f"Risco medio: {risco_medio}/10")
print(f"MACs randomizados: {mac_randomizados}")
print(f"Desconhecidos: {desconhecidos}")

print("\n📱 DISPOSITIVOS DETECTADOS:")
print("-"*100)

tipos = {}
for d in dispositivos_processados:
    tipo = d["tipo"]
    tipos[tipo] = tipos.get(tipo, 0) + 1
    
    # Indicador visual de risco
    risk_icon = "🟢" if d["risco"] <= 2 else "🟡" if d["risco"] <= 5 else "🟠" if d["risco"] <= 7 else "🔴"
    
    # Mostrar portas abertas
    ports_info = ""
    if d.get('open_ports') and len(d['open_ports']) > 0:
        ports_str = ', '.join(map(str, d['open_ports']))
        ports_info = f" 🔓 Portas: [{ports_str}]"
    
    # Mostrar serviços nas portas
    services_info = ""
    if d.get('open_ports'):
        services = []
        for port in d['open_ports']:
            service = {
                22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS",
                445: "SMB", 3389: "RDP", 5900: "VNC", 8080: "Proxy",
                554: "RTSP", 1900: "UPnP", 21: "FTP", 25: "SMTP"
            }.get(port, "")
            if service:
                services.append(service)
        if services:
            services_info = f" [{', '.join(services)}]"
    
    print(f"{risk_icon} {d['ip']:15} | {d['nome'][:20]:20} | {d['fabricante'][:25]:25} | {d['tipo'][:20]:20} | Risco {d['risco']}/10{ports_info}{services_info}")

# Salvar histórico
with open(historico_arquivo, "w") as f:
    json.dump(historico_legado, f, indent=4)

# Salvar no SQLite
dados = {
    "timestamp": agora,
    "ambiente": AMBIENTE,
    "wifi": nome_wifi,
    "subrede": rede,
    "gateway": gateway,
    "ips_ativos": ativos,
    "uso": round(uso, 2),
    "risco_medio": risco_medio,
    "desconhecidos": desconhecidos,
    "mac_randomizados": mac_randomizados,
    "novos_dispositivos": len(novos_dispositivos),
    "recomendacao": "OK",
    "dispositivos": dispositivos_processados
}

try:
    salvar_scan(dados)
    print("\nDados salvos no SQLite!")
except Exception as e:
    print(f"Erro ao salvar: {e}")

try:
    gerar_graficos(dados)
    print("Graficos gerados!")
except Exception as e:
    print(f"Erro nos graficos: {e}")

print(f"\nScan concluido em {datetime.now().strftime('%H:%M:%S')}")
# =========================
# Geração do PDF
# =========================
try:
    from reports.pdf_report import gerar_pdf
    
    # Preparar dados para o PDF
    dispositivos_pdf = []
    for d in dispositivos_processados:
        dispositivos_pdf.append({
            "ip": d.get("ip", "-"),
            "hostname": d.get("nome", "-"),
            "mac": d.get("mac", "-"),
            "vendor": d.get("fabricante", "Desconhecido"),
            "tipo": d.get("tipo", "desconhecido"),
            "risco": d.get("risco", 3),
            "severity": d.get("severity", "Médio"),
            "open_ports": d.get("open_ports", [])
        })
    
    # Carregar histórico para o PDF
    historico_scans_arquivo = "storage/historico_scans.json"
    if os.path.exists(historico_scans_arquivo):
        with open(historico_scans_arquivo, "r") as f:
            historico_pdf = json.load(f)
    else:
        historico_pdf = []
    
    caminho_pdf = gerar_pdf(dispositivos_pdf, historico_pdf)
    print(f"\n📄 Relatório PDF gerado: {caminho_pdf}")
except Exception as e:
    print(f"❌ Erro ao gerar PDF: {e}")

# =========================
# Scan Wi-Fi (opcional)
# =========================
if CONFIG.get("scan_wifi", False):
    print("\n" + "="*60)
    print("📶 SCAN WI-FI")
    print("="*60)
    
    try:
        from core.wifi_scanner import listar_interfaces_wifi, scan_wifi_simples
        
        interfaces = listar_interfaces_wifi()
        if interfaces:
            print(f"📡 Interface: {interfaces[0]}")
            
            redes_wifi = scan_wifi_simples()
            
            if redes_wifi:
                print(f"\n📡 Redes Wi-Fi detectadas: {len(redes_wifi)}")
                print("-" * 75)
                print(f"   {'SSID':<25} {'BSSID':<20} {'Canal':<6} {'Sinal':<8} {'Segurança'}")
                print("-" * 75)
                for rede in redes_wifi[:20]:
                    icone = "🔒" if rede.get('encrypted', True) else "🌐"
                    ssid = rede['ssid'][:24] if len(rede['ssid']) > 24 else rede['ssid']
                    sinal = rede.get('sinal', 'N/A')
                    seguranca = "WPA2" if rede.get('encrypted', True) else "Aberta"
                    print(f"   {icone} {ssid:<25} {rede['bssid']:<20} {rede['channel']:<6} {sinal:<8} {seguranca}")
            else:
                print("   Nenhuma rede Wi-Fi detectada")
        else:
            print("   Nenhuma interface Wi-Fi encontrada")
    except Exception as e:
        print(f"   ⚠️ Erro no scan Wi-Fi: {e}")

# =========================
# Alertas de segurança
# =========================
print("\n" + "="*60)
print("🔒 ALERTAS DE SEGURANÇA")
print("="*60)

alertas_gerados = 0
for d in dispositivos_processados:
    if d["risco"] >= 7:
        alertas_gerados += 1
        print(f"🚨 ALTO RISCO: {d['ip']} - {d['tipo']} (Risco {d['risco']}/10)")
        for rec in d.get('recommendations', [])[:2]:
            print(f"   → {rec}")
    elif d["risco"] >= 5:
        alertas_gerados += 1
        print(f"⚠️ RISCO MÉDIO: {d['ip']} - {d['tipo']} (Risco {d['risco']}/10)")

if alertas_gerados == 0:
    print("✅ Nenhum alerta de segurança significativo detectado")

print("="*60)
print(f"✅ Scan concluído em {datetime.now().strftime('%H:%M:%S')}")
