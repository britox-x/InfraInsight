#!/usr/bin/env python3
# scanner.py - InfraInsight Network Scanner

import subprocess
import re
import json
import os
import socket
from tqdm import tqdm
from datetime import datetime

from core.host_local import obter_host_local
from core.classifier import classificar_dispositivo, classificar_por_porta, classificar_dispositivo_randomizado
from core.risk_scorer import calcular_risco_avancado, classificar_severidade, gerar_recomendacoes
from core.persistence import init_database, salvar_scan, carregar_historico
from core.graph_generator import gerar_graficos
from core.exporter import exportar_csv
from core.telegram_bot import alerta_novo, alerta_porta, alerta_resumo
from core.colors import Colors
from core.utils import obter_mac_por_ip, fabricante_por_mac, detectar_rede, obter_nome_wifi, obter_gateway, detectar_ambiente_por_rede

# Wi-Fi Scanner
try:
    from core.wifi_scanner import listar_interfaces_wifi, scan_wifi_simples, scan_wifi_nmcli
    WIFI_AVAILABLE = True
except ImportError as e:
    WIFI_AVAILABLE = False
    print(f"[INFO] Módulo Wi-Fi não disponível: {e}")

# Configuração
CONFIG_PATH = "config.json"
if os.path.exists(CONFIG_PATH):
    with open(CONFIG_PATH, "r") as f:
        CONFIG = json.load(f)
else:
    CONFIG = {}

# ============================================================
# BOT TELEGRAM (LISTENER PARA COMANDOS)


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
from tqdm import tqdm
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
    Escaneia portas em PARALELO (muito mais rapido)
    
    Args:
        ip: Endereco IP
        ports: Lista de portas (padrao: portas comuns)
        timeout: Timeout em segundos
        max_workers: Numero maximo de threads paralelas
    
    Returns:
        Lista de portas abertas
    """
    if ports is None:
        ports = [22, 23, 53, 80, 443, 554, 1900, 8080, 50000]
    
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
        all_historical_devices.extend(scan.get("devices", []))

print(f"[INFO] Carregados {len(historical_scans)} scans históricos")

# Executar Nmap
print(Colors.info(" Executando scan Nmap..."))
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

for d in tqdm(dispositivos, desc="🔍 Escaneando portas", unit="disp"):
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
    
    # Se ainda é desconhecido, tentar classificar por portas
    if d["tipo"] == "desconhecido" and d.get('open_ports'):
        tipo_por_porta = classificar_por_porta(d['open_ports'])
        if tipo_por_porta:
            d["tipo"] = tipo_por_porta
            print(f"   🔍 Classificado por porta: {d['ip']} → {tipo_por_porta}")
    
    # Se é randomizado ou privado, classificar melhor
    if "privado" in d["fabricante"].lower() or "randomizado" in d["fabricante"].lower():
        tipo_random, _ = classificar_dispositivo_randomizado(d["mac"], d["nome"])
        if tipo_random != "mobile/desconhecido":
            d["tipo"] = tipo_random
            print(f"   📱 Classificado como móvel: {d['ip']} → {tipo_random}")

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

print("\n" + "="*100)
print(f"{'📱 DISPOSITIVOS DETECTADOS':^100}")
print("="*100)
print(f" {'IP':<16} {'Tipo':<20} {'Fabricante':<25} {'Dispositivo':<20} {'Risco':<6} {'Portas'}")
print("-"*100)

tipos = {}
for d in dispositivos_processados:
    tipo = d["tipo"]
    tipos[tipo] = tipos.get(tipo, 0) + 1
    
    # Indicador visual de risco
    if d["risco"] <= 2:
        risk_icon = "🟢"
        risk_color = "\033[92m"  # Verde
    elif d["risco"] <= 5:
        risk_icon = "🟡"
        risk_color = "\033[93m"  # Amarelo
    elif d["risco"] <= 7:
        risk_icon = "🟠"
        risk_color = "\033[91m"  # Laranja/Vermelho
    else:
        risk_icon = "🔴"
        risk_color = "\033[91m"  # Vermelho
    
    # Nome amigável do dispositivo
    nome_amigavel = d.get("tipo", "desconhecido").replace("_", " ").title()
    
    # Mostrar portas
    ports_info = ""
    if d.get('open_ports'):
        ports_short = []
        for p in d['open_ports'][:3]:  # Mostrar até 3 portas
            if p == 22: ports_short.append("🔐SSH")
            elif p == 23: ports_short.append("⚠️Telnet")
            elif p == 80: ports_short.append("🌐HTTP")
            elif p == 443: ports_short.append("🔒HTTPS")
            elif p == 445: ports_short.append("📁SMB")
            elif p == 554: ports_short.append("📹RTSP")
            elif p == 8080: ports_short.append("⚙️Proxy")
            else: ports_short.append(str(p))
        if ports_short:
            ports_info = f" [{', '.join(ports_short)}]"
    
    print(f"{risk_icon} {d['ip']:<16} {d['tipo']:<20} {d['fabricante'][:24]:<25} {nome_amigavel:<20} {risk_color}{d['risco']}/10\033[0m {ports_info}")

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
if CONFIG.get("scan_wifi", False) and WIFI_AVAILABLE:
    print("\n" + "="*60)
    print("📶 SCAN WI-FI")
    print("="*60)
    
    try:
        interfaces = listar_interfaces_wifi()
        if interfaces:
            print(f"📡 Interfaces Wi-Fi encontradas: {', '.join(interfaces)}")
            
            # Tentar scan via nmcli primeiro (mais rápido)
            redes_wifi = scan_wifi_nmcli() if 'scan_wifi_nmcli' in dir() else []
            
            if not redes_wifi:
                redes_wifi = scan_wifi_simples()
            
            if redes_wifi:
                print(f"\n📡 Redes Wi-Fi detectadas: {len(redes_wifi)}")
                print("-" * 75)
                print(f"   {'SSID':<30} {'BSSID':<20} {'Canal':<6} {'Sinal':<8}")
                print("-" * 75)
                for rede in redes_wifi[:20]:
                    icone = "🔒" if rede.get('encrypted', True) else "🌐"
                    ssid = rede['ssid'][:28] if len(rede['ssid']) > 28 else rede['ssid']
                    sinal = rede.get("sinal", rede.get("quality", "N/A"))
                    print(f"   {icone} {ssid:<30} {rede['bssid']:<20} {rede['channel']:<6} {sinal:<8}")
            else:
                print("   Nenhuma rede Wi-Fi detectada")
        else:
            print("   Nenhuma interface Wi-Fi encontrada")
            print("   Dica: Verifique se o Wi-Fi está ativado")
    except Exception as e:
        print(f"   ⚠️ Erro no scan Wi-Fi: {e}")

# ============================================================
# VERIFICAÇÃO DE SEGURANÇA DOS ROTEADORES
# ============================================================
try:
    from core.router_login import gerar_alerta_seguranca
    
    for d in dispositivos_processados:
        if d.get('tipo') == 'roteador':
            alertas_router = gerar_alerta_seguranca(d['ip'], d.get('fabricante', ''))
            for alerta in alertas_router:
                print(f"   {alerta}")
                alertas_gerados += 1
except ImportError:
    pass  # Módulo não disponível

# =========================
# Alertas de segurança
# =========================
print("\n" + "="*60)
print("🔒 ALERTAS DE SEGURANÇA")
print("="*60)

alertas_gerados = 0

for d in dispositivos_processados:
    # Alertas por risco
    if d["risco"] >= 7:
        alertas_gerados += 1
        print(f"🚨 ALTO RISCO: {d['ip']} - {d['tipo']} (Risco {d['risco']}/10)")
        for rec in d.get('recommendations', [])[:2]:
            print(f"   → {rec}")
    elif d["risco"] >= 5:
        alertas_gerados += 1
        print(f"⚠️ RISCO MÉDIO: {d['ip']} - {d['tipo']} (Risco {d['risco']}/10)")
    
    # Alertas específicos por PORTA (dentro do loop!)
    if 23 in d.get('open_ports', []):
        alertas_gerados += 1
        print(f"⚠️ SERVIÇO LEGADO DETECTADO: Telnet (porta 23) - Recomenda-se utilizar SSH")
    
    if 445 in d.get('open_ports', []):
        alertas_gerados += 1
        print(f"⚠️ SERVIÇO LEGADO DETECTADO: SMB (porta 445) - Avaliar necessidade de bloqueio")
    
    if 554 in d.get('open_ports', []):
        alertas_gerados += 1
        print(f"ℹ️ SERVIÇO MULTIMÍDIA DETECTADO: RTSP (porta 554) - Possível câmera IP")
    
    if 3389 in d.get('open_ports', []):
        alertas_gerados += 1
        print(f"ℹ️ ACESSO REMOTO DETECTADO: RDP (porta 3389) - Verificar políticas de acesso")

if alertas_gerados == 0:
    print(Colors.ok(" Nenhum alerta de segurança significativo detectado"))
else:
    print(f"\n📊 Total de alertas: {alertas_gerados}")

print("="*60)
    # EXPORTAR CSV

# EXPORTAR CSV
if CONFIG.get("export_csv", True):
    try:
        exportar_csv(dispositivos_processados)
    except Exception as e:
        print(f"⚠️ CSV: {e}")

# TELEGRAM
if CONFIG.get("telegram_alerts", False):
    for n in novos_dispositivos:
        alerta_novo(n)
    for d in dispositivos_processados:
        if 23 in d.get("open_ports", []):
            alerta_porta(d["ip"], 23, "Telnet")
        if 445 in d.get("open_ports", []):
            alerta_porta(d["ip"], 445, "SMB")
    alerta_resumo(dados)

print(f"✅ Scan concluído em {datetime.now().strftime('%H:%M:%S')}")
