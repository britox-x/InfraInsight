import subprocess
import re
import json
import os
from datetime import datetime
from modulos.host_local import obter_host_local
from dotenv import load_dotenv
from mac_vendor_lookup import MacLookup
from modulos.classificador import classificar_dispositivo
from modulos.ddwrt import coletar_arp_ddwrt
from modulos.utils import (
    obter_mac_por_ip,
    fabricante_por_mac,
    escanear_detalhado,
    detectar_rede,
    obter_nome_wifi,
    obter_gateway
)


host_local = obter_host_local()

print("[DEBUG] Host local detectado:", host_local)


# =========================
# Configuração central
# =========================
CONFIG_PATH = "config.json"

if os.path.exists(CONFIG_PATH):
    with open(CONFIG_PATH, "r") as f:
        CONFIG = json.load(f)
else:
    CONFIG = {}

AMBIENTE = CONFIG.get("ambiente", "Casa")
gateway = CONFIG.get("gateway_ip") or obter_gateway()

# =========================
# Carregar variáveis de ambiente
# =========================
#load_dotenv()

#mac_lookup = MacLookup()

#try:
 #   mac_lookup.update_vendors()
#except:
 #   pass

# =========================
# Configurações
# =========================
historico_arquivo = "historico_dispositivos.json"

# =========================
# Detectar rede
# =========================
rede = detectar_rede()
nome_wifi = obter_nome_wifi()
gateway = gateway
agora = datetime.now().isoformat()

print("Rede detectada:", rede)
print("Wi-Fi:", nome_wifi)
print("Gateway:", gateway)

# =========================
# Carregar histórico
# =========================
if os.path.exists(historico_arquivo):
    with open(historico_arquivo, "r") as f:
        historico = json.load(f)
else:
    historico = {}

# =========================
# Score de risco
# =========================
def calcular_risco(dispositivo, ips_ativos=0):
    risco = 0

    fabricante = (dispositivo.get("fabricante") or "").lower()
    hostname = (dispositivo.get("nome") or "").lower()
    tipo = (dispositivo.get("tipo") or "").lower()
    frequencia = dispositivo.get("frequencia", 1)

    # =========================
    # MAC privado / randomizado
    # =========================
    if "privado" in fabricante or "randomizado" in fabricante:
        risco += 2

    # =========================
    # Hostname desconhecido
    # =========================
    if hostname in ["", "desconhecido", "unknown"]:
        risco += 1

    # =========================
    # Tipo desconhecido
    # =========================
    if tipo == "desconhecido":
        risco += 2

    # =========================
    # Fabricante realmente desconhecido
    # =========================
    if fabricante in ["unknown", "desconhecido", ""]:
        risco += 2

    # =========================
    # Novo / pouca recorrência
    # =========================
    if frequencia <= 2:
        risco += 1

    # =========================
    # Persistência reduz risco
    # =========================
    if frequencia > 10:
        risco -= 2
    elif frequencia > 5:
        risco -= 1

    # =========================
    # Ambientes grandes = mais tolerância
    # =========================
    if ips_ativos >= 15:
        risco -= 1

    # =========================
    # Infraestrutura confiável
    # =========================
    if tipo in ["gateway_principal", "sensor_borda"]:
        risco = max(risco - 3, 0)

    # =========================
    # Limites
    # =========================
    risco = max(0, min(risco, 10))

    return risco

# =========================
# Executar Nmap
# =========================
resultado = subprocess.check_output(
    ["sudo", "nmap", "-sn","-n", "-PR", rede]
).decode()

linhas = resultado.split("\n")
dispositivos = []

# Coleta complementar via DD-WRT
dispositivos_ddwrt = coletar_arp_ddwrt()


# =========================
# Parsing inicial
# =========================
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

# =========================
# Mesclar DD-WRT + Nmap
# =========================
for dd in dispositivos_ddwrt:
    if not any(
        d["ip"] == dd["ip"] or (
            d["mac"] != "desconhecido" and d["mac"] == dd["mac"]
        )
        for d in dispositivos
    ):
        dispositivos.append({
            "ip": dd["ip"],
            "nome": "desconhecido",
            "mac": dd["mac"],
            "fabricante": fabricante_por_mac(dd["mac"])
        })

# =========================
# Processamento central
# =========================

novos_dispositivos = []

for d in dispositivos:

    # =========================
    # Auto reconhecer host local
    # =========================
    hostname = (d.get("nome") or "").lower()
    mac = (d.get("mac") or "").lower()
    ip = d.get("ip") or ""

    if (
        ip == host_local["ip"]
        or mac == host_local["mac"]
        or hostname == host_local["hostname"]
    ):
        d["tipo"] = "computador_conhecido"

        # Corrigir MAC local automaticamente
        if d["mac"] == "desconhecido":
            d["mac"] = host_local["mac"]

        d["fabricante"] = "local"
        d["risco_base"] = 1
        d["risco"] = 1

        # Persistência
        if d["mac"] != "desconhecido":
            if d["mac"] not in historico:
                historico[d["mac"]] = {}

            historico[d["mac"]].update({
                "tipo": d["tipo"],
                "primeira_vista": historico[d["mac"]].get(
                    "primeira_vista",
                    agora
                ),
                "ultima_vista": agora,
                "frequencia": historico[d["mac"]].get(
                    "frequencia",
                    0
                ) + 1
            })

        print("[DEBUG] Host local classificado corretamente:", d["ip"])

        continue

        # Corrigir MAC se necessário
        if d["mac"] == "desconhecido":
            d["mac"] = obter_mac_por_ip(d["ip"])

        # Persistência
        if d["mac"] != "desconhecido":
            if d["mac"] not in historico:
                historico[d["mac"]] = {}

            historico[d["mac"]].update({
                "tipo": d["tipo"],
                "primeira_vista": historico[d["mac"]].get(
                    "primeira_vista",
                    agora
                ),
                "ultima_vista": agora,
                "frequencia": historico[d["mac"]].get(
                    "frequencia",
                    0
                ) + 1
            })

        print("[DEBUG] Host local classificado corretamente:", d["ip"])

        continue

    # Corrigir MAC
    if d["mac"] == "desconhecido":
        d["mac"] = obter_mac_por_ip(d["ip"])

    # Corrigir fabricante
    if d["fabricante"].lower() in ["unknown", "desconhecido"]:
        fabricante_mac = fabricante_por_mac(d["mac"])

        if fabricante_mac != "desconhecido":
            d["fabricante"] = fabricante_mac

    # Verificar se é novo
    novo = (
        d["mac"] not in historico and
        d["mac"] != "desconhecido"
    )


    # Classificação
    if d["mac"] in historico:

        # Compatibilidade com histórico antigo
        if isinstance(historico[d["mac"]], str):
            historico[d["mac"]] = {
                "tipo": historico[d["mac"]],
                "primeira_vista": agora,
                "ultima_vista": agora,
                "frequencia": 1
            }

        d["tipo"] = historico[d["mac"]]["tipo"]

    else:
        tipo, risco_base = classificar_dispositivo(
            d["nome"],
            d["fabricante"],
            d["mac"],
            d["ip"],
            gateway
        )

        d["tipo"] = tipo
        d["risco_base"] = risco_base

        # Scan avançado se necessário
        if d["tipo"] == "desconhecido":
            tipo_detalhado = escanear_detalhado(d["ip"])

            if tipo_detalhado != "desconhecido":
                d["tipo"] = tipo_detalhado

    # Risco
    d["risco"] = max(
        d.get("risco_base", 0),
        calcular_risco(d, len(dispositivos))
    )

    # Registrar novo dispositivo
    if novo:
        novos_dispositivos.append({
            "ip": d["ip"],
            "nome": d["nome"],
            "mac": d["mac"],
            "fabricante": d["fabricante"],
            "tipo": d["tipo"],
            "risco": d["risco"],
            "timestamp": agora
        })

    # Atualizar histórico
    if d["mac"] != "desconhecido":
        if d["mac"] not in historico:
            historico[d["mac"]] = {}

        historico[d["mac"]].update({
            "tipo": d["tipo"],
            "primeira_vista": historico[d["mac"]].get(
                "primeira_vista",
                agora
            ),
            "ultima_vista": agora,
            "frequencia": historico[d["mac"]].get(
                "frequencia",
                0
            ) + 1
        })


# =========================
# Métricas
# =========================
ativos = len(dispositivos)
total_ips = 254
uso = (ativos / total_ips) * 100

desconhecidos = sum(
    1 for d in dispositivos
    if d["tipo"] == "desconhecido"
)

mac_randomizados = sum(
    1 for d in dispositivos
    if "privado" in d["fabricante"].lower()
)

risco_medio = round(
    sum(d["risco"] for d in dispositivos) / ativos,
    2
) if ativos > 0 else 0


# =========================
# Recomendação
# =========================
if uso < 50:
    recomendacao = "OK"
elif uso < 80:
    recomendacao = "ALERTA"
else:
    recomendacao = "CRÍTICO"


# =========================
# Saída principal
# =========================
print(f"\n[INFO] IPs ativos: {ativos}")
print(f"[INFO] Uso da rede: {round(uso, 2)} %")
print(f"[INFO] Risco médio: {risco_medio}/10")
print(f"[INFO] MACs randomizados: {mac_randomizados}")
print(f"[INFO] Dispositivos desconhecidos: {desconhecidos}")
print(f"[INFO] Recomendação: {recomendacao}")

# =========================
# Novos dispositivos
# =========================
if novos_dispositivos:
    print("\n[WARN] Novos dispositivos detectados:")

    for novo in novos_dispositivos:
        print(
            f'{novo["ip"]} → '
            f'{novo["mac"]} → '
            f'{novo["fabricante"]} → '
            f'{novo["tipo"]} → '
            f'Risco {novo["risco"]}/10'
        )


# =========================
# Saída detalhada
# =========================
print("\nDispositivos detectados:")

tipos = {}

for d in dispositivos:
    tipo = d["tipo"]
    tipos[tipo] = tipos.get(tipo, 0) + 1

    print(
        f'{d["ip"]} → '
        f'{d["nome"]} → '
        f'{d["fabricante"]} → '
        f'{d["mac"]} → '
        f'{tipo} → '
        f'Risco {d["risco"]}/10'
    )

# =========================
# Resumo por tipo
# =========================
print("\nResumo por tipo:")

for t, q in tipos.items():
    print(f"{t}: {q}")


# =========================
# Salvar histórico
# =========================
with open(historico_arquivo, "w") as f:
    json.dump(historico, f, indent=4)


# =========================
# Dados estruturados
# =========================
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
    "recomendacao": recomendacao,
    "dispositivos": dispositivos
}

# =========================
# Persistência local (SQLite)
# =========================

if CONFIG.get("usar_sqlite", True):
    from storage.sqlite import iniciar_banco, salvar_scan

    iniciar_banco()
    salvar_scan(dados)

    print("\nDados salvos no SQLite com sucesso!")

# PDF opcional via config.json
if CONFIG.get("gerar_pdf", False):
    try:
        from reports.pdf_report import gerar_pdf
        gerar_pdf(dados)
        print("Relatório PDF gerado com sucesso!")
    except Exception as e:
        print("Erro ao gerar PDF:", e)
# =========================
# Geração de gráficos
# =========================
try:
    from reports.graph_generator import gerar_graficos
    gerar_graficos(dados)
    print("Gráficos gerados em reports/graficos/")
except Exception as e:
    print("Erro ao gerar gráficos:", e)
