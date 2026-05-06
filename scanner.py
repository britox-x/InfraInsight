import subprocess
import re
import json
import os
from datetime import datetime
from dotenv import load_dotenv
from mac_vendor_lookup import MacLookup
from modulos.utils import (
    obter_mac_por_ip,
    fabricante_por_mac,
    escanear_detalhado,
    detectar_rede,
    obter_nome_wifi,
    obter_gateway
)

# =========================
# Carregar variáveis de ambiente
# =========================
load_dotenv()

mac_lookup = MacLookup()

try:
    mac_lookup.update_vendors()
except:
    pass

# =========================
# Configurações
# =========================
historico_arquivo = "historico_dispositivos.json"
AMBIENTE = "Casa"

# =========================
# Detectar rede
# =========================
rede = detectar_rede()
nome_wifi = obter_nome_wifi()
gateway = obter_gateway()
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
# Classificação central
# =========================
def classificar(nome, fabricante, ip):
    nome = (nome or "").lower()
    fabricante = (fabricante or "").lower()

    # Roteador
    if ip.endswith(".1") or ip.endswith(".254"):
        return "roteador"

    # TV / decoder
    if "amino" in fabricante:
        return "tv/decoder"

    # Streaming / Smart TV
    if any(x in fabricante for x in [
        "streaming", "roku", "chromecast",
        "samsung electronics", "amazon"
    ]):
        return "smarttv/streaming"

    # IoT / Rede
    if "bilian" in fabricante:
        return "iot/rede"

    # MAC randomizado
    if "privado" in fabricante or "randomizado" in fabricante:
        return "dispositivo_privado"

    # Celular
    if any(x in fabricante for x in [
        "samsung", "xiaomi", "motorola",
        "apple", "lg"
    ]):
        return "celular"

    if any(x in nome for x in [
        "android", "galaxy", "iphone",
        "redmi", "moto"
    ]):
        return "celular"

    # Switch / AP
    if any(x in fabricante for x in [
        "cisco", "tp-link", "ubiquiti",
        "intelbras"
    ]):
        return "switch/rede"

    # Computador
    if any(x in fabricante for x in [
        "intel", "dell", "lenovo",
        "asus", "acer"
    ]):
        return "computador"

    # Impressora
    if any(x in fabricante for x in [
        "epson", "brother", "hp"
    ]):
        return "impressora"

    # Câmera
    if any(x in fabricante for x in [
        "hikvision", "dahua", "camera"
    ]):
        return "câmera"

    return "desconhecido"


# =========================
# Score de risco
# =========================
def calcular_risco(dispositivo, novo):
    risco = 0

    fabricante = dispositivo["fabricante"].lower()
    nome = dispositivo["nome"].lower()
    tipo = dispositivo["tipo"].lower()

    if novo:
        risco += 3

    if "privado" in fabricante or "randomizado" in fabricante:
        risco += 2

    if fabricante == "desconhecido":
        risco += 2

    if tipo == "desconhecido":
        risco += 2

    if nome == "desconhecido":
        risco += 1

    return min(risco, 10)


# =========================
# Executar Nmap
# =========================
resultado = subprocess.check_output(
    ["sudo", "nmap", "-sn", "-PR", "-R", rede]
).decode()

linhas = resultado.split("\n")
dispositivos = []

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
# Processamento central
# =========================
novos_dispositivos = []

for d in dispositivos:

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
        d["tipo"] = classificar(
            d["nome"],
            d["fabricante"],
            d["ip"]
        )

        # Scan avançado se necessário
        if d["tipo"] == "desconhecido":
            tipo_detalhado = escanear_detalhado(d["ip"])

            if tipo_detalhado != "desconhecido":
                d["tipo"] = tipo_detalhado



    # Risco
    d["risco"] = calcular_risco(d, novo)

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
# Salvar JSON
# =========================
with open("dados.json", "a") as f:
    f.write(json.dumps(dados) + "\n")


# =========================
# Salvar CSV
# =========================
arquivo_csv = "dados.csv"

if not os.path.exists(arquivo_csv):
    with open(arquivo_csv, "w") as f:
        f.write(
            "timestamp,ambiente,wifi,subrede,gateway,"
            "ips_ativos,uso,risco_medio,desconhecidos,"
            "mac_randomizados,novos_dispositivos,recomendacao\n"
        )

with open(arquivo_csv, "a") as f:
    f.write(
        f"{agora},{AMBIENTE},{nome_wifi},{rede},"
        f"{gateway},{ativos},{round(uso,2)},"
        f"{risco_medio},{desconhecidos},"
        f"{mac_randomizados},{len(novos_dispositivos)},"
        f"{recomendacao}\n"
    )

print("\nDados salvos com sucesso!")


# =========================
# Enviar para InfluxDB
# =========================
try:
    from influxdb_client import InfluxDBClient, Point
    from influxdb_client.client.write_api import SYNCHRONOUS

    url = os.getenv("INFLUX_URL")
    token = os.getenv("INFLUX_TOKEN")
    org = os.getenv("INFLUX_ORG")
    bucket = os.getenv("INFLUX_BUCKET")

    if all([url, token, org, bucket]):

        client = InfluxDBClient(
            url=url,
            token=token,
            org=org
        )

        write_api = client.write_api(
            write_options=SYNCHRONOUS
        )

        ponto = Point("rede") \
            .tag("ambiente", AMBIENTE) \
            .tag("wifi", nome_wifi) \
            .tag("subrede", rede) \
            .tag("gateway", gateway) \
            .field("ips_ativos", ativos) \
            .field("uso", float(uso)) \
            .field("novos_dispositivos", len(novos_dispositivos)) \
            .field("desconhecidos", desconhecidos) \
            .field("mac_randomizados", mac_randomizados) \
            .field("risco_medio", float(risco_medio))

        write_api.write(
            bucket=bucket,
            org=org,
            record=ponto
        )

        print("Dados enviados para InfluxDB!")

    else:
        print("InfluxDB não configurado (.env incompleto).")

except Exception as e:
    print("Erro ao enviar para InfluxDB:", e)
