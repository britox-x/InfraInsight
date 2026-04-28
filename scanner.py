import subprocess
import re
import json
import os
from datetime import datetime
from dotenv import load_dotenv
from mac_vendor_lookup import MacLookup
from modulos.utils import obter_mac_por_ip, fabricante_por_mac, escanear_detalhado


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
# Histórico persistente por MAC
# =========================
historico_arquivo = "historico_dispositivos.json"

if os.path.exists(historico_arquivo):
    with open(historico_arquivo, "r") as f:
        historico = json.load(f)
else:
    historico = {}

# =========================
# Classificação central
# =========================
def classificar(nome, fabricante, ip):
    nome = nome.lower()
    fabricante = fabricante.lower()

    # Roteador
    if ip.endswith(".1") or ip.endswith(".254"):
        return "roteador"

    # TV / decoder
    if "amino" in fabricante:
        return "tv/decoder"

    # Streaming / Smart TV
    if any(x in fabricante for x in ["streaming", "roku", "chromecast", "samsung electronics"]):
        return "smarttv/streaming"

    # Celular
    if any(x in fabricante for x in ["samsung", "xiaomi", "motorola", "apple", "lg"]):
        return "celular"

    if any(x in nome for x in ["android", "galaxy", "iphone", "redmi", "moto"]):
        return "celular"

    # Switch / AP
    if any(x in fabricante for x in ["cisco", "tp-link", "ubiquiti", "intelbras"]):
        return "switch/rede"

    # Computador
    if any(x in fabricante for x in ["intel", "dell", "lenovo", "asus", "acer"]):
        return "computador"

    # Impressora
    if any(x in fabricante for x in ["epson", "brother", "hp"]):
        return "impressora"

    # Câmera
    if any(x in fabricante for x in ["hikvision", "dahua", "camera"]):
        return "câmera"

    return "desconhecido"


# =========================
# Detectar rede automaticamente
# =========================
ip_local = subprocess.check_output("hostname -I", shell=True).decode().split()[0]
base = ".".join(ip_local.split(".")[:3])
rede = base + ".0/24"

print("Rede detectada:", rede)

# =========================
# Executar Nmap (mais completo)
# =========================
resultado = subprocess.check_output(
    ["sudo", "nmap", "-sn", "-PR", "-R", rede]
).decode()

linhas = resultado.split("\n")
dispositivos = []

# =========================
# Parsing
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
# Remover duplicados
# =========================
ips_unicos = {}

for d in dispositivos:
    ip = d["ip"]
    ultimo = int(ip.split(".")[-1])

    if ultimo not in [0, 255]:
        ips_unicos[ip] = d

dispositivos = list(ips_unicos.values())

# Ordenar IP
dispositivos.sort(key=lambda x: list(map(int, x["ip"].split("."))))

# =========================
# Refinamento por ARP + Histórico + Scan
# =========================
for d in dispositivos:

    # Corrigir MAC
    if d["mac"] == "desconhecido":
        d["mac"] = obter_mac_por_ip(d["ip"])

    # Corrigir fabricante
    if d["fabricante"].lower() in ["unknown", "desconhecido"]:
        fabricante_mac = fabricante_por_mac(d["mac"])

        if fabricante_mac != "desconhecido":
            d["fabricante"] = fabricante_mac

    # Histórico
    if d["mac"] in historico:
        d["tipo"] = historico[d["mac"]]

    else:
        d["tipo"] = classificar(d["nome"], d["fabricante"], d["ip"])

        # Scan avançado apenas se ainda desconhecido
        if d["tipo"] == "desconhecido":
            tipo_detalhado = escanear_detalhado(d["ip"])

            if tipo_detalhado != "desconhecido":
                d["tipo"] = tipo_detalhado

        historico[d["mac"]] = d["tipo"]


# =========================
# Cálculo de uso
# =========================
ativos = len(dispositivos)
total_ips = 254
uso = (ativos / total_ips) * 100

print("\nIPs ativos:", ativos)
print("Uso da rede:", round(uso, 2), "%")

# =========================
# Recomendação
# =========================
if uso > 80:
    recomendacao = "Expandir sub-rede (possível saturação)"
elif uso > 60:
    recomendacao = "Monitorar crescimento"
else:
    recomendacao = "OK"

print("Recomendação:", recomendacao)

# =========================
# Saída detalhada
# =========================
print("\nDispositivos detectados:")

tipos = {}

for d in dispositivos:
    tipo = d["tipo"]
    tipos[tipo] = tipos.get(tipo, 0) + 1

    print(f'{d["ip"]} → {d["nome"]} → {d["fabricante"]} → {d["mac"]} → {tipo}')

print("\nResumo por tipo:")
for t, q in tipos.items():
    print(f"{t}: {q}")

# =========================
# Salvar histórico
# =========================
with open(historico_arquivo, "w") as f:
    json.dump(historico, f, indent=4)

# =========================
# Salvar métricas
# =========================
agora = datetime.now().isoformat()

dados = {
    "timestamp": agora,
    "ips_ativos": ativos,
    "uso": round(uso, 2),
    "recomendacao": recomendacao
}

# JSON
with open("dados.json", "a") as f:
    f.write(json.dumps(dados) + "\n")

# CSV
arquivo_csv = "dados.csv"

if not os.path.exists(arquivo_csv):
    with open(arquivo_csv, "w") as f:
        f.write("timestamp,ips_ativos,uso,recomendacao\n")

with open(arquivo_csv, "a") as f:
    f.write(f"{agora},{ativos},{round(uso,2)},{recomendacao}\n")

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

        client = InfluxDBClient(url=url, token=token, org=org)
        write_api = client.write_api(write_options=SYNCHRONOUS)

        ponto = Point("rede") \
            .field("ips_ativos", ativos) \
            .field("uso", float(uso))

        write_api.write(bucket=bucket, record=ponto)

        print("Dados enviados para InfluxDB!")

    else:
        print("InfluxDB não configurado (.env incompleto).")

except Exception as e:
    print("Erro ao enviar para InfluxDB:", e)
