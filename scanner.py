import subprocess
import re
import json
import os
from datetime import datetime

# =========================
# Detectar rede automaticamente
# =========================
ip_local = subprocess.check_output("hostname -I", shell=True).decode().split()[0]
base = ".".join(ip_local.split(".")[:3])
rede = base + ".0/24"

print("Rede detectada:", rede)

# =========================
# Executar Nmap (com MAC e fabricante)
# =========================
resultado = subprocess.check_output(
    ["sudo", "nmap", "-sn", "-PR", "-n", rede]
).decode()

linhas = resultado.split("\n")
dispositivos = []

# =========================
# Parsing
# =========================
for linha in linhas:

    # Novo host encontrado
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
                "mac": "N/A",
                "fabricante": "desconhecido"
            })

    # Captura MAC + fabricante
    elif "MAC Address" in linha:
        match = re.search(r"MAC Address: ([\w:]+) \((.+)\)", linha)
        if match and dispositivos:
            dispositivos[-1]["mac"] = match.group(1)
            dispositivos[-1]["fabricante"] = match.group(2)

# =========================
# Remover duplicados e inválidos
# =========================
ips_unicos = {}

for d in dispositivos:
    ip = d["ip"]
    ultimo = int(ip.split(".")[-1])

    if ultimo != 0 and ultimo != 255:
        ips_unicos[ip] = d

dispositivos = list(ips_unicos.values())

# ordenar IPs
dispositivos.sort(key=lambda x: list(map(int, x["ip"].split("."))))

# =========================
# Classificação melhorada
# =========================
def classificar(nome, fabricante, ip):
    nome = nome.lower()
    fabricante = fabricante.lower()

    if ip.endswith(".1") or ip.endswith(".254"):
        return "roteador"

    if "samsung" in fabricante or "xiaomi" in fabricante:
        return "celular"

    if "intel" in fabricante or "dell" in fabricante or "lenovo" in fabricante:
        return "computador"

    if "hikvision" in fabricante or "intelbras" in fabricante:
        return "câmera"

    if "printer" in nome:
        return "impressora"

    return "desconhecido"

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
    tipo = classificar(d["nome"], d["fabricante"], d["ip"])
    tipos[tipo] = tipos.get(tipo, 0) + 1

    print(f'{d["ip"]} → {d["nome"]} → {d["fabricante"]} → {tipo}')

print("\nResumo por tipo:")
for t, q in tipos.items():
    print(f"{t}: {q}")

# =========================
# Salvar histórico
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

# =========================
# CSV
# =========================
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
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

url = "http://localhost:8086"

# ⚠️ COLOQUE SEU TOKEN CORRETO (SEM ESPAÇO E SEM >)
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

url = "http://localhost:8086"

# 🔐 pega o token do ambiente (SEGURANÇA)
token = os.getenv("INFLUX_TOKEN")

org = "tcc"
bucket = "monitoramento"

try:
    client = InfluxDBClient(url=url, token=token, org=org)
    write_api = client.write_api(write_options=SYNCHRONOUS)

    ponto = Point("rede") \
        .field("ips_ativos", ativos) \
        .field("uso", float(uso))

    write_api.write(bucket=bucket, record=ponto)

    print("Dados enviados para InfluxDB!")

except Exception as e:
    print("Erro ao enviar para InfluxDB:", e)
