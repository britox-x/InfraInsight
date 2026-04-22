import subprocess
import re

rede = "192.168.1.0/24"

resultado = subprocess.check_output(["nmap", "-sn", rede]).decode()

# pega apenas linhas de "scan report"
linhas = resultado.split("\n")

ips = []

for linha in linhas:
    if "Nmap scan report for" in linha:
        # extrai IP dentro de parênteses ou direto
        match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", linha)
        if match:
            ips.append(match.group(1))
        else:
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)", linha)
            if match:
                ips.append(match.group(1))

ativos = len(ips)
total_ips = 254
uso = (ativos / total_ips) * 100

print("IPs ativos:", ativos)
print("Uso da rede:", round(uso, 2), "%")

if uso > 80:
    recomendacao = "Expandir sub-rede"
elif uso > 60:
    recomendacao = "Monitorar crescimento"
else:
    recomendacao = "OK"

print("Recomendação:", recomendacao)
