import subprocess
from mac_vendor_lookup import MacLookup

mac_lookup = MacLookup()

try:
    mac_lookup.update_vendors()
except:
    pass


def obter_mac_por_ip(ip):
    try:
        arp_saida = subprocess.check_output(["arp", "-a"]).decode(errors="ignore")

        for linha in arp_saida.splitlines():
            if f"({ip})" in linha:
                for parte in linha.split():
                    if ":" in parte and len(parte) >= 17:
                        return parte.lower()
    except:
        pass

    return "desconhecido"

def fabricante_por_mac(mac):
    if mac == "desconhecido":
        return "desconhecido"

    try:
        vendor = mac_lookup.lookup(mac)
        if vendor and vendor.lower() != "unknown":
            return vendor
    except:
        pass

    prefixo = mac[:8].lower()

    vendors = {
        # TVs / Streaming
        "24:4b:03": "Samsung",
        "60:92:c8": "Roku",
        "5c:0f:fb": "Amino",

        # Infraestrutura
        "78:3e:a1": "Nokia",
        "3c:84:6a": "TP-Link",
        "a0:0f:37": "Cisco",
        "80:85:44": "Intelbras",
        "24:fe:9a": "CyberTAN",
        "50:3e:aa": "TP-Link",

        # Celulares
        "fc:a9:f5": "Xiaomi",
        "e0:80:6b": "Xiaomi",
        "10:a2:d3": "Apple",
        "e4:f3:c4": "Samsung",

        # Computadores
        "44:a3:bb": "Intel",
        "74:70:fd": "Intel",
        "98:bd:80": "Intel",
        "00:d7:6d": "Intel",

        # Genérico
        "c8:fe:0f": "Rede/IoT",
    }

    # MAC privado/randomizado
    if len(mac) > 1 and mac[1].lower() in ["2", "6", "a", "e"]:
        return "Privado/Randomizado"

    return vendors.get(prefixo, "desconhecido")

def escanear_detalhado(ip):
    try:
        detalhe = subprocess.check_output(
            ["sudo", "nmap", "-O", "-sV", "--top-ports", "20", ip],
            stderr=subprocess.DEVNULL,
            timeout=35
        ).decode(errors="ignore").lower()

        if "android" in detalhe:
            return "celular"
        if "airplay" in detalhe or "airtunes" in detalhe or "rtsp" in detalhe:
            return "smarttv/streaming"
        if "printer" in detalhe or "ipp" in detalhe:
            return "impressora"
        if "mikrotik" in detalhe or "routeros" in detalhe:
            return "roteador"
        if "windows" in detalhe:
            return "computador"
        if "linux" in detalhe:
            return "iot/linux"

    except subprocess.TimeoutExpired:
        return "timeout"

    except:
        pass

    return "desconhecido"
import re


# =========================
# Detectar sub-rede automaticamente
# =========================
def detectar_rede():
    try:
        ip_local = subprocess.check_output(
            ["hostname", "-I"]
        ).decode().split()[0]

        base = ".".join(ip_local.split(".")[:3])

        return f"{base}.0/24"

    except:
        return "desconhecido"


# =========================
# Detectar nome da rede Wi-Fi (SSID)
# =========================
def obter_nome_wifi():
    try:
        resultado = subprocess.check_output(
            ["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],
            stderr=subprocess.DEVNULL
        ).decode(errors="ignore")

        for linha in resultado.splitlines():
            if linha.startswith("yes:"):
                return linha.split("yes:")[1].strip()

    except:
        pass

    return "Cabeada/Ethernet"


# =========================
# Detectar gateway/roteador principal
# =========================
def obter_gateway():
    try:
        rota = subprocess.check_output(
            ["ip", "route"]
        ).decode(errors="ignore")

        match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", rota)

        if match:
            return match.group(1)

    except:
        pass

    return "desconhecido"
