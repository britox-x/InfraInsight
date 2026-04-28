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
        if vendor:
            return vendor
    except:
        pass

    prefixo = mac[:8].lower()

    vendors = {
        "24:4b:03": "Samsung",
        "5c:0f:fb": "Amino",
        "60:92:c8": "Roku",
        "78:3e:a1": "Nokia",
        "c8:fe:0f": "Rede/IoT"
    }

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
