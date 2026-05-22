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


from core.mac_cache import fabricante_por_mac_com_cache

def fabricante_por_mac(mac):
    """Retorna fabricante do MAC usando cache local (offline)"""
    return fabricante_por_mac_com_cache(mac, use_internet=False)

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
def detectar_ambiente_por_rede(gateway_ip=None, rede=None):
    """
    Detecta o ambiente baseado no gateway ou rede
    """
    # Mapeamento de gateways para ambientes
    ambientes_conhecidos = {
        "192.168.0.1": "Casa",
        "192.168.1.1": "Trabalho",
        "10.0.0.1": "Escritório",
        "192.168.15.1": "Cliente_A",
        "192.168.100.1": "Cliente_B",
    }
    
    if gateway_ip and gateway_ip in ambientes_conhecidos:
        return ambientes_conhecidos[gateway_ip]
    
    # Fallback: perguntar ao usuário
    print(f"\n📡 Rede detectada: {rede}")
    print(f"🌐 Gateway: {gateway_ip}")
    print("Ambientes disponíveis: Casa, Trabalho, Escritorio, Cliente_A, Cliente_B")
    
    ambiente = input("Digite o nome do ambiente (Enter para 'Casa'): ").strip()
    if not ambiente:
        ambiente = "Casa"
    
    # Salvar no config.json para próxima vez
    config_path = "config.json"
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            config = json.load(f)
    else:
        config = {}
    
    config["ambiente"] = ambiente
    config["gateway_ip"] = gateway_ip
    
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    
    return ambiente
def detectar_ambiente_por_rede(gateway_ip=None, rede=None, ssid=None):
    """
    Detecta o ambiente baseado no gateway ou SSID da rede
    """
    # Mapeamento de gateways para ambientes
    ambientes_conhecidos = {
        "192.168.0.1": "Casa",
        "192.168.1.1": "Trabalho",
        "10.0.0.1": "Escritório",
        "192.168.15.1": "Cliente_A",
        "192.168.100.1": "Cliente_B",
    }
    
    if gateway_ip and gateway_ip in ambientes_conhecidos:
        return ambientes_conhecidos[gateway_ip]
    
    # Se não conhece, pergunta ao usuário
    print(f"\n🌐 Nova rede detectada: {rede}")
    print(f"📡 Gateway: {gateway_ip}")
    print(f"📶 SSID: {ssid}")
    
    ambiente = input("Digite o nome do ambiente (ou Enter para 'Casa'): ").strip()
    if not ambiente:
        ambiente = "Casa"
    
    # Salvar no config para próxima vez
    config_path = "config.json"
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            config = json.load(f)
    else:
        config = {}
    
    config["ambiente"] = ambiente
    config["gateway_ip"] = gateway_ip
    
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    
    return ambiente
