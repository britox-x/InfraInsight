# core/classifier.py

def classificar_dispositivo(hostname="", vendor="", ip="", mac="", open_ports=None):
    """
    Classifica o dispositivo baseado em múltiplas informações
    
    Args:
        hostname: Nome do dispositivo
        vendor: Fabricante
        ip: Endereço IP
        mac: Endereço MAC
        open_ports: Lista de portas abertas
    
    Returns:
        tuple: (tipo, nivel_confianca)
    """
    if open_ports is None:
        open_ports = []
    
    hostname = (hostname or "").lower()
    vendor = (vendor or "").lower()
    ip = ip or ""
    mac = mac or ""

    # =========================
    # ROKU (prioridade máxima - identificação por MAC ou porta)
    # =========================
    if mac.startswith('60:92:c8') or 8060 in open_ports:
        return "roku", 1

    
    # =========================
    # Amino (set-top box / TV Box)
    # =========================
    if "amino" in vendor:
        return "smarttv", 2
    
    # =========================
    # TP-Link
    # =========================
    if "tp-link" in vendor:
        if ip.endswith(".1") or ip.endswith(".254"):
            return "roteador", 1
        if any(x in hostname for x in ["router", "gateway", "archer", "tplink", "deco"]):
            return "roteador", 1
        if 80 in open_ports or 443 in open_ports or 53 in open_ports:
            return "roteador", 1
        return "switch/rede", 2
    
    # =========================
    # Cisco
    # =========================
    if "cisco" in vendor:
        if ip.endswith(".1") or ip.endswith(".254"):
            return "roteador", 1
        return "infraestrutura", 2
    
    # =========================
    # PCs (Intel, Dell, Lenovo, etc)
    # =========================
    if any(x in vendor for x in ["intel", "dell", "lenovo", "asus", "acer", "hp", "local"]):
        return "computador_conhecido", 1
    
    # =========================
    # Smart TVs
    # =========================
    if any(x in vendor for x in ["samsung", "lg", "sony", "philips"]):
        return "smarttv", 2
    
    # =========================
    # Apple
    # =========================
    if "apple" in vendor:
        if "iphone" in hostname or "ipad" in hostname:
            return "mobile/ios", 2
        if "apple tv" in hostname:
            return "smarttv", 2
        return "mobile/apple", 2
    
    # =========================
    # IoT
    # =========================
    if any(x in vendor for x in ["espressif", "tuya", "wemos", "node mcu"]):
        return "iot", 3
    if any(x in vendor for x in ["hikvision", "dahua"]):
        return "camera", 3
    
    # =========================
    # Android/Mobile
    # =========================
    if any(x in vendor for x in ["xiaomi", "motorola", "huawei", "oneplus", "google"]):
        return "mobile/android", 2
    
    # =========================
    # Impressoras
    # =========================
    if any(x in vendor for x in ["brother", "epson", "canon", "kyocera"]):
        return "impressora", 2
    
    # =========================
    # Virtualização
    # =========================
    if any(x in vendor for x in ["vmware", "virtualbox", "qemu"]):
        return "virtual", 2
    
    # =========================
    # MAC Randomizado (dispositivos móveis)
    # =========================
    if "privado" in vendor or "randomizado" in vendor:
        if mac.startswith(('46:', '4e:', '5e:', '6a:', '2a:')):
            return "mobile/android", 2
        return "mobile/desconhecido", 3
    
    # =========================
    # Porta 5353 (mDNS) - comum em smartphones e smart TVs
    # =========================
    if 5353 in open_ports:
        return "smart_device", 2
    
    # =========================
    # Windows (porta 445 ou 3389)
    # =========================
    if 445 in open_ports or 3389 in open_ports:
        return "computador_windows", 2
    
    # =========================
    # Linux (porta 22 e 80)
    # =========================
    if 22 in open_ports and 80 in open_ports:
        return "computador_linux", 2
    # =========================
    # Prefixos MAC específicos (Android)
    # =========================
    if mac.startswith(('56:6e:b6', '60:92:c8')):
        return "mobile/android", 2
    
    # =========================
    # Fabricantes desconhecidos que são móveis
    # =========================
    if vendor == "unknown" and (5353 in open_ports or 5555 in open_ports):
        return "mobile/android", 2

    # =========================
    # Prefixos MAC específicos (Android/Dispositivos móveis)
    # =========================
    if mac.startswith(('92:dd:a1', '2a:fa:67')):
        return "mobile/android", 2
    # =========================
    # Roku (porta 8060 aberta)
    # =========================
    if 8060 in open_ports:
        return "roku", 2
    
    # Prefixo MAC Roku
    if mac.startswith('60:92:c8'):
        return "roku", 2

    # =========================
    # Dispositivo com TTL 64 e sem portas (modo economia)
    # =========================
    if mac.startswith('72:fb:ad'):
        return "mobile/android", 2

    
    # =========================
    # Fallback
    # =========================
    if mac.startswith("72:fb:ad"):
        return "mobile/android", 2
    return "desconhecido", 5


def identificar_tipo_por_mac(mac):
    """Identifica o tipo do dispositivo baseado no prefixo MAC (OUI)"""
    if not mac or mac == "desconhecido":
        return None
    
    tipos_por_mac = {
        "50:3e:aa": "switch/rede",
        "3c:84:6a": "roteador",
        "a0:0f:37": "infraestrutura",
        "8c:b0:e9": "computador_conhecido",
    }
    
    mac_upper = mac.upper()
    for prefixo, tipo in tipos_por_mac.items():
        if mac_upper.startswith(prefixo.upper()):
            return tipo
    return None


def classificar_dispositivo_randomizado(mac, hostname=""):
    """Classifica dispositivos com MAC randomizado baseado em padrões"""
    mac_prefix = mac[:8].upper() if mac else ""
    hostname = (hostname or "").lower()
    
    android_prefixes = ['46:', '4E:', '5E:', '6A:', '2A:', '3A:', '7A:', '8A:', '9A:', 'AE:', 'BE:', 'CE:', 'DE:', 'EE:', 'FE:']
    ios_prefixes = ['2A:', '4A:', '6A:', '8A:', '9A:', 'BA:', 'CA:', 'DA:', 'EA:', 'FA:']
    windows_prefixes = ['1E:', '3E:', '5E:', '7E:', '9E:', 'BE:', 'DE:', 'FE:']
    
    if 'android' in hostname or 'xiaomi' in hostname:
        return "mobile/android", 2
    if 'iphone' in hostname or 'ipad' in hostname or 'apple' in hostname:
        return "mobile/ios", 2
    if 'windows' in hostname or 'win' in hostname:
        return "mobile/windows", 2
    
    for prefix in android_prefixes:
        if mac_prefix.startswith(prefix):
            return "mobile/android", 2
    for prefix in ios_prefixes:
        if mac_prefix.startswith(prefix):
            return "mobile/ios", 2
    for prefix in windows_prefixes:
        if mac_prefix.startswith(prefix):
            return "mobile/windows", 2
    
    return "mobile/desconhecido", 3


def classificar_por_porta(open_ports):
    """Classifica dispositivo baseado nas portas abertas"""
    if not open_ports:
        return None
    
    portas_para_tipo = {
        554: "camera_ip",
        8008: "camera_ip",
        8000: "camera_ip",
        9100: "impressora",
        515: "impressora",
        1883: "iot_mqtt",
        8883: "iot_mqtt",
        1900: "smart_device",
        5353: "smart_device",
        8200: "smart_tv",
        8009: "chromecast",
        7000: "tv",
        5000: "nas",
        8088: "router",
        5001: "nas_https",
        32400: "plex",
    }
    
    for port, tipo in portas_para_tipo.items():
        if port in open_ports:
            return tipo
    
    if 22 in open_ports and 80 in open_ports:
        return "linux_server"
    if 3389 in open_ports:
        return "windows_server"
    if 445 in open_ports:
        return "windows_computer"
    
    return None


def nivel_identificacao(dispositivo):
    """Classifica nível de identificação do dispositivo"""
    if dispositivo.get('fabricante') not in ['desconhecido', 'Unknown', 'local']:
        return {"nivel": 3, "texto": "Conhecido", "cor": "🟢"}
    if dispositivo.get('open_ports'):
        return {"nivel": 2, "texto": "Parcialmente identificado", "cor": "🟡"}
    return {"nivel": 1, "texto": "Desconhecido", "cor": "🔴"}
