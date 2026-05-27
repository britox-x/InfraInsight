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
    # TP-Link
    # =========================
    if "tp-link" in vendor:
        # Verifica se é gateway (IP .1 ou .254)
        if ip.endswith(".1") or ip.endswith(".254"):
            return "roteador", 1
        
        # Verifica por hostnames de roteador
        if any(x in hostname for x in ["router", "gateway", "archer", "tplink", "deco"]):
            return "roteador", 1
        
        # Verifica portas comuns de roteador
        if 80 in open_ports or 443 in open_ports or 53 in open_ports:
            return "roteador", 1
        
        # Padrão para outros dispositivos TP-Link
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
    if any(x in vendor for x in ["brother", "epson", "canon", "kyocera", "hp"]):
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
    # Fallback
    # =========================
    return "desconhecido", 5


def identificar_tipo_por_mac(mac):
    """
    Identifica o tipo do dispositivo baseado no prefixo MAC (OUI)
    """
    if not mac or mac == "desconhecido":
        return None
    
    # Prefixos de MAC conhecidos
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
    """
    Classifica dispositivos com MAC randomizado baseado em padrões
    """
    mac_prefix = mac[:8].upper() if mac else ""
    hostname = (hostname or "").lower()
    
    # Padrões de MAC randomizado por fabricante/família
    # Android: 46:, 4e:, 5e:, 6a:, 2a:, 3a:, 7a:, 8a:, 9a:
    android_prefixes = ['46:', '4E:', '5E:', '6A:', '2A:', '3A:', '7A:', '8A:', '9A:', 'AE:', 'BE:', 'CE:', 'DE:', 'EE:', 'FE:']
    
    # iOS: 2a:, 4a:, 6a:, 8a:, 9a:, ba:, ca:, da:, ea:, fa:
    ios_prefixes = ['2A:', '4A:', '6A:', '8A:', '9A:', 'BA:', 'CA:', 'DA:', 'EA:', 'FA:']
    
    # Windows: 1e:, 3e:, 5e:, 7e:, 9e:, be:, de:, fe:
    windows_prefixes = ['1E:', '3E:', '5E:', '7E:', '9E:', 'BE:', 'DE:', 'FE:']
    
    # Por hostname
    if 'android' in hostname or 'xiaomi' in hostname or 'samsung' in hostname:
        return "mobile/android", 2
    if 'iphone' in hostname or 'ipad' in hostname or 'apple' in hostname:
        return "mobile/ios", 2
    if 'windows' in hostname or 'win' in hostname:
        return "mobile/windows", 2
    
    # Por MAC
    for prefix in android_prefixes:
        if mac_prefix.startswith(prefix):
            return "mobile/android", 2
    for prefix in ios_prefixes:
        if mac_prefix.startswith(prefix):
            return "mobile/ios", 2
    for prefix in windows_prefixes:
        if mac_prefix.startswith(prefix):
            return "mobile/windows", 2
    
def classificar_por_porta(open_ports):
    """
    Classifica dispositivo baseado nas portas abertas
    """
    if not open_ports:
        return None
    
    # Mapeamento de portas para tipo provável
    portas_para_tipo = {
        554: "camera_ip",      # RTSP
        8008: "camera_ip",     # Câmera IP
        8000: "camera_ip",
        9100: "impressora",    # JetDirect
        515: "impressora",     # LPD
        1883: "iot_mqtt",      # MQTT
        8883: "iot_mqtt",
        1900: "smart_device",  # UPnP
        5353: "smart_device",  # mDNS
        8200: "smart_tv",      # UPnP Media
        8009: "chromecast",    # Google Cast
        7000: "tv",            # UPnP TV
        5000: "nas",           # Synology/QNAP
        8088: "router",        # Router admin
        5001: "nas_https",     # NAS HTTPS
        32400: "plex",         # Plex Media
        5050: "iot_hub",       # IoT Hub
    }
    
    for port, tipo in portas_para_tipo.items():
        if port in open_ports:
            return tipo
    
    # Combinações de portas
    if 22 in open_ports and 80 in open_ports:
        return "linux_server"
    if 3389 in open_ports:
        return "windows_server"
    
    return None

    # Fallback
    return "mobile/desconhecido", 3
def classificar_dispositivo_randomizado(mac, hostname=""):
    """
    Classifica dispositivos com MAC randomizado baseado em padrões
    """
    mac_prefix = mac[:8].upper() if mac else ""
    hostname = (hostname or "").lower()
    
    # Padrões de MAC randomizado por fabricante/família
    android_prefixes = ['46:', '4E:', '5E:', '6A:', '2A:', '3A:', '7A:', '8A:', '9A:', 'AE:', 'BE:', 'CE:', 'DE:', 'EE:', 'FE:']
    ios_prefixes = ['2A:', '4A:', '6A:', '8A:', '9A:', 'BA:', 'CA:', 'DA:', 'EA:', 'FA:']
    windows_prefixes = ['1E:', '3E:', '5E:', '7E:', '9E:', 'BE:', 'DE:', 'FE:']
    
    # Por hostname
    if 'android' in hostname or 'xiaomi' in hostname or 'samsung' in hostname:
        return "mobile/android", 2
    if 'iphone' in hostname or 'ipad' in hostname or 'apple' in hostname:
        return "mobile/ios", 2
    if 'windows' in hostname or 'win' in hostname:
        return "mobile/windows", 2
    
    # Por MAC
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

def nivel_identificacao(dispositivo):
    """Classifica nível de identificação do dispositivo"""
    # Conhecido: fabricante identificado
    if dispositivo.get('fabricante') not in ['desconhecido', 'Unknown', 'local']:
        return {"nivel": 3, "texto": "Conhecido", "cor": "🟢"}
    
    # Parcial: serviço/porta identificada
    if dispositivo.get('open_ports'):
        return {"nivel": 2, "texto": "Parcialmente identificado", "cor": "🟡"}
    
    # Desconhecido
    return {"nivel": 1, "texto": "Desconhecido", "cor": "🔴"}
