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
