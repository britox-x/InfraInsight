def identificar_tipo_por_mac(mac):
    """
    Identifica o tipo do dispositivo baseado no MAC real
    """
    if not mac or mac == "desconhecido":
        return None
    
    # Prefixos de MAC conhecidos (OUI)
    tipos_por_mac = {
        # Switches TP-Link
        "50:3e:aa": "switch/rede",
        # Roteadores TP-Link
        "3c:84:6a": "roteador",
        "d8:0d:17": "roteador",
        # Cisco
        "a0:0f:37": "infraestrutura",
        "00:0f:37": "infraestrutura",
        # Intel (PCs)
        "8c:b0:e9": "computador_conhecido",
        "00:15:5d": "computador_conhecido",
        # Dispositivos móveis (MAC randomizado)
        "46:ed:16": "mobile/android",
        "62:9f:82": "mobile/desconhecido",
        "a6:2f:0a": "mobile/desconhecido",
    }
    
    mac_upper = mac.upper()
    for prefixo, tipo in tipos_por_mac.items():
        if mac_upper.startswith(prefixo.upper()):
            return tipo
    
    return None
