def classificar_dispositivo(nome, fabricante, mac, ip, gateway, known_host_keywords=None, trusted_vendors=None):
    """
    Classificação contextual de dispositivos InfraInsight
    Retorna: (tipo, risco_base)
    """

    nome = (nome or "").lower()
    fabricante = (fabricante or "").lower()
    mac = (mac or "").lower()
    ip = (ip or "").strip()
    gateway = (gateway or "").strip()

    known_host_keywords = known_host_keywords or []
    trusted_vendors = trusted_vendors or []

    # Gateway principal
    if gateway and ip == gateway:
        return "roteador", 1

    # Host conhecido
    if any(keyword.lower() in nome for keyword in known_host_keywords):
        return "computador_conhecido", 1

    # Vendors confiáveis
    if any(vendor.lower() in fabricante for vendor in trusted_vendors):
        return "switch/rede", 2

    # Regras específicas
    if "roku" in fabricante:
        return "smarttv/streaming", 3

    if "bilian" in fabricante:
        return "iot/rede", 4

    if "intelbras" in fabricante:
        return "switch/ap", 2

    if "hikvision" in fabricante:
        return "camera", 4

    if "epson" in fabricante:
        return "impressora", 2

    if "amino" in fabricante:
        return "tv_box", 4

    if "nokia" in fabricante:
        return "roteador", 1

    if "tp-link" in fabricante:
        return "switch/rede", 2

    # MAC randomizado
    if mac.startswith(("02:", "06:", "0a:", "0e:")):
        return "privado/randomizado", 6

    # Heurística por hostname
    if any(keyword in nome for keyword in ["tv", "roku", "firestick", "chromecast"]):
        return "smarttv/streaming", 4

    if any(keyword in nome for keyword in ["cam", "camera", "hik"]):
        return "camera", 4

    if any(keyword in nome for keyword in ["printer", "epson", "hp"]):
        return "impressora", 3

    # Fallback
    return "desconhecido", 6
