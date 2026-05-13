def classificar_dispositivo(hostname, vendor, mac, ip, gateway=None):
    hostname = (hostname or "").lower()
    vendor = (vendor or "").lower()
    mac = (mac or "").lower()

    tipo = "desconhecido"
    risco = 6

    # Gateway principal
    if gateway and ip == gateway:
        return "roteador", 2

    # Infraestrutura TP-Link / Switch / AP
    if any(x in vendor for x in ["tp-link", "ubiquiti", "intelbras"]):
        return "switch/rede", 2

    # Nokia / modem / gateway ISP
    if any(x in vendor for x in ["nokia", "huawei", "zte"]):
        return "roteador", 2


    # Computador conhecido (hostname)
    if any(x in hostname for x in [
        "matheus",
        "desktop",
        "notebook",
        "pc",
        "550xcj",
        "linux",
        "ubuntu"
    ]):
        return "computador_conhecido", 2

    # Computador por fabricante de placa de rede
    if any(x in vendor for x in [
        "intel",
        "realtek",
        "qualcomm",
        "killer",
        "broadcom"
    ]):
        return "computador", 3


    # Android / celular
    if any(x in hostname for x in ["android", "motorola", "samsung", "xiaomi", "iphone"]):
        return "celular", 3

    # MAC randomizado/local
    try:
        primeiro_byte = int(mac.split(":")[0], 16)

        if primeiro_byte & 2:
            return "dispositivo_privado", 4

    except Exception:
        pass

    # IoT
    if any(x in vendor for x in ["amazon", "google", "tuya", "espressif"]):
        return "iot", 5

    return tipo, risco
