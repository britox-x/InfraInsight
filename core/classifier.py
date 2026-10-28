# core/classifier.py
"""
Classificador de dispositivos — v3-conservador.

Princípios:
- MAC localmente administrado (aleatório) é EVIDÊNCIA, nunca tipo.
- Marca isolada ou porta isolada não prova o tipo: confiança baixa.
- Na dúvida, "desconhecido".

Escala de confiança (menor = mais confiável, igual às versões anteriores):
1 alta · 2 média · 3 baixa · 5 nenhuma.
"""

import re

CLASSIFICADOR_VERSAO = "v3-conservador"

CONF_ALTA = 1
CONF_MEDIA = 2
CONF_BAIXA = 3
CONF_NENHUMA = 5

_PLACEHOLDER_VENDORS = {"", "local", "unknown", "desconhecido", "n/a", "none"}

# Nomes que o resolvedor local do Linux devolve para o gateway.
# Não dizem nada sobre o aparelho, então não contam como hostname.
_HOSTNAMES_SEM_VALOR = {"_gateway", "_outbound"}


# ------------------------------------------------------------
# Normalização
# ------------------------------------------------------------
def normalizar_mac(mac):
    """Minúsculas e separador ':' (aceita '-')."""
    return str(mac or "").strip().lower().replace("-", ":")


def normalizar_hostname(hostname):
    """Remove sufixos locais de descoberta e placeholders de hostname."""
    normalized = str(hostname or "").strip().rstrip(".")
    if normalized.lower().endswith(".local"):
        normalized = normalized[:-6]
    return normalized.strip()


def formatar_hostname(hostname):
    """Formata hostname para exibição consistente em dashboard e relatórios."""
    return normalizar_hostname(hostname).replace("_", " ").strip()


def normalizar_fabricante(vendor):
    """Converte valores ausentes ou genéricos do scanner para string vazia."""
    normalized = str(vendor or "").strip()
    if normalized.casefold() in _PLACEHOLDER_VENDORS:
        return ""
    return normalized


def mac_localmente_administrado(mac):
    """Retorna se o bit U/L do primeiro octeto do MAC está definido."""
    try:
        first_octet_text = normalizar_mac(mac).split(":")[0]
        if len(first_octet_text) != 2:
            return False
        first_octet = int(first_octet_text, 16)
    except (AttributeError, IndexError, ValueError):
        return False
    return bool(first_octet & 0x02)


def vendor_tem(vendor, *marcas):
    """
    True se alguma marca aparece no INÍCIO de uma palavra do fabricante.
    Evita falsos positivos de substring (ex.: 'hp' dentro de outra palavra).
    Atenção: 'intel' também casa com 'intelbras'; trate Intelbras antes.
    """
    v = str(vendor or "").casefold()
    return any(
        re.search(rf"(?<![a-z0-9]){re.escape(m.casefold())}", v) for m in marcas
    )


def _eh_gateway(ip, gateway_ip):
    if gateway_ip:
        return ip == gateway_ip
    # Fallback por convenção, só quando o IP real do gateway não foi informado.
    return ip.endswith(".1") or ip.endswith(".254")


# ------------------------------------------------------------
# Classificação principal
# ------------------------------------------------------------
def classificar_dispositivo(
    hostname="", vendor="", ip="", mac="", open_ports=None, gateway_ip=None
):
    """
    Classifica o dispositivo com base nas evidências disponíveis.

    Args:
        hostname: nome do dispositivo
        vendor: fabricante (OUI)
        ip: endereço IP
        mac: endereço MAC
        open_ports: lista de portas abertas
        gateway_ip: IP real do gateway (opcional, mais confiável que '.1')

    Returns:
        tuple: (tipo, confianca) — confiança: 1 melhor, 5 pior
    """
    open_ports = list(open_ports or [])
    hostname = normalizar_hostname(hostname).lower()
    if hostname in _HOSTNAMES_SEM_VALOR:
        hostname = ""
    vendor = normalizar_fabricante(vendor)
    ip = ip or ""
    mac = normalizar_mac(mac)
    gateway = _eh_gateway(ip, gateway_ip)

    # Roku: porta 8060 (ECP) ou OUI conhecido.
    # Confirme o OUI 60:92:c8 na sua base antes de confiar só nele.
    if mac.startswith("60:92:c8") or 8060 in open_ports:
        return "roku", CONF_ALTA

    # Sem hostname nem portas, não inferir tipo a partir de MAC aleatório
    # ou de fabricante não identificado.
    if (
        not hostname
        and not open_ports
        and (mac_localmente_administrado(mac) or not vendor)
    ):
        return "desconhecido", CONF_NENHUMA

    if vendor_tem(vendor, "amino"):
        return "smarttv", CONF_MEDIA

    if vendor_tem(vendor, "tp-link", "tplink"):
        if gateway:
            return "roteador", CONF_ALTA
        if any(x in hostname for x in ["router", "gateway", "archer", "tplink", "deco"]):
            return "roteador", CONF_ALTA
        if 80 in open_ports or 443 in open_ports or 53 in open_ports:
            # TP-Link também fabrica câmeras e tomadas com web: confiança média.
            return "roteador", CONF_MEDIA
        return "switch/rede", CONF_BAIXA

    if vendor_tem(vendor, "cisco"):
        if gateway:
            return "roteador", CONF_ALTA
        return "infraestrutura", CONF_MEDIA

    # Intelbras ANTES de Intel (o prefixo 'intel' casaria com 'intelbras').
    if vendor_tem(vendor, "intelbras"):
        # Intelbras fabrica câmeras IP, roteadores e APs. RTSP (554) é
        # evidência forte de câmera.
        if 554 in open_ports:
            return "camera", CONF_MEDIA
        return "infraestrutura", CONF_BAIXA

    if vendor_tem(vendor, "intel", "dell", "lenovo", "asus", "acer", "hp", "hewlett"):
        return "computador_conhecido", CONF_MEDIA

    # Marca isolada não prova tipo: essas marcas fazem celular, TV e mais.
    if vendor_tem(vendor, "samsung", "lg", "sony", "philips"):
        return "smarttv", CONF_BAIXA

    if vendor_tem(vendor, "apple"):
        if "iphone" in hostname or "ipad" in hostname:
            return "mobile/ios", CONF_MEDIA
        if "apple tv" in hostname:
            return "smarttv", CONF_MEDIA
        return "mobile/apple", CONF_BAIXA

    if vendor_tem(vendor, "espressif", "tuya", "wemos", "node mcu"):
        return "iot", CONF_BAIXA
    if vendor_tem(vendor, "hikvision", "dahua"):
        return "camera", CONF_BAIXA

    if vendor_tem(vendor, "xiaomi", "motorola", "huawei", "oneplus", "google"):
        return "mobile/android", CONF_BAIXA

    if vendor_tem(vendor, "brother", "epson", "canon", "kyocera"):
        return "impressora", CONF_MEDIA

    if vendor_tem(vendor, "vmware", "virtualbox", "qemu"):
        return "virtual", CONF_MEDIA

    # Evidência por porta isolada: confiança baixa
    # (NAS, roteadores e câmeras também têm 445, 22 e 80).
    if 554 in open_ports:
        return "camera", CONF_BAIXA
    if 5353 in open_ports:
        return "smart_device", CONF_BAIXA
    if 445 in open_ports or 3389 in open_ports:
        return "computador_windows", CONF_BAIXA
    if 22 in open_ports and 80 in open_ports:
        return "computador_linux", CONF_BAIXA

    return "desconhecido", CONF_NENHUMA


# ------------------------------------------------------------
# Contagem e níveis
# ------------------------------------------------------------
def tipo_eh_desconhecido(tipo):
    """'desconhecido' e variantes como 'mobile/desconhecido' (scans antigos)."""
    t = str(tipo or "desconhecido").strip().lower()
    return t == "desconhecido" or t.endswith("/desconhecido")


def contar_dispositivos_desconhecidos(dispositivos):
    """Conta dispositivos sem uma classe determinada pelo classificador."""
    return sum(
        1 for device in dispositivos if tipo_eh_desconhecido(device.get("tipo"))
    )


def nivel_identificacao(dispositivo):
    """Nível de identificação para exibição (aqui 3 = melhor, só para UI)."""
    fab = normalizar_fabricante(dispositivo.get("fabricante"))
    fabricante_util = bool(fab) and not fab.casefold().startswith("mac local")
    if fabricante_util:
        return {"nivel": 3, "texto": "Conhecido", "cor": "🟢"}
    if dispositivo.get("open_ports"):
        return {"nivel": 2, "texto": "Parcialmente identificado", "cor": "🟡"}
    return {"nivel": 1, "texto": "Desconhecido", "cor": "🔴"}


# ------------------------------------------------------------
# Auxiliares
# ------------------------------------------------------------
def identificar_tipo_por_mac(mac):
    """Tipo pelo prefixo MAC (OUI) para fabricantes fixos conhecidos."""
    mac = normalizar_mac(mac)
    if not mac or mac == "desconhecido":
        return None

    tipos_por_mac = {
        "50:3e:aa": "switch/rede",
        "3c:84:6a": "roteador",
        "a0:0f:37": "infraestrutura",
        "8c:b0:e9": "computador_conhecido",
    }
    for prefixo, tipo in tipos_por_mac.items():
        if mac.startswith(prefixo):
            return tipo
    return None