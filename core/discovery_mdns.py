# core/discovery_mdns.py
"""
Descoberta mDNS (Bonjour/Zeroconf) como FONTE DE EVIDÊNCIA.

- Escuta anúncios por alguns segundos e só depois resolve os serviços,
  em paralelo, fora do callback (callbacks não devem bloquear).
- Agrupa por IPv4 (a rede do scanner), guardando hostname, tipos de serviço
  e propriedades.
- evidencias_mdns() converte isso em evidências com confiança, sem chutar:
  quem decide o tipo final é o classificador.

Tudo que vem da rede é dado NÃO CONFIÁVEL: escape/sanitize ao exibir
(dashboard, PDF, mensagens do Telegram).
"""

import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from zeroconf import IPVersion, ServiceBrowser, ServiceStateChange, Zeroconf

# Mesma escala do classificador: menor = mais confiável.
CONF_ALTA, CONF_MEDIA, CONF_BAIXA = 1, 2, 3

# Tipos de serviço consultados (sem a meta-consulta _services._dns-sd._udp,
# que devolve TIPOS de serviço e não instâncias).
SERVICOS_PADRAO = [
    "_ipp._tcp.local.",
    "_ipps._tcp.local.",
    "_printer._tcp.local.",
    "_pdl-datastream._tcp.local.",
    "_googlecast._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_workstation._tcp.local.",
    "_hap._tcp.local.",
    "_http._tcp.local.",
]

_MAX_VALOR = 100  # limita o tamanho de cada propriedade guardada


def _txt(b):
    if b is None:
        return ""
    if isinstance(b, bytes):
        return b.decode("utf-8", "ignore")[:_MAX_VALOR]
    return str(b)[:_MAX_VALOR]


def _resolver(zc, par, resolucao_ms):
    tipo, nome = par
    try:
        info = zc.get_service_info(tipo, nome, timeout=resolucao_ms)
    except Exception:
        return None
    if not info:
        return None
    ips = info.parsed_addresses(IPVersion.V4Only)  # só IPv4
    if not ips:
        return None
    props = {_txt(k): _txt(v) for k, v in (info.properties or {}).items()}
    return {
        "ips": ips,
        "tipo_servico": tipo,
        "nome": str(nome)[:_MAX_VALOR],
        "hostname": str(info.server or "")[:_MAX_VALOR],
        "propriedades": props,
    }


def coletar_mdns(escuta_s=4.0, resolucao_ms=1500, servicos=None, max_workers=8):
    """
    Retorna {ip_v4: {"hostnames": [...], "servicos": [...], "nomes": [...],
                     "propriedades": {tipo_servico: {k: v}}}}.
    Duração aproximada: escuta_s + até resolucao_ms (resolução em paralelo).
    """
    vistos = set()
    lock = threading.Lock()

    def ao_mudar(zeroconf, service_type, name, state_change):
        if state_change is not ServiceStateChange.Removed:
            with lock:
                vistos.add((service_type, name))

    zc = Zeroconf()
    try:
        browser = ServiceBrowser(
            zc, list(servicos or SERVICOS_PADRAO), handlers=[ao_mudar]
        )
        time.sleep(escuta_s)
        browser.cancel()
        with lock:
            pares = list(vistos)
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            infos = list(ex.map(lambda p: _resolver(zc, p, resolucao_ms), pares))
    finally:
        zc.close()

    por_ip = {}
    for info in infos:
        if not info:
            continue
        for ip in info["ips"]:
            d = por_ip.setdefault(
                ip,
                {"hostnames": set(), "servicos": set(), "nomes": set(), "propriedades": {}},
            )
            if info["hostname"]:
                d["hostnames"].add(info["hostname"])
            d["servicos"].add(info["tipo_servico"])
            d["nomes"].add(info["nome"])
            d["propriedades"][info["tipo_servico"]] = info["propriedades"]

    return {
        ip: {
            "hostnames": sorted(d["hostnames"]),
            "servicos": sorted(d["servicos"]),
            "nomes": sorted(d["nomes"]),
            "propriedades": d["propriedades"],
        }
        for ip, d in por_ip.items()
    }


# ------------------------------------------------------------
# Evidências (sem chutar)
# ------------------------------------------------------------
_RE_IOS = re.compile(r"(?<![a-z])(iphone|ipad)")
_RE_ANDROID = re.compile(r"(?<![a-z])(android|galaxy|pixel)")
_RE_MAC = re.compile(r"macbook|imac|mac ?mini|mac ?pro")

# prefixo do tipo de serviço -> (tipo, confiança, motivo)
_POR_SERVICO = {
    "_ipp._tcp": ("impressora", CONF_MEDIA, "serviço de impressão mDNS (IPP)"),
    "_ipps._tcp": ("impressora", CONF_MEDIA, "serviço de impressão mDNS (IPPS)"),
    "_printer._tcp": ("impressora", CONF_MEDIA, "serviço de impressão mDNS (LPD)"),
    "_pdl-datastream._tcp": ("impressora", CONF_MEDIA, "serviço de impressão mDNS (raw)"),
    # TVs, caixas de som, Apple TV e outros também anunciam isto: confiança baixa.
    "_googlecast._tcp": ("smart_device", CONF_BAIXA, "receptor Google Cast"),
    "_airplay._tcp": ("smart_device", CONF_BAIXA, "receptor AirPlay"),
    "_raop._tcp": ("smart_device", CONF_BAIXA, "receptor AirPlay (áudio)"),
    # Avahi anuncia isto por padrão em desktops Linux.
    "_workstation._tcp": ("computador_linux", CONF_BAIXA, "serviço _workstation (Avahi)"),
    "_hap._tcp": ("iot", CONF_BAIXA, "acessório HomeKit"),
}


def _sem_sufixo(tipo_servico):
    return tipo_servico.removesuffix(".local.").removesuffix(".local")


def evidencias_mdns(info):
    """Lista de evidências {tipo, confianca, motivo}; melhores primeiro."""
    if not info:
        return []
    ev = []

    for serv in info.get("servicos", []):
        regra = _POR_SERVICO.get(_sem_sufixo(serv))
        if regra:
            ev.append({"tipo": regra[0], "confianca": regra[1], "motivo": regra[2]})

    # Refinamentos por propriedades (modelo anunciado), se existirem.
    for serv, props in (info.get("propriedades") or {}).items():
        blob = " ".join(props.values()).lower()
        base = _sem_sufixo(serv)
        if base in ("_airplay._tcp", "_raop._tcp"):
            if "appletv" in blob:
                ev.append({"tipo": "smarttv", "confianca": CONF_MEDIA, "motivo": "modelo Apple TV anunciado"})
            elif _RE_MAC.search(blob):
                ev.append({"tipo": "computador_conhecido", "confianca": CONF_MEDIA, "motivo": "modelo Mac anunciado"})
        if base == "_googlecast._tcp" and "chromecast" in props.get("md", "").lower():
            ev.append({"tipo": "chromecast", "confianca": CONF_MEDIA, "motivo": "modelo Chromecast anunciado"})

    # Hostname anunciado (evidência explícita, ao contrário de prefixo de MAC).
    for h in info.get("hostnames", []):
        h = _sem_sufixo(h).lower()
        if _RE_IOS.search(h):
            ev.append({"tipo": "mobile/ios", "confianca": CONF_MEDIA, "motivo": "hostname iPhone/iPad"})
        elif _RE_ANDROID.search(h):
            ev.append({"tipo": "mobile/android", "confianca": CONF_BAIXA, "motivo": "hostname Android/Galaxy/Pixel"})

    return sorted(ev, key=lambda e: e["confianca"])


def melhor_evidencia(info):
    ev = evidencias_mdns(info)
    return ev[0] if ev else None

