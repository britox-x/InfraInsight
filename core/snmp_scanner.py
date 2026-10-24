"""Consultas SNMPv2c somente leitura para enriquecimento do inventário."""

import asyncio
import logging
import re
import threading
from collections.abc import Mapping, Sequence
from typing import Any

from core.classifier import classificar_dispositivo, normalizar_hostname

logger = logging.getLogger(__name__)

SYSTEM_OIDS = {
    "description": "1.3.6.1.2.1.1.1.0",
    "object_id": "1.3.6.1.2.1.1.2.0",
    "uptime": "1.3.6.1.2.1.1.3.0",
    "contact": "1.3.6.1.2.1.1.4.0",
    "name": "1.3.6.1.2.1.1.5.0",
    "location": "1.3.6.1.2.1.1.6.0",
}

VENDOR_OIDS = {
    "1.3.6.1.4.1.9": "Cisco",
    "1.3.6.1.4.1.2636": "Juniper",
    "1.3.6.1.4.1.171": "D-Link",
    "1.3.6.1.4.1.14988": "MikroTik",
    "1.3.6.1.4.1.11863": "TP-Link",
    "1.3.6.1.4.1.2011": "Huawei",
    "1.3.6.1.4.1.8072": "Linux/SNMP",
    "1.3.6.1.4.1.11": "HP",
    "1.3.6.1.4.1.311": "Microsoft",
    "1.3.6.1.4.1.2": "IBM",
    "1.3.6.1.4.1.253": "Xerox",
}

_DESCRIPTION_TYPES = (
    (re.compile(r"\b(router|roteador|gateway)\b"), "roteador"),
    (re.compile(r"\b(switch|comutador)\b"), "switch/rede"),
    (re.compile(r"\b(printer|impressora|print server)\b"), "impressora"),
    (re.compile(r"\b(camera|ipcam|cctv)\b"), "camera"),
    (re.compile(r"\b(access[ -]?point|wireless ap)\b"), "access_point"),
)


def identificar_fabricante_snmp(object_id: str) -> str | None:
    """Identifica OIDs de fabricante por prefixo de enterprise exato."""
    value = str(object_id or "").strip()
    numeric_oid = value if re.fullmatch(r"[0-9.]+", value) else None
    if numeric_oid is None:
        enterprise_match = re.search(r"(?:^|::)enterprises\.(\d+)", value)
        if enterprise_match:
            numeric_oid = f"1.3.6.1.4.1.{enterprise_match.group(1)}"
    if numeric_oid is None:
        return None

    numeric_oid = numeric_oid.lstrip(".")
    for prefix, vendor in VENDOR_OIDS.items():
        if numeric_oid == prefix or numeric_oid.startswith(f"{prefix}."):
            return vendor
    return None


def classificar_descricao_snmp(description: str) -> str | None:
    normalized = str(description or "").casefold()
    for pattern, device_type in _DESCRIPTION_TYPES:
        if pattern.search(normalized):
            return device_type
    return None


def integrar_dados_snmp(
    device: dict[str, Any], snmp_data: Mapping[str, Any]
) -> None:
    """Enriquece um dispositivo descoberto sem substituir evidência melhor."""
    if not snmp_data:
        return

    object_id = str(snmp_data.get("object_id") or "")
    description = str(snmp_data.get("description") or "")
    hostname = normalizar_hostname(snmp_data.get("name"))
    vendor = identificar_fabricante_snmp(object_id)
    evidence = device.get("classificacao_evidencia")
    if not isinstance(evidence, list):
        evidence = []
        device["classificacao_evidencia"] = evidence

    if hostname and not device.get("hostname"):
        device["hostname"] = hostname
        evidence.append(f"SNMP sysName: {hostname}")
    if vendor and (
        not device.get("fabricante")
        or str(device["fabricante"]).casefold() == "desconhecido"
    ):
        device["fabricante"] = vendor
        evidence.append(f"SNMP sysObjectID: {vendor}")
    if description:
        evidence.append(f"SNMP sysDescr: {description[:200]}")

    effective_vendor = vendor or str(device.get("fabricante") or "")
    candidate_type, candidate_confidence = classificar_dispositivo(
        hostname=hostname or device.get("hostname", ""),
        vendor=effective_vendor,
        ip=str(device.get("ip") or ""),
        mac=str(device.get("mac") or ""),
        open_ports=device.get("open_ports", []),
    )
    confidence = device.get("classificacao_confianca")
    if candidate_type != "desconhecido" and (
        confidence is None or candidate_confidence < confidence
    ):
        device["tipo"] = candidate_type
        device["classificacao_confianca"] = candidate_confidence

    description_type = classificar_descricao_snmp(description)
    confidence = device.get("classificacao_confianca")
    if description_type and (confidence is None or confidence >= 2):
        device["tipo"] = description_type
        device["classificacao_confianca"] = 2

    device["snmp_info"] = {
        key: snmp_data.get(key)
        for key in (
            "object_id",
            "description",
            "uptime",
            "contact",
            "location",
        )
        if snmp_data.get(key) not in (None, "")
    }


async def _consultar_host(
    snmp_engine: Any,
    ip: str,
    community: str,
    port: int,
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> tuple[str, dict[str, str] | None]:
    from pysnmp.hlapi.v3arch.asyncio import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        UdpTransportTarget,
        get_cmd,
    )

    async with semaphore:
        target = await UdpTransportTarget.create(
            (ip, port), timeout=timeout, retries=0
        )
        response = await get_cmd(
            snmp_engine,
            CommunityData(community, mpModel=1),
            target,
            ContextData(),
            *(ObjectType(ObjectIdentity(oid)) for oid in SYSTEM_OIDS.values()),
        )
        error_indication, error_status, _, var_binds = response
        if error_indication or error_status:
            logger.debug(
                "Sem resposta SNMP utilizável em %s: %s%s",
                ip,
                error_indication or "",
                f" ({error_status.prettyPrint()})" if error_status else "",
            )
            return ip, None

        values: dict[str, str] = {}
        for key, var_bind in zip(SYSTEM_OIDS, var_binds):
            value = var_bind[1]
            if value is None or not value.isValue:
                continue
            values[key] = value.prettyPrint()
        if not values.get("description") and not values.get("object_id"):
            return ip, None
        return ip, values


async def _consultar_hosts(
    hosts: Sequence[str],
    community: str,
    port: int,
    timeout: float,
    concurrency: int,
) -> dict[str, dict[str, str]]:
    from pysnmp.hlapi.v3arch.asyncio import SnmpEngine

    engine = SnmpEngine()
    semaphore = asyncio.Semaphore(concurrency)
    try:
        results = await asyncio.gather(
            *(
                _consultar_host(
                    engine, ip, community, port, timeout, semaphore
                )
                for ip in hosts
            )
        )
    finally:
        engine.close_dispatcher()
    return {ip: values for ip, values in results if values}


def consultar_hosts_snmp(
    hosts: Sequence[str],
    community: str,
    *,
    port: int = 161,
    timeout: float = 1.5,
    concurrency: int = 16,
) -> dict[str, dict[str, str]]:
    """Consulta somente leitura sysDescr/sysObjectID e atributos básicos."""
    community = str(community or "").strip()
    if not community:
        raise ValueError(
            "A comunidade SNMP deve ser configurada explicitamente"
        )
    if not 1 <= port <= 65535:
        raise ValueError("A porta SNMP deve estar entre 1 e 65535")
    if timeout <= 0:
        raise ValueError("O timeout SNMP deve ser positivo")
    if concurrency < 1:
        raise ValueError("A concorrência SNMP deve ser pelo menos 1")

    normalized_hosts: list[str] = []
    seen_hosts: set[str] = set()
    for host in hosts or ():
        if host is None:
            continue
        candidate = str(host).strip()
        if not candidate or candidate in seen_hosts:
            continue
        seen_hosts.add(candidate)
        normalized_hosts.append(candidate)

    if not normalized_hosts:
        return {}

    coroutine = _consultar_hosts(
        normalized_hosts, community, port, timeout, concurrency
    )
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)

    result: dict[str, dict[str, str]] = {}
    error: Exception | None = None

    def _run_in_thread() -> None:
        nonlocal result, error
        try:
            result = asyncio.run(coroutine)
        except Exception as exc:  # pragma: no cover - exercised via async loop path
            error = exc

    worker = threading.Thread(target=_run_in_thread)
    worker.start()
    worker.join()
    if error is not None:
        raise error
    return result
