"""Normalização de portas e serviços vindos do python-nmap."""

import json
from collections.abc import Mapping
from typing import Any

from core.fingerprint.cpe_mapper import mapear_cpe


def _confidence(value: Any) -> int | None:
    try:
        confidence = int(value)
    except (TypeError, ValueError):
        return None
    if not 0 <= confidence <= 100:
        return None
    return confidence * 10 if confidence <= 10 else confidence


def parsear_servicos_nmap(host: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Converte portas TCP/UDP abertas para serviços em formato estável."""
    services: list[dict[str, Any]] = []

    for protocol in ("tcp", "udp"):
        ports = host.get(protocol, {})
        if not isinstance(ports, Mapping):
            continue

        for port_value, port_info in ports.items():
            if (
                not isinstance(port_info, Mapping)
                or port_info.get("state") != "open"
            ):
                continue
            try:
                port = int(port_value)
            except (TypeError, ValueError):
                continue

            service_info = port_info.get("service", {})
            if not isinstance(service_info, Mapping):
                service_info = {}
            raw_cpe = service_info.get("cpe") or port_info.get("cpe")
            product = str(
                service_info.get("product") or port_info.get("product") or ""
            ).strip()
            version = str(
                service_info.get("version") or port_info.get("version") or ""
            ).strip()
            service_name = str(
                service_info.get("name") or port_info.get("name") or ""
            ).strip()
            cpe_value = raw_cpe
            if isinstance(cpe_value, (list, tuple)):
                cpe_value = next((value for value in cpe_value if value), None)
            cpe = str(cpe_value).strip() if cpe_value else None
            cpe_source = "nmap" if cpe else None
            if not cpe:
                cpe = mapear_cpe(product, version)
                cpe_source = "inferred"

            service: dict[str, Any] = {
                "port": port,
                "protocol": protocol,
                "service": service_name or None,
                "product": product or None,
                "version": version or None,
                "cpe": cpe,
                "cpe_source": cpe_source if cpe else None,
                "confidence": _confidence(
                    service_info.get("conf", port_info.get("conf"))
                ),
                "evidence": json.dumps(
                    port_info, ensure_ascii=False, default=str
                ),
            }
            services.append(service)

    return services
