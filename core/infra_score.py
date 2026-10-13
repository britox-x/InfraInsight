"""Cálculo do InfraScore com fatores base e risco de CVEs."""

from collections.abc import Mapping
import json
from typing import Any

ADMIN_PORTS = {22, 3389, 5900, 8080, 8443}


def pontuar_vulnerabilidades(scan_data: Mapping[str, Any]) -> int:
    """Calcula S uma vez por CVE/instância, limitado ao máximo de 3."""
    weights = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}
    findings = []
    for vulnerability in scan_data.get("software_vulnerabilities", []):
        if not isinstance(vulnerability, Mapping):
            continue
        scope = (
            vulnerability.get("software_instance_id")
            or vulnerability.get("asset_id")
            or "global"
        )
        findings.append((str(scope), vulnerability))
    for device_index, device in enumerate(scan_data.get("dispositivos", [])):
        if not isinstance(device, Mapping):
            continue
        asset = (
            device.get("asset_id")
            or device.get("mac")
            or device.get("ip")
            or f"device:{device_index}"
        )
        for service in device.get("services", []):
            if not isinstance(service, Mapping):
                continue
            scope = service.get("software_instance_id") or (
                f"{asset}:{service.get('port')}:{service.get('protocol')}:"
                f"{service.get('product')}:{service.get('version')}"
            )
            findings.extend(
                (str(scope), cve)
                for cve in service.get("cves", [])
                if isinstance(cve, Mapping)
            )

    seen: set[tuple[str, str]] = set()
    score = 0
    for scope, vulnerability in findings:
        cve_id = vulnerability.get("cve_id") or vulnerability.get("id")
        key = (scope, str(cve_id)) if cve_id else None
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        severity = str(vulnerability.get("severity") or "").upper()
        score += weights.get(severity, 0)
    return min(3, score)


def _open_ports(device: Mapping[str, Any]) -> set[int]:
    ports = device.get("open_ports", [])
    if isinstance(ports, str):
        try:
            ports = json.loads(ports)
        except (TypeError, ValueError):
            ports = []
    try:
        return {int(port) for port in ports}
    except (TypeError, ValueError):
        return set()


def _derive_base_factors(scan_data: Mapping[str, Any]) -> dict[str, bool]:
    devices = [
        device
        for device in scan_data.get("dispositivos", [])
        if isinstance(device, Mapping)
    ]
    port_sets = [(device, _open_ports(device)) for device in devices]
    total = scan_data.get("ips_ativos", len(devices))
    unknown = scan_data.get("desconhecidos", 0)
    try:
        many_unknown = total > 0 and unknown / total > 0.3
    except (TypeError, ZeroDivisionError):
        many_unknown = False
    gateway_ip = scan_data.get("gateway")
    gateway_http = any(
        ports & {80, 443}
        and (
            (gateway_ip and device.get("ip") == gateway_ip)
            or str(device.get("tipo", "")).lower()
            in {"gateway", "roteador", "router"}
        )
        for device, ports in port_sets
    )
    return {
        "telnet": any(23 in ports for _, ports in port_sets),
        "rtsp": any(554 in ports for _, ports in port_sets),
        "unknown": bool(many_unknown),
        "gateway_http": gateway_http,
        "admin_ports": any(ports & ADMIN_PORTS for _, ports in port_sets),
    }


def calcular_infra_score(
    scan_data: Mapping[str, Any] | None = None,
    *,
    telnet: int | bool | None = None,
    rtsp: int | bool | None = None,
    unknown: int | bool | None = None,
    gateway_http: int | bool | None = None,
    admin_ports: int | bool | None = None,
    cve_criticas: int = 0,
    cve_altas: int = 0,
    cve_medias: int = 0,
) -> float:
    """Calcula min(10, ((2T + 2Q + U + H + A + S) / 7) * 10)."""
    data = scan_data or {}
    factors = _derive_base_factors(data)
    values = {
        "telnet": telnet,
        "rtsp": rtsp,
        "unknown": unknown,
        "gateway_http": gateway_http,
        "admin_ports": admin_ports,
    }
    factors.update(
        {
            name: bool(value) if value is not None else factors[name]
            for name, value in values.items()
        }
    )
    base = (
        2 * factors["telnet"]
        + 2 * factors["rtsp"]
        + factors["unknown"]
        + factors["gateway_http"]
        + factors["admin_ports"]
    )
    software_score = min(
        3,
        3 * max(0, cve_criticas)
        + 2 * max(0, cve_altas)
        + max(0, cve_medias)
        + pontuar_vulnerabilidades(data),
    )
    return min(10.0, ((base + software_score) / 7.0) * 10.0)
