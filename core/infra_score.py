"""Cálculo do InfraScore com fatores base e risco de CVEs."""

from collections.abc import Mapping
import json
from typing import Any

ADMIN_PORTS = {22, 3389, 5900, 8080, 8443}
SCORE_WEIGHTS = {"T": 2, "Q": 2, "U": 1, "H": 1, "A": 1, "S": 3}


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
        80 in ports
        and 443 not in ports
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


def decompor_infra_score(
    scan_data: Mapping[str, Any],
    *,
    scan_services: bool,
    cve_lookup: bool,
    cve_coverage_complete: bool,
    classification_observed: bool = True,
) -> dict[str, Any]:
    """Retorna os componentes observáveis e o limite inferior do InfraScore."""
    factors = _derive_base_factors(scan_data)
    total = scan_data.get("ips_ativos", 0)
    unknown = scan_data.get("desconhecidos", 0)
    try:
        unknown_ratio = unknown / total if total else 0.0
    except (TypeError, ZeroDivisionError):
        unknown_ratio = 0.0

    software_score = pontuar_vulnerabilidades(scan_data)
    values: dict[str, tuple[str, int, Any, str, bool]] = {
        "T": (
            "Telnet exposto",
            SCORE_WEIGHTS["T"],
            factors["telnet"],
            "Sim" if factors["telnet"] else "Não",
            scan_services,
        ),
        "Q": (
            "RTSP exposto",
            SCORE_WEIGHTS["Q"],
            factors["rtsp"],
            "Sim" if factors["rtsp"] else "Não",
            scan_services,
        ),
        "U": (
            "Dispositivos desconhecidos (>30%)",
            SCORE_WEIGHTS["U"],
            factors["unknown"],
            f"{unknown}/{total} ({unknown_ratio:.0%}); fator "
            f"{int(factors['unknown'])}",
            classification_observed,
        ),
        "H": (
            "HTTP sem HTTPS detectado no gateway",
            SCORE_WEIGHTS["H"],
            factors["gateway_http"],
            "Sim" if factors["gateway_http"] else "Não",
            scan_services,
        ),
        "A": (
            "Porta administrativa exposta",
            SCORE_WEIGHTS["A"],
            factors["admin_ports"],
            "Sim" if factors["admin_ports"] else "Não",
            scan_services,
        ),
        "S": (
            "CVEs conhecidas",
            f"até {SCORE_WEIGHTS['S']}",
            software_score,
            str(software_score),
            scan_services and cve_lookup and cve_coverage_complete,
        ),
    }
    components = []
    weighted_observed = 0.0
    observed_count = 0
    for key, (name, weight, value, display_value, observed) in values.items():
        contribution = (
            value if key == "S" and observed
            else weight * value if observed
            else None
        )
        if observed:
            weighted_observed += contribution
            observed_count += 1
        components.append(
            {
                "key": key,
                "name": name,
                "weight": weight,
                "status": "observado" if observed else "não verificado",
                "value": value if observed else None,
                "display_value": display_value if observed else "—",
                "contribution": contribution,
            }
        )

    return {
        "score": min(10.0, weighted_observed * 10.0 / 7.0)
        if observed_count
        else None,
        "components": components,
        "complete": observed_count == len(values),
    }


def score_minimo_observado(components: list[Mapping[str, Any]]) -> float | None:
    """Calcula o score apenas quando todos os componentes observados têm valor."""
    observed = [
        component
        for component in components
        if component.get("status") == "observado"
    ]
    if not observed:
        return None

    weighted_score = 0.0
    for component in observed:
        contribution = component.get("contribution")
        if contribution is None:
            value = component.get("value")
            if value is None:
                return None
            try:
                contribution = (
                    float(value)
                    if component.get("key") == "S"
                    else float(component["weight"]) * float(value)
                )
            except (KeyError, TypeError, ValueError):
                return None
        try:
            weighted_score += float(contribution)
        except (TypeError, ValueError):
            return None

    return min(10.0, weighted_score * 10.0 / 7.0)


def cobertura_infra_score(components: list[Mapping[str, Any]]) -> float:
    """Retorna a fração do peso total correspondente a componentes observados."""
    total_weight = sum(SCORE_WEIGHTS.values())
    verified_weight = sum(
        SCORE_WEIGHTS.get(str(component.get("key")), 0)
        for component in components
        if component.get("status") == "observado"
    )
    return verified_weight / total_weight if total_weight else 0.0


def formatar_infra_score(
    score: float | None, coverage: float | None
) -> str:
    """Formata o score persistido sem substituir dados ausentes por zero."""
    if score is None or coverage is None:
        return "—"
    score_text = f"{score:.1f}".replace(".", ",")
    return f"≥ {score_text}/10 (cobertura {coverage:.0%})"


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
