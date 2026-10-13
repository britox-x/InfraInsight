"""Configuração das portas incluídas na detecção padrão de serviços."""

import os

TOP_100_PORTS = (
    80,
    23,
    443,
    21,
    22,
    25,
    3389,
    110,
    445,
    139,
    143,
    53,
    135,
    3306,
    8080,
    1723,
    111,
    995,
    993,
    5900,
    1025,
    587,
    8888,
    199,
    1720,
    465,
    548,
    113,
    81,
    6001,
    10000,
    514,
    5060,
    179,
    1026,
    2000,
    8443,
    8000,
    32768,
    554,
    26,
    1433,
    49152,
    2001,
    515,
    8008,
    49154,
    1027,
    5666,
    646,
    5000,
    5631,
    631,
    49153,
    8081,
    2049,
    88,
    79,
    5800,
    106,
    2121,
    1110,
    49155,
    6000,
    513,
    990,
    5357,
    427,
    49156,
    543,
    544,
    5101,
    144,
    7,
    389,
    8009,
    3128,
    444,
    9999,
    5009,
    7070,
    5190,
    3000,
    5432,
    3986,
    1900,
    13,
    1029,
    9,
    6646,
    5051,
    49157,
    1028,
    873,
    1755,
    2717,
    4899,
    9100,
    119,
    37,
)


def obter_portas_scan(env_value: str | None = None) -> tuple[int, ...]:
    """Retorna as portas configuradas ou a lista padrão, validando entrada."""
    configured = (
        os.getenv("INFRA_SCAN_PORTS") if env_value is None else env_value
    )
    if configured is None or not configured.strip():
        return TOP_100_PORTS

    try:
        ports = tuple(int(part.strip()) for part in configured.split(","))
    except ValueError as error:
        raise ValueError(
            "INFRA_SCAN_PORTS deve conter portas numéricas separadas por vírgula."
        ) from error
    if not ports or any(not 1 <= port <= 65535 for port in ports):
        raise ValueError(
            "Cada porta em INFRA_SCAN_PORTS deve estar entre 1 e 65535."
        )
    if len(set(ports)) != len(ports):
        raise ValueError("INFRA_SCAN_PORTS não deve conter portas duplicadas.")
    return ports
