"""Testes da fórmula normalizada do InfraScore."""

import pytest

from core.infra_score import (
    calcular_infra_score,
    decompor_infra_score,
    score_minimo_observado,
)


def test_score_zero():
    assert (
        calcular_infra_score({"dispositivos": [{"open_ports": [80, 443]}]})
        == 0
    )


def test_score_sem_cve_usa_divisor_original():
    assert calcular_infra_score(
        telnet=1,
        rtsp=0,
        unknown=0,
        gateway_http=0,
        admin_ports=0,
    ) == pytest.approx(2.86, abs=0.01)


def test_score_completo_e_limitado_a_dez():
    assert (
        calcular_infra_score(
            telnet=1,
            rtsp=1,
            unknown=5,
            gateway_http=1,
            admin_ports=3,
            cve_criticas=10,
            cve_altas=10,
            cve_medias=10,
        )
        == 10.0
    )


def test_score_aplica_teto_de_tres_a_cves():
    assert calcular_infra_score(
        telnet=0,
        rtsp=0,
        unknown=0,
        gateway_http=0,
        admin_ports=0,
        cve_criticas=10,
    ) == pytest.approx(30 / 7)


def test_unknown_factor_uses_fraction_of_unknown_hosts():
    assert (
        calcular_infra_score(
            {
                "ips_ativos": 10,
                "desconhecidos": 2,
                "dispositivos": [],
            }
        )
        == 0
    )
    assert calcular_infra_score(
        {
            "ips_ativos": 10,
            "desconhecidos": 4,
            "dispositivos": [],
        }
    ) == pytest.approx(10 / 7)


@pytest.mark.parametrize(
    ("ports", "expected"),
    [
        ([80], True),
        ([80, 443], False),
        ([443], False),
        ([], False),
    ],
)
def test_h_detecta_http_no_gateway_sem_https(ports, expected):
    resultado = decompor_infra_score(
        {
            "gateway": "192.0.2.1",
            "ips_ativos": 1,
            "desconhecidos": 0,
            "dispositivos": [{
                "ip": "192.0.2.1",
                "tipo": "gateway",
                "open_ports": ports,
            }],
        },
        scan_services=True,
        cve_lookup=False,
        cve_coverage_complete=False,
    )

    component = next(item for item in resultado["components"] if item["key"] == "H")
    assert component["name"] == "HTTP sem HTTPS no gateway"
    assert component["value"] is expected


def test_score_minimo_observado_usa_apenas_componentes_com_valor():
    assert score_minimo_observado([{
        "key": "U",
        "status": "observado",
        "weight": 1,
        "value": 1,
        "contribution": 1,
    }]) == pytest.approx(10 / 7)
    assert score_minimo_observado([{
        "key": "U",
        "status": "observado",
    }]) is None
