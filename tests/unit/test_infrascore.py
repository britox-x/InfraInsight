"""Testes da fórmula normalizada do InfraScore."""

import pytest

from core.infra_score import calcular_infra_score


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
