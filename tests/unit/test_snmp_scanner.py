import asyncio

import pytest
from pysnmp.hlapi.v3arch import asyncio as pysnmp_asyncio
from pysnmp.hlapi.v3arch.asyncio import CommunityData
from pysnmp.proto.rfc1902 import Integer32, ObjectIdentifier, OctetString

import core.snmp_scanner as snmp_scanner
from core.snmp_scanner import (
    classificar_descricao_snmp,
    consultar_hosts_snmp,
    identificar_fabricante_snmp,
    integrar_dados_snmp,
)


@pytest.mark.parametrize(
    ("object_id", "expected"),
    [
        ("1.3.6.1.4.1.9.1.1", "Cisco"),
        ("SNMPv2-SMI::enterprises.14988.1.1", "MikroTik"),
        ("1.3.6.1.4.1.11863.6.1", "TP-Link"),
        ("1.3.6.1.4.1.90.1", None),
        ("not-an-oid", None),
    ],
)
def test_identifica_fabricante_por_prefixo_oid(object_id, expected):
    assert identificar_fabricante_snmp(object_id) == expected


@pytest.mark.parametrize(
    ("description", "expected"),
    [
        ("Cisco Router", "roteador"),
        ("Generic Ethernet switch", "switch/rede"),
        ("Network Printer", "impressora"),
        ("Linux host", None),
    ],
)
def test_classifica_descricao_snmp_sem_chutar(description, expected):
    assert classificar_descricao_snmp(description) == expected


def test_snmp_enriquece_dispositivo_desconhecido_com_evidencia():
    device = {
        "ip": "192.0.2.10",
        "tipo": "desconhecido",
        "fabricante": "Desconhecido",
        "hostname": "",
        "classificacao_confianca": 5,
        "classificacao_evidencia": [],
    }

    integrar_dados_snmp(
        device,
        {
            "object_id": "1.3.6.1.4.1.9.1.1",
            "description": "Cisco Router",
            "name": "gateway",
            "location": "Sala técnica",
        },
    )

    assert device["tipo"] == "roteador"
    assert device["fabricante"] == "Cisco"
    assert device["hostname"] == "gateway"
    assert device["classificacao_confianca"] == 2
    assert "SNMP sysObjectID: Cisco" in device["classificacao_evidencia"]
    assert device["snmp_info"]["location"] == "Sala técnica"
    assert "community" not in device


def test_snmp_nao_substitui_classificacao_de_confianca_maior():
    device = {
        "tipo": "computador_windows",
        "fabricante": "Dell",
        "classificacao_confianca": 1,
        "classificacao_evidencia": ["Porta aberta: 445"],
    }

    integrar_dados_snmp(
        device,
        {"description": "Cisco Router", "object_id": "1.3.6.1.4.1.9"},
    )

    assert device["tipo"] == "computador_windows"
    assert device["fabricante"] == "Dell"


def test_snmp_requer_comunidade_explicita_e_valida_parametros():
    with pytest.raises(ValueError, match="configurada explicitamente"):
        consultar_hosts_snmp(["192.0.2.10"], "")
    with pytest.raises(ValueError, match="porta SNMP"):
        consultar_hosts_snmp(["192.0.2.10"], "read-only", port=70000)
    with pytest.raises(ValueError, match="timeout SNMP"):
        consultar_hosts_snmp(["192.0.2.10"], "read-only", timeout=0)


def test_snmp_com_lista_vazia_nao_faz_requisicoes():
    assert consultar_hosts_snmp([], "read-only") == {}


def test_snmp_filtra_hosts_invalidos_e_normaliza_comunidade(monkeypatch):
    async def fake_consultar_hosts(hosts, community, port, timeout, concurrency):
        assert hosts == ["192.0.2.10"]
        assert community == "read-only"
        assert port == 161
        assert timeout == 1.5
        assert concurrency == 16
        return {"192.0.2.10": {"description": "Cisco Router"}}

    monkeypatch.setattr(snmp_scanner, "_consultar_hosts", fake_consultar_hosts)

    assert consultar_hosts_snmp(
        [" 192.0.2.10 ", "", "192.0.2.10"], " read-only "
    ) == {"192.0.2.10": {"description": "Cisco Router"}}


def test_snmp_aceita_chamada_dentro_de_loop(monkeypatch):
    async def fake_consultar_hosts(hosts, community, port, timeout, concurrency):
        assert hosts == ["192.0.2.10"]
        return {"192.0.2.10": {"description": "Cisco Router"}}

    monkeypatch.setattr(snmp_scanner, "_consultar_hosts", fake_consultar_hosts)

    async def runner():
        return consultar_hosts_snmp(["192.0.2.10"], "read-only")

    assert asyncio.run(runner()) == {
        "192.0.2.10": {"description": "Cisco Router"}
    }


def test_consulta_snmp_obtem_identificacao_sem_fazer_rede(
    monkeypatch,
):
    async def fake_get_cmd(*request):
        auth_data = request[1]
        var_binds = request[4:]
        assert isinstance(auth_data, CommunityData)
        assert len(var_binds) == 6
        values = (
            OctetString("Cisco Router"),
            ObjectIdentifier("1.3.6.1.4.1.9.1.1"),
            Integer32(100),
            OctetString("ops@example.test"),
            OctetString("gateway"),
            OctetString("Lab"),
        )
        return (
            None,
            0,
            0,
            tuple(
                (object_type, value)
                for object_type, value in zip(var_binds, values)
            ),
        )

    monkeypatch.setattr(pysnmp_asyncio, "get_cmd", fake_get_cmd)

    result = consultar_hosts_snmp(["192.0.2.10"], "configured-read-only")

    assert result["192.0.2.10"] == {
        "description": "Cisco Router",
        "object_id": "1.3.6.1.4.1.9.1.1",
        "uptime": "100",
        "contact": "ops@example.test",
        "name": "gateway",
        "location": "Lab",
    }
