# tests/unit/test_classifier_v3.py
import pytest

from core.classifier import (
    classificar_dispositivo,
    contar_dispositivos_desconhecidos,
    identificar_tipo_por_mac,
    mac_localmente_administrado,
    nivel_identificacao,
    normalizar_mac,
    vendor_tem,
)


@pytest.mark.parametrize(
    "kwargs,tipo",
    [
        # MAC em maiúsculas não pode quebrar a regra por prefixo
        (dict(mac="60:92:C8:11:22:33"), "roku"),
        (dict(open_ports=[8060]), "roku"),
        # Intelbras não é computador
        (dict(vendor="Intelbras S/A", hostname="x"), "infraestrutura"),
        (dict(vendor="Intel Corporate", hostname="x"), "computador_conhecido"),
        # MAC aleatório sem hostname nem portas: desconhecido
        (dict(mac="b6:ed:06:a6:8d:74"), "desconhecido"),
        (dict(mac="B6-ED-06-A6-8D-74"), "desconhecido"),
        # MAC aleatório não vira Android por prefixo
        (dict(mac="46:aa:bb:cc:dd:ee", vendor="MAC local (possível randomização)", hostname="x"), "desconhecido"),
        # Gateway: '_gateway' não conta como hostname
        (dict(hostname="_gateway", vendor="TP-Link Limited", ip="192.168.0.1", mac="3c:84:6a:00:00:01"), "roteador"),
        # Sem hostname/portas e sem fabricante: desconhecido
        (dict(hostname="X02600E60KFM"), "desconhecido"),
    ],
)
def test_tipo(kwargs, tipo):
    assert classificar_dispositivo(**kwargs)[0] == tipo


def test_gateway_ip_real_tem_prioridade_sobre_convencao():
    # .1 NÃO é o gateway quando o IP real foi informado
    t, _ = classificar_dispositivo(
        hostname="x", vendor="TP-Link Limited", ip="192.168.0.1", gateway_ip="192.168.0.254"
    )
    assert t == "switch/rede"
    t, _ = classificar_dispositivo(
        hostname="x", vendor="TP-Link Limited", ip="192.168.0.254", gateway_ip="192.168.0.254"
    )
    assert t == "roteador"


def test_confianca_rebaixada_para_marca_isolada():
    _, conf = classificar_dispositivo(hostname="x", vendor="Samsung Electronics")
    assert conf >= 3


@pytest.mark.parametrize("fab", ["Desconhecido", "desconhecido", "Unknown", None, "", "local", "MAC local (possível randomização)"])
def test_nivel_desconhecido(fab):
    assert nivel_identificacao({"fabricante": fab})["nivel"] == 1


def test_nivel_conhecido_e_parcial():
    assert nivel_identificacao({"fabricante": "TP-Link Limited"})["nivel"] == 3
    assert nivel_identificacao({"fabricante": "", "open_ports": [80]})["nivel"] == 2


def test_contagem_inclui_variantes_de_desconhecido():
    devs = [
        {"tipo": "desconhecido"},
        {"tipo": "mobile/desconhecido"},
        {"tipo": None},
        {"tipo": "roteador"},
    ]
    assert contar_dispositivos_desconhecidos(devs) == 3


def test_vendor_tem_fronteira_de_palavra():
    assert vendor_tem("Intel Corporate", "intel")
    assert vendor_tem("HP Inc.", "hp")
    assert not vendor_tem("Shenzhen Whp Co", "hp")


def test_helpers_de_mac():
    assert normalizar_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert mac_localmente_administrado("16:82:53:d0:d5:03")
    assert not mac_localmente_administrado("3c:84:6a:00:00:01")
    assert identificar_tipo_por_mac("3C:84:6A:11:22:33") == "roteador"
