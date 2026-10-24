"""Testes para o classificador de dispositivos"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.classifier import (
    classificar_dispositivo,
    contar_dispositivos_desconhecidos,
    mac_localmente_administrado,
    normalizar_fabricante,
    normalizar_hostname,
)

class TestClassifier:
    """Testes para a função classificar_dispositivo"""
    
    def test_classificar_roteador_por_ip(self):
        """Testa classificação de roteador por IP"""
        tipo, confianca = classificar_dispositivo(
            ip="192.168.1.1",
            vendor="tp-link",
            hostname="",
            mac="",
            open_ports=[]
        )
        assert tipo == "roteador"
        assert confianca == 1
    
    def test_classificar_roteador_por_hostname(self):
        """Testa classificação de roteador por hostname"""
        tipo, confianca = classificar_dispositivo(
            ip="192.168.1.100",
            vendor="tp-link",
            hostname="router",
            mac="",
            open_ports=[80, 443]
        )
        assert tipo == "roteador"
        assert confianca == 1
    
    def test_classificar_roku_por_mac(self):
        """Testa classificação de Roku por MAC"""
        tipo, confianca = classificar_dispositivo(
            ip="192.168.1.50",
            vendor="",
            hostname="",
            mac="60:92:c8:aa:bb:cc",
            open_ports=[]
        )
        assert tipo == "roku"
        assert confianca == 1
    
    def test_classificar_roku_por_porta(self):
        """Testa classificação de Roku por porta 8060"""
        tipo, confianca = classificar_dispositivo(
            ip="192.168.1.50",
            vendor="",
            hostname="",
            mac="",
            open_ports=[8060, 80]
        )
        assert tipo == "roku"
        assert confianca == 1
    
    def test_classificar_smarttv_amino(self):
        """Testa classificação de Amino (TV Box)"""
        tipo, confianca = classificar_dispositivo(
            ip="192.168.1.60",
            vendor="amino",
            hostname="",
            mac="",
            open_ports=[]
        )
        assert tipo == "smarttv"
        assert confianca == 2
    
    def test_classificar_desconhecido(self):
        """Testa classificação desconhecida"""
        tipo, confianca = classificar_dispositivo(
            ip="192.168.1.200",
            vendor="unknown",
            hostname="",
            mac="00:11:22:33:44:55",
            open_ports=[]
        )
        assert tipo == "desconhecido"
        assert confianca in [2, 5]

    @pytest.mark.parametrize(
        ("vendor", "mac"),
        [
            ("local", "00:11:22:33:44:55"),
            ("", "02:11:22:33:44:55"),
            ("unknown", "02:11:22:33:44:55"),
        ],
    )
    def test_nao_inferir_computador_sem_evidencias(self, vendor, mac):
        tipo, confianca = classificar_dispositivo(
            hostname="",
            vendor=vendor,
            ip="192.168.1.25",
            mac=mac,
            open_ports=[],
        )

        assert tipo == "desconhecido"
        assert confianca == 5

    def test_hostname_local_distintivo_permanece_util(self):
        tipo, confianca = classificar_dispositivo(
            hostname="router.local",
            vendor="",
            ip="192.168.1.25",
            mac="02:11:22:33:44:55",
            open_ports=[],
        )

        assert (tipo, confianca) == ("desconhecido", 5)
        assert normalizar_hostname("Gateway.Local.") == "Gateway"


@pytest.mark.parametrize(
    ("mac", "expected"),
    [
        ("02:11:22:33:44:55", True),
        ("06:11:22:33:44:55", True),
        ("0a:11:22:33:44:55", True),
        ("0e:11:22:33:44:55", True),
        ("d2:4f:00:11:22:33", True),
        ("D2:4F:00:11:22:33", True),
        ("a4:2b:8c:11:22:33", False),
        ("00:11:22:33:44:55", False),
        ("invalid", False),
        (None, False),
    ],
)
def test_bit_ul_identifica_mac_localmente_administrado(mac, expected):
    assert mac_localmente_administrado(mac) is expected

    @pytest.mark.parametrize(
        ("vendor", "expected"),
        [
            (" local ", ""),
            ("unknown", ""),
            ("n/a", ""),
            ("TP-Link Corporation", "TP-Link Corporation"),
        ],
    )
    def test_normaliza_fabricante_placeholders(self, vendor, expected):
        assert normalizar_fabricante(vendor) == expected

    def test_classificar_por_portas(self):
        """Testa classificação baseada em portas"""
        # Câmera com RTSP (porta 554)
        tipo, confianca = classificar_dispositivo(
            ip="192.168.1.70",
            vendor="intelbras",
            hostname="",
            mac="",
            open_ports=[554, 80]
        )
        tipos_aceitaveis = ["camera_ip", "camera", "iot", "computador_conhecido"]
        assert tipo in tipos_aceitaveis, \
            f"Esperado {tipos_aceitaveis}, obteve {tipo}"

    def test_conta_somente_tipos_desconhecidos(self):
        assert contar_dispositivos_desconhecidos(
            [
                {"tipo": "roteador"},
                {"tipo": "desconhecido"},
                {"tipo": "computador_conhecido"},
            ]
        ) == 1
        assert contar_dispositivos_desconhecidos([{}]) == 1
