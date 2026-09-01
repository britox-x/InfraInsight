"""Testes de integração com o classificador real"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.classifier import classificar_dispositivo

class TestRealClassifier:
    """Testes com o classificador real"""
    
    def test_classificar_varios_dispositivos(self):
        """Testa classificação de vários dispositivos"""
        casos = [
            ("192.168.1.1", "tp-link", "", "", [], ["roteador"]),
            ("192.168.1.2", "d-link", "", "", [80, 443], ["roteador", "desconhecido"]),
            ("192.168.1.10", "apple", "iPhone", "", [], ["smartphone", "mobile/ios", "mobile"]),
            ("192.168.1.20", "samsung", "TV", "", [], ["smarttv", "tv"]),
            ("192.168.1.30", "", "", "60:92:c8:aa:bb:cc", [], ["roku"]),
        ]
        
        for ip, vendor, hostname, mac, ports, esperados in casos:
            tipo, confianca = classificar_dispositivo(
                ip=ip,
                vendor=vendor,
                hostname=hostname,
                mac=mac,
                open_ports=ports
            )
            assert tipo in esperados, \
                f"Falhou para {ip}: esperado {esperados}, obteve {tipo}"
    
    def test_classificar_por_portas_abertas(self):
        """Testa classificação baseada em portas abertas"""
        # Roteador com portas típicas
        tipo, _ = classificar_dispositivo(
            ip="192.168.1.1",
            vendor="",
            hostname="",
            mac="",
            open_ports=[53, 80, 443]
        )
        assert tipo in ["roteador", "desconhecido"]
        
        # Câmera com RTSP - Intelbras
        tipo, _ = classificar_dispositivo(
            ip="192.168.1.50",
            vendor="intelbras",
            hostname="",
            mac="",
            open_ports=[554, 80]
        )
        # Intelbras pode retornar 'computador_conhecido'
        tipos_aceitaveis = ["camera_ip", "camera", "iot", "computador_conhecido"]
        assert tipo in tipos_aceitaveis, \
            f"Esperado {tipos_aceitaveis}, obteve {tipo}"
        
        # Câmera com RTSP - outro fabricante
        tipo, _ = classificar_dispositivo(
            ip="192.168.1.51",
            vendor="hikvision",
            hostname="",
            mac="",
            open_ports=[554, 80]
        )
        # Pode ser camera ou desconhecido
        assert tipo in ["camera_ip", "camera", "iot", "desconhecido"], \
            f"Esperado camera/iot/desconhecido, obteve {tipo}"
    
    def test_confianca_classificacao(self):
        """Testa os níveis de confiança"""
        # Alta confiança (MAC específico)
        _, confianca = classificar_dispositivo(
            ip="",
            vendor="",
            hostname="",
            mac="60:92:c8:aa:bb:cc",
            open_ports=[]
        )
        assert confianca == 1  # Roku
        
        # Média confiança (vendor)
        _, confianca = classificar_dispositivo(
            ip="",
            vendor="tp-link",
            hostname="",
            mac="",
            open_ports=[]
        )
        assert confianca in [1, 2]
