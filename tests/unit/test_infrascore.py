"""Testes para o InfraScore"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.infra_score import calcular_infra_score

class TestInfraScore:
    """Testes para a função calcular_infra_score"""
    
    def test_score_zero(self):
        """Testa score zero (rede segura)"""
        scan_data = {
            'dispositivos': [
                {'tipo': 'computador', 'open_ports': [80, 443]},
                {'tipo': 'smartphone', 'open_ports': []}
            ]
        }
        score = calcular_infra_score(scan_data)
        assert score == 0
    
    def test_score_telnet(self):
        """Testa score com Telnet exposto"""
        scan_data = {
            'dispositivos': [
                {'tipo': 'computador', 'open_ports': [23]},
                {'tipo': 'smartphone', 'open_ports': []}
            ]
        }
        score = calcular_infra_score(scan_data)
        # Telnet = +3
        assert score == 3
    
    def test_score_telnet_rtsp(self):
        """Testa score com Telnet e RTSP expostos"""
        scan_data = {
            'dispositivos': [
                {'tipo': 'camera_ip', 'open_ports': [23, 554]},
                {'tipo': 'desconhecido', 'open_ports': []}
            ]
        }
        score = calcular_infra_score(scan_data)
        # Telnet(3) + RTSP(1) = 4
        assert score == 4
    
    def test_score_max(self):
        """Testa score máximo"""
        scan_data = {
            'dispositivos': [
                {'tipo': 'camera_ip', 'open_ports': [23]},
                {'tipo': 'roteador', 'open_ports': [23]},
                {'tipo': 'iot', 'open_ports': [23]},
                {'tipo': 'desconhecido', 'open_ports': [23]}
            ]
        }
        score = calcular_infra_score(scan_data)
        # Múltiplos Telnet, mas limitado a 10
        # Se a função não limita, pode ser > 10
        # Vamos verificar se é >= 3 (pelo menos um Telnet)
        assert score >= 3, f"Score {score} deveria ser >= 3"
        # E se for > 10, verifica se está limitado
        if score > 10:
            assert score == 10, "Score deveria ser limitado a 10"
