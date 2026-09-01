"""Testes para o scanner"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Tenta importar o scanner real
try:
    from core.network import scan_network, get_network_info
    HAS_SCANNER = True
except ImportError:
    HAS_SCANNER = False
    
    # Mock para testes
    def scan_network(network):
        return []

class TestScanner:
    def test_scanner_exists(self):
        """Verifica se o scanner existe"""
        if not HAS_SCANNER:
            pytest.skip("Módulo de scanner não encontrado")
        assert scan_network is not None
    
    def test_scan_returns_list(self):
        """Testa se o scan retorna uma lista"""
        if not HAS_SCANNER:
            pytest.skip("Módulo de scanner não encontrado")
        result = scan_network("127.0.0.1/32")
        assert isinstance(result, list)
