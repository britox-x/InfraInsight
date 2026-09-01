"""Testes com scanner real (requer rede)"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

@pytest.mark.integration
@pytest.mark.network
class TestScannerReal:
    def test_scan_localhost(self):
        """Testa scan do localhost"""
        try:
            from core.network import scan_network
            result = scan_network("127.0.0.1/32")
            assert isinstance(result, list)
        except ImportError:
            pytest.skip("Scanner não disponível")
    
    def test_get_network_info(self):
        """Testa obtenção de informações da rede"""
        try:
            from core.network import get_network_info
            info = get_network_info()
            assert 'ip' in info or 'network' in info
        except ImportError:
            pytest.skip("Função não disponível")
