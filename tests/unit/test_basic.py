"""Testes básicos que não dependem de imports complexos"""
import pytest
import json
import os
import sys

class TestBasic:
    def test_python_version(self):
        """Verifica versão do Python"""
        assert sys.version_info >= (3, 10)
    
    def test_project_structure(self):
        """Verifica estrutura do projeto"""
        important_dirs = ['core', 'dashboard', 'storage', 'reports']
        for dir_name in important_dirs:
            assert os.path.exists(dir_name), f"Diretório {dir_name} não encontrado"
    
    def test_config_exists(self):
        """Verifica arquivo de configuração"""
        if os.path.exists('config.json'):
            with open('config.json', 'r') as f:
                config = json.load(f)
                assert isinstance(config, dict)
        else:
            pytest.skip("config.json não encontrado")
    
    def test_core_files_exist(self):
        """Verifica arquivos core essenciais"""
        core_files = ['classifier.py', 'infra_score.py', 'network.py']
        for file in core_files:
            path = os.path.join('core', file)
            assert os.path.exists(path), f"Arquivo {path} não encontrado"
