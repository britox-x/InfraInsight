import os
import json
import re
import subprocess
import sys
from pathlib import Path
import socket
import ipaddress
import requests

def detectar_ambiente_por_rede(gateway, rede, ssid, perguntar=True):
    """
    Detecta o ambiente baseado na rede, gateway e SSID
    """
    # Carregar configuração de ambientes conhecidos
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')
    
    ambientes_conhecidos = {}
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                ambientes_conhecidos = config.get('ambientes_conhecidos', {})
        except:
            pass
    
    # Verificar se a rede é conhecida
    for nome, dados in ambientes_conhecidos.items():
        if dados.get('rede') == rede or dados.get('gateway') == gateway:
            return nome
    
    # Detectar por SSID
    if ssid and ssid in ambientes_conhecidos:
        return ssid
    
    # Se não encontrou, perguntar
    print(f"\n🌐 Nova rede detectada: {rede}")
    print(f"📡 Gateway: {gateway}")
    print(f"📶 SSID: {ssid}")
    
    if perguntar:
        ambiente = input("Digite o nome do ambiente (ou Enter para 'Casa'): ").strip()
    else:
        ambiente = "Casa"
    if not ambiente:
        ambiente = "Casa"
    
    # Salvar ambiente conhecido
    ambientes_conhecidos[ambiente] = {
        'rede': rede,
        'gateway': gateway,
        'ssid': ssid
    }
    
    # Atualizar config.json
    config = {}
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
        except:
            pass
    
    config['ambientes_conhecidos'] = ambientes_conhecidos
    
    try:
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"✅ Ambiente '{ambiente}' salvo nas configurações")
    except:
        pass
    
    return ambiente
