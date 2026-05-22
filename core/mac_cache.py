# core/mac_cache.py

import json
import os
from typing import Optional

MAC_CACHE_PATH = "storage/mac_cache.json"

# Dicionário local de MACs conhecidos (OUI - Organizationally Unique Identifier)
KNOWN_VENDORS = {
    # TP-Link
    "3c:84:6a": "TP-Link Technologies",
    "50:3e:aa": "TP-Link Technologies",
    "fc:d7:b4": "TP-Link Technologies",
    "d8:0d:17": "TP-Link Technologies",
    
    # Cisco
    "a0:0f:37": "Cisco Systems",
    "00:0f:37": "Cisco Systems",
    "70:ca:9b": "Cisco Systems",
    "00:1a:a1": "Cisco Systems",
    
    # Intel
    "8c:b0:e9": "Intel Corporation",
    "00:15:5d": "Intel Corporation",
    "00:1b:fc": "Intel Corporation",
    
    # Dell
    "00:0c:f1": "Dell Inc.",
    "00:1d:09": "Dell Inc.",
    "a4:ba:db": "Dell Inc.",
    
    # Apple
    "00:16:cb": "Apple Inc.",
    "00:25:00": "Apple Inc.",
    "48:2c:6a": "Apple Inc.",
    "8c:85:90": "Apple Inc.",
    
    # Samsung
    "00:21:6a": "Samsung Electronics",
    "04:8d:38": "Samsung Electronics",
    
    # LG
    "00:19:21": "LG Electronics",
    "b0:91:22": "LG Electronics",
    
    # Xiaomi
    "04:cf:8c": "Xiaomi Communications",
    "08:6c:6a": "Xiaomi Communications",
    
    # Asus
    "04:92:26": "ASUSTek Computer",
    "00:1f:c6": "ASUSTek Computer",
    
    # HP
    "00:15:60": "Hewlett Packard",
    "64:51:06": "Hewlett Packard",
    
    # Sony
    "00:0c:6e": "Sony Corporation",
    "c0:56:27": "Sony Corporation",
    
    # Motorola
    "00:16:6e": "Motorola Mobility",
    "3c:56:fa": "Motorola Mobility",
    
    # Huawei
    "00:25:9e": "Huawei Technologies",
    "78:5c:d4": "Huawei Technologies",
    
    # Microsoft (Xbox, Surface)
    "00:15:5d": "Microsoft Corporation",
    "40:6c:8f": "Microsoft Corporation",
    
    # IoT / ESP
    "cc:50:e3": "Espressif Inc.",
    "24:6f:28": "Espressif Inc.",
    
    # Amazon (Alexa, Echo)
    "2c:54:91": "Amazon Technologies",
    "ac:3e:7a": "Amazon Technologies",
    
    # Google (Chromecast, Nest)
    "d8:96:85": "Google Inc.",
    "e4:aa:5d": "Google Inc.",
}

def carregar_cache_mac():
    """Carrega cache de MAC addresses do disco"""
    if os.path.exists(MAC_CACHE_PATH):
        try:
            with open(MAC_CACHE_PATH, "r") as f:
                return json.load(f)
        except:
            return {}
    return {}

def salvar_cache_mac(cache):
    """Salva cache de MAC addresses no disco"""
    os.makedirs("storage", exist_ok=True)
    with open(MAC_CACHE_PATH, "w") as f:
        json.dump(cache, f, indent=2)

def lookup_vendor_local(mac: str) -> Optional[str]:
    """
    Busca fabricante localmente (sem internet)
    Baseado no prefixo OUI (primeiros 8 caracteres: XX:XX:XX)
    """
    if not mac or mac == "desconhecido":
        return None
    
    # Normalizar MAC
    mac_clean = mac.upper().replace("-", ":").replace(" ", "")
    
    # Extrair OUI (primeiros 8 caracteres: XX:XX:XX)
    if len(mac_clean) >= 8:
        oui = mac_clean[:8]  # Ex: "3C:84:6A"
        
        # Buscar no dicionário local
        for known_oui, vendor in KNOWN_VENDORS.items():
            if oui.startswith(known_oui.upper()):
                return vendor
    
    return None

def fabricante_por_mac_com_cache(mac: str, use_internet: bool = False) -> str:
    """
    Versão com cache e fallback local (NÃO usa internet por padrão)
    
    Args:
        mac: Endereço MAC
        use_internet: Se True, tenta consultar online (pode falhar)
    
    Returns:
        Nome do fabricante ou "desconhecido"
    """
    if not mac or mac == "desconhecido":
        return "desconhecido"
    
    # 1. Verificar cache em disco
    cache = carregar_cache_mac()
    if mac in cache:
        return cache[mac]
    
    # 2. Buscar localmente (offline)
    vendor = lookup_vendor_local(mac)
    if vendor:
        # Salvar no cache
        cache[mac] = vendor
        salvar_cache_mac(cache)
        return vendor
    
    # 3. Tentar online (opcional - pode falhar)
    if use_internet:
        try:
            from mac_vendor_lookup import MacLookup
            ml = MacLookup()
            # Timeout curto para não travar
            import socket
            socket.setdefaulttimeout(5)
            vendor = ml.lookup(mac)
            if vendor and vendor != "Unknown":
                cache[mac] = vendor
                salvar_cache_mac(cache)
                return vendor
        except Exception as e:
            print(f"[DEBUG] Erro lookup online para {mac}: {e}")
    
    # 4. Fallback
    return "desconhecido"

def preencher_cache_inicial():
    """Popula o cache com MACs conhecidos"""
    cache = carregar_cache_mac()
    
    # Adicionar MACs conhecidos ao cache
    for mac, vendor in KNOWN_VENDORS.items():
        if mac not in cache:
            cache[mac] = vendor
    
    salvar_cache_mac(cache)
    print(f"[INFO] Cache inicializado com {len(cache)} entradas")

# Inicializar cache quando o módulo é carregado
preencher_cache_inicial()
