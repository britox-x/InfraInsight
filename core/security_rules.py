# core/security_rules.py

def deve_escanear_portas(dispositivo):
    """
    Decide se um dispositivo precisa ter suas portas escaneadas
    Baseado em tipo, risco, novidade e criticidade
    """
    tipo = dispositivo.get("tipo", "").lower()
    risco = dispositivo.get("risco", 0)
    mac = dispositivo.get("mac", "")
    ip = dispositivo.get("ip", "")
    historico = dispositivo.get("frequencia", 0)
    
    # SEMPRE escanear gateway
    if ip.endswith(".1") or ip.endswith(".254"):
        return True
    
    # SEMPRE escanear dispositivos desconhecidos
    if tipo == "desconhecido":
        return True
    
    # Escanear se risco já é médio/alto
    if risco >= 4:
        return True
    
    # Escanear dispositivos críticos
    if tipo in ["roteador", "gateway_principal", "switch_core"]:
        return True
    
    # Dispositivos novos (menos de 3 aparições)
    if historico < 3 and historico > 0:
        return True
    
    # Fabricantes suspeitos
    fabricantes_suspeitos = ["espressif", "tuya", "hikvision", "unknown"]
    fabricante = dispositivo.get("fabricante", "").lower()
    if any(sus in fabricante for sus in fabricantes_suspeitos):
        return True
    
    # Dispositivos com MAC randomizado
    if "privado" in fabricante or "randomizado" in fabricante:
        return True
    
    return False

def definir_timeout_scan(tipo_dispositivo):
    """Define timeout de scan baseado no tipo de dispositivo"""
    timeouts = {
        "roteador": 0.5,
        "switch/rede": 0.3,
        "computador_conhecido": 0.3,
        "mobile/android": 0.2,
        "mobile/ios": 0.2,
        "mobile/windows": 0.2,
        "desconhecido": 0.5,
        "iot": 0.4,
        "camera": 0.4
    }
    return timeouts.get(tipo_dispositivo, 0.3)
