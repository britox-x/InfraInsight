def verificar_alertas(dispositivo, scan_atual, scan_anterior):
    alertas = []
    
    # Novo dispositivo
    if scan_anterior and dispositivo['ip'] not in [d['ip'] for d in scan_anterior['dispositivos']]:
        alertas.append(f"🆕 NOVO DISPOSITIVO: {dispositivo['ip']} - {dispositivo['tipo']}")
    
    # Porta perigosa
    if 23 in dispositivo.get('open_ports', []):
        alertas.append(f"⚠️ PORTA TELNET (23) ABERTA em {dispositivo['ip']}")
    
    if 445 in dispositivo.get('open_ports', []):
        alertas.append(f"⚠️ PORTA SMB (445) ABERTA em {dispositivo['ip']} - Risco de ransomware")
    
    # Risco alto
    if dispositivo.get('risco', 0) >= 7:
        alertas.append(f"🔴 ALTO RISCO: {dispositivo['ip']} - {dispositivo['risco']}/10")
    
    return alertas
