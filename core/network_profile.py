def gerar_perfil(dispositivos):
    """Gera perfil da rede baseado nos dispositivos"""
    tipos = {}
    for d in dispositivos:
        tipo = d.get('tipo', 'desconhecido')
        tipos[tipo] = tipos.get(tipo, 0) + 1
    
    # Determinar tipo de rede
    if tipos.get('smarttv', 0) > 0 or tipos.get('camera_ip', 0) > 0:
        perfil = "Rede doméstica híbrida com dispositivos multimídia e IoT"
    elif tipos.get('roteador', 0) > 1:
        perfil = "Rede com múltiplos pontos de acesso"
    elif tipos.get('desconhecido', 0) > tipos.get('computador_conhecido', 0):
        perfil = "Ambiente com baixa visibilidade de dispositivos"
    else:
        perfil = "Ambiente controlado com boa visibilidade"
    
    return {"tipos": tipos, "perfil": perfil}
