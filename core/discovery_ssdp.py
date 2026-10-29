# core/discovery_ssdp.py
import socket
import time

def descobrir_ssdp(timeout=2):
    """
    Envia um M-SEARCH e retorna um dicionário {ip: {'server': ..., 'location': ..., 'st': ...}}
    """
    msg = (
        'M-SEARCH * HTTP/1.1\r\n'
        'HOST: 239.255.255.250:1900\r\n'
        'MAN: "ssdp:discover"\r\n'
        'MX: 1\r\n'
        'ST: ssdp:all\r\n\r\n'
    ).encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)
    sock.sendto(msg, ('239.255.255.250', 1900))

    resultados = {}
    try:
        while True:
            data, addr = sock.recvfrom(2048)
            ip = addr[0]
            texto = data.decode('utf-8', errors='ignore')
            
            if ip not in resultados:
                resultados[ip] = {'server': '', 'location': '', 'st': ''}
            
            for linha in texto.split('\r\n'):
                if linha.upper().startswith('SERVER:'):
                    resultados[ip]['server'] = linha.split(':', 1)[1].strip()
                elif linha.upper().startswith('LOCATION:'):
                    resultados[ip]['location'] = linha.split(':', 1)[1].strip()
                elif linha.upper().startswith('ST:'):
                    # Guarda o primeiro ST (o mais genérico costuma ser útil)
                    if not resultados[ip]['st']:
                        resultados[ip]['st'] = linha.split(':', 1)[1].strip()
    except socket.timeout:
        pass
    finally:
        sock.close()
    
    return resultados

def inferir_tipo_por_ssdp(server, st, location):
    """Tenta adivinhar o tipo do dispositivo baseado na resposta UPnP."""
    server_lower = server.lower()
    st_lower = st.lower()
    
    if 'roku' in server_lower or 'roku' in st_lower:
        return 'roku'
    if 'linux' in server_lower and 'internetgatewaydevice' in st_lower:
        return 'roteador'
    if 'windows' in server_lower:
        return 'computador_windows'
    if 'android' in server_lower or 'google' in server_lower:
        return 'mobile/android'
    if 'printer' in server_lower or 'print' in st_lower:
        return 'impressora'
    if 'mediarenderer' in st_lower or 'mediaserver' in st_lower:
        return 'smarttv'
    
    return 'desconhecido'

