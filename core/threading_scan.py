# core/threading_scan.py

from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
from typing import List, Dict, Any

def scan_port_single(ip: str, port: int, timeout: float = 0.3) -> tuple:
    """Escaneia uma única porta"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return (port, result == 0)
    except:
        return (port, False)

def scan_ports_parallel(ip: str, ports: List[int] = None, timeout: float = 0.3, max_workers: int = 20) -> List[int]:
    """Escaneia portas em paralelo"""
    if ports is None:
        ports = [22, 23, 80, 443, 445, 3389, 5900, 8080, 554, 1900, 8009, 9100, 1883]
    
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port_single, ip, port, timeout): port for port in ports}
        
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
    
    return sorted(open_ports)

def executar_paralelo(funcao, itens, max_workers=10):
    """Executa uma função em paralelo para uma lista de itens"""
    resultados = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(funcao, item) for item in itens]
        
        for future in as_completed(futures):
            try:
                resultados.append(future.result())
            except Exception as e:
                print(f"Erro em execução paralela: {e}")
    
    return resultados
