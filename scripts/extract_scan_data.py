#!/usr/bin/env python3
"""Extrai dados de scan do campo data_json"""

import sqlite3
import json
from datetime import datetime

def extract_scan_data(scan_id=None):
    """Extrai dados de um scan do campo data_json"""
    
    conn = sqlite3.connect('storage/infrainsight.db')
    cursor = conn.cursor()
    
    # Buscar scan
    if scan_id:
        cursor.execute('SELECT id, timestamp, data_json FROM scans WHERE id = ?', (scan_id,))
    else:
        cursor.execute('SELECT id, timestamp, data_json FROM scans ORDER BY id DESC LIMIT 1')
    
    row = cursor.fetchone()
    if not row:
        print('❌ Nenhum scan encontrado')
        conn.close()
        return None, None
    
    scan_id = row[0]
    timestamp = row[1]
    data_json = row[2]
    
    # Parse do JSON
    try:
        data = json.loads(data_json) if data_json else {}
    except:
        data = {}
    
    print(f'📊 Scan ID: {scan_id}')
    print(f'  Data: {timestamp}')
    print(f'  Ambiente: {data.get("ambiente", "N/A")}')
    print(f'  Dispositivos: {data.get("ips_ativos", 0)}')
    
    # Extrair dispositivos do JSON
    dispositivos = []
    for dev in data.get('dispositivos', []):
        # Processar portas
        portas = dev.get('open_ports', [])
        if isinstance(portas, str):
            try:
                portas = json.loads(portas)
            except:
                portas = []
        elif not isinstance(portas, list):
            portas = [portas] if portas else []
        
        # Determinar risco
        risco = dev.get('risco', 1)
        if isinstance(risco, str):
            try:
                risco = int(risco)
            except:
                risco = 1
        
        dispositivo = {
            'ip': dev.get('ip', ''),
            'mac': dev.get('mac', ''),
            'hostname': dev.get('nome', ''),
            'fabricante': dev.get('fabricante', ''),
            'tipo': dev.get('tipo', 'desconhecido'),
            'risco': risco,
            'portas': portas,
            'severity': dev.get('severity', 'Baixo')
        }
        dispositivos.append(dispositivo)
    
    # Criar histórico dos últimos scans
    cursor.execute('''
        SELECT id, timestamp, data_json FROM scans 
        ORDER BY id DESC LIMIT 10
    ''')
    historico = []
    for row in cursor.fetchall():
        try:
            hist_data = json.loads(row[2]) if row[2] else {}
            score = hist_data.get('risco_medio', 0)
            if isinstance(score, str):
                try:
                    score = float(score)
                except:
                    score = 0
            historico.append({
                'data': row[1][:10] if row[1] else '',
                'score': score
            })
        except:
            pass
    historico.reverse()
    
    conn.close()
    return dispositivos, historico

if __name__ == '__main__':
    dispositivos, historico = extract_scan_data()
    print(f'\nDispositivos extraídos: {len(dispositivos)}')
    if dispositivos:
        print(f'Primeiro dispositivo: {dispositivos[0].get("ip")} - {dispositivos[0].get("tipo")}')
    print(f'Histórico: {len(historico)} pontos')
