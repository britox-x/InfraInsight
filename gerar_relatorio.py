#!/usr/bin/env python3
"""Gerador de relatório PDF do InfraInsight - usando data_json"""

import sys
import os
import sqlite3
import json
from datetime import datetime
from core.infra_score import decompor_infra_score, score_minimo_observado

sys.path.insert(0, '.')
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'storage', 'infrainsight.db')

def extract_scan_data(scan_id=None):
    """Extrai dados de scan do campo data_json"""
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    if scan_id:
        cursor.execute(
            'SELECT id, timestamp, data_json, componentes_json FROM scans '
            'WHERE id = ?',
            (scan_id,),
        )
    else:
        cursor.execute(
            'SELECT id, timestamp, data_json, componentes_json FROM scans '
            'ORDER BY id DESC LIMIT 1'
        )
    
    row = cursor.fetchone()
    if not row:
        print('❌ Nenhum scan encontrado')
        conn.close()
        return None, None
    
    scan_id = row[0]
    timestamp = row[1]
    data_json = row[2]
    
    try:
        data = json.loads(data_json) if data_json else {}
    except:
        data = {}

    classifier_version = data.get('classifier_version', 'v1')
    try:
        componentes = json.loads(row[3]) if row[3] else []
    except (TypeError, ValueError):
        componentes = []
    if not componentes:
        componentes = data.get('componentes', [])
    if not componentes:
        componentes = decompor_infra_score(
            data,
            scan_services=bool(data.get('scan_services', False)),
            cve_lookup=bool(data.get('cve_lookup', False)),
            cve_coverage_complete=bool(
                data.get('cve_coverage_complete', False)
            ),
            classification_observed=classifier_version != 'v1',
        )['components']
    componentes_observados = [
        component.get('key')
        for component in componentes
        if component.get('status') == 'observado'
    ]

    contexto_scan = {
        'id': scan_id,
        'modo': (
            'Serviços' if data.get('scan_services') else 'Rápido (ARP)'
        ) + (
            ' + NVD' if data.get('cve_lookup') else ''
        ) + (
            ' + SNMP' if data.get('snmp_enabled') else ''
        ),
        'scan_services': data.get('scan_services', False),
        'cve_lookup': data.get('cve_lookup', False),
        'duracao_s': data.get('duracao_s'),
        'classifier_version': classifier_version,
        'formula_version': data.get(
            'formula_version', 'normalizada-7-v1'
        ),
        'componentes': componentes,
        'score_observado': score_minimo_observado(componentes),
        'componentes_observados': componentes_observados,
    }
    print(f'📊 Scan ID: {scan_id}')
    print(f'  Data: {timestamp}')
    print(f'  Ambiente: {data.get("ambiente", "N/A")}')
    print(f'  Dispositivos: {data.get("ips_ativos", 0)}')
    
    # Extrair dispositivos
    dispositivos = []
    for dev in data.get('dispositivos', []):
        portas = dev.get('open_ports', [])
        if isinstance(portas, str):
            try:
                portas = json.loads(portas)
            except:
                portas = []
        elif not isinstance(portas, list):
            portas = [portas] if portas else []
        
        risco = dev.get('risco', 1)
        if isinstance(risco, str):
            try:
                risco = int(risco)
            except:
                risco = 1
        
        dispositivo = {
            'ip': dev.get('ip', ''),
            'mac': dev.get('mac', ''),
            'hostname': dev.get('hostname') or dev.get('nome', ''),
            'fabricante': dev.get('fabricante') or dev.get('vendor', ''),
            'tipo': 'Host Conhecido' if dev.get('tipo') == 'computador_conhecido' else dev.get('tipo', 'desconhecido'),
            'risco': risco,
            'portas': portas,
            'severity': dev.get('severity', 'Baixo')
        }
        dispositivos.append(dispositivo)
    
    # Histórico
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
    return dispositivos, historico, contexto_scan

def gerar_relatorio(scan_id=None, nome_arquivo=None):
    """Gera relatório PDF"""
    
    from reports.pdf_report import gerar_pdf
    
    dispositivos, historico, contexto_scan = extract_scan_data(scan_id)
    
    if not dispositivos:
        print('❌ Nenhum dado disponível')
        return None
    
    print(f'  Dispositivos extraídos: {len(dispositivos)}')
    print(f'  Histórico: {len(historico)} pontos')
    
    if not nome_arquivo:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        nome_arquivo = os.path.join(BASE_DIR, 'reports', f'relatorio_{timestamp}.pdf')
    
    os.makedirs(os.path.dirname(nome_arquivo) or '.', exist_ok=True)
    
    try:
        caminho = gerar_pdf(
            dispositivos=dispositivos,
            historico=historico if historico else None,
            nome_arquivo=nome_arquivo,
            contexto_scan=contexto_scan,
        )
        print(f'✅ Relatório gerado: {caminho}')
        if os.path.exists(caminho):
            size = os.path.getsize(caminho)
            print(f'  Tamanho: {size} bytes ({size/1024:.1f} KB)')
        return caminho
    except Exception as e:
        print(f'❌ Erro ao gerar PDF: {e}')
        import traceback
        traceback.print_exc()
        return None

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Gerar relatório PDF')
    parser.add_argument('--scan-id', type=int, help='ID do scan (padrão: último)')
    parser.add_argument('--output', '-o', help='Nome do arquivo de saída')
    args = parser.parse_args()
    
    gerar_relatorio(args.scan_id, args.output)
