#!/usr/bin/env python3
import csv
import os
from datetime import datetime

def exportar_csv(dispositivos, nome_arquivo=None):
    if not nome_arquivo:
        os.makedirs("exports", exist_ok=True)
        nome_arquivo = f"exports/dispositivos_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    with open(nome_arquivo, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['IP', 'Hostname', 'MAC', 'Fabricante', 'Tipo', 'Risco', 'Severidade', 'Portas'])
        for d in dispositivos:
            writer.writerow([
                d.get('ip', ''),
                d.get('nome', ''),
                d.get('mac', ''),
                d.get('fabricante', ''),
                d.get('tipo', ''),
                d.get('risco', ''),
                d.get('severity', ''),
                ', '.join(map(str, d.get('open_ports', [])))
            ])
    print(f"✅ CSV: {nome_arquivo}")
    return nome_arquivo
