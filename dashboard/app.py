# dashboard/app.py - Versão corrigida com as colunas corretas

from flask import Flask, render_template, jsonify
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'storage', 'infrainsight.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/")
def index():
    """Página principal do dashboard"""
    conn = get_db_connection()
    
    # Estatísticas gerais
    total_scans = conn.execute("SELECT COUNT(*) as count FROM scans").fetchone()["count"]
    
    # Último scan - usando apenas colunas que existem
    latest_scan = conn.execute("""
        SELECT id, timestamp, ambiente, ips_ativos, uso, risco_medio, 
               desconhecidos, mac_randomizados, recomendacao
        FROM scans
        ORDER BY id DESC
        LIMIT 1
    """).fetchone()
    
    # Se não houver scans, criar um objeto vazio com valores padrão
    if not latest_scan:
        latest_scan = {
            'id': 0,
            'timestamp': datetime.now().isoformat(),
            'ambiente': 'N/A',
            'ips_ativos': 0,
            'uso': 0,
            'risco_medio': 0,
            'desconhecidos': 0,
            'mac_randomizados': 0,
            'recomendacao': 'Nenhum scan realizado',
            'novos_dispositivos': 0  # Adicionar padrão
        }
    else:
        # Converter Row para dict
        latest_scan = dict(latest_scan)
        # Adicionar campo novos_dispositivos (pode não existir no banco)
        if 'novos_dispositivos' not in latest_scan:
            latest_scan['novos_dispositivos'] = 0
        # Adicionar campos para compatibilidade com template
        latest_scan['wifi'] = 'Cabeada/Ethernet'
        latest_scan['subrede'] = '192.168.0.0/24'
        latest_scan['gateway'] = '192.168.0.1'
    
    # Dispositivos do último scan
    devices = []
    if latest_scan['id'] > 0:
        try:
            devices = conn.execute("""
                SELECT ip, nome, mac, fabricante, tipo, risk_score, severity, open_ports
                FROM dispositivos
                WHERE scan_id = ?
                ORDER BY risk_score DESC
            """, (latest_scan['id'],)).fetchall()
        except:
            devices = []
    
    # Alertas ativos
    alertas = []
    try:
        alertas = conn.execute("""
            SELECT * FROM alertas 
            WHERE resolved = 0 
            ORDER BY detected_at DESC 
            LIMIT 10
        """).fetchall()
    except:
        alertas = []
    
    # Histórico recente (últimos 10 scans)
    recent_scans = conn.execute("""
        SELECT timestamp, ips_ativos, uso, risco_medio, desconhecidos, mac_randomizados
        FROM scans
        ORDER BY id DESC
        LIMIT 10
    """).fetchall()
    
    conn.close()
    
    # Converter para lista de dicionários
    recent_scans_list = []
    for scan in recent_scans:
        recent_scans_list.append({
            'timestamp': scan['timestamp'],
            'ips_ativos': scan['ips_ativos'],
            'uso': scan['uso'],
            'risco_medio': scan['risco_medio'],
            'desconhecidos': scan['desconhecidos'],
            'mac_randomizados': scan['mac_randomizados'],
            'novos_dispositivos': 0  # Campo pode não existir
        })
    
    return render_template(
        "index.html",
        total_scans=total_scans,
        latest_scan=latest_scan,
        devices=devices,
        alertas=alertas,
        recent_scans=recent_scans_list,
        now=datetime.now()
    )

@app.route("/history")
def history():
    """Página de histórico de scans"""
    conn = get_db_connection()
    
    scans = conn.execute("""
        SELECT id, timestamp, ips_ativos, uso, risco_medio, 
               desconhecidos, mac_randomizados, recomendacao
        FROM scans
        ORDER BY id DESC
    """).fetchall()
    
    conn.close()
    return render_template("history.html", scans=scans)

@app.route("/api/scan/<int:scan_id>")
def api_scan_detail(scan_id):
    """API para detalhes de um scan específico"""
    conn = get_db_connection()
    
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    
    if scan:
        devices = conn.execute("""
            SELECT ip, nome, mac, fabricante, tipo, risk_score, severity, open_ports
            FROM dispositivos
            WHERE scan_id = ?
        """, (scan_id,)).fetchall()
        
        conn.close()
        
        return jsonify({
            'scan': dict(scan),
            'devices': [dict(device) for device in devices]
        })
    
    conn.close()
    return jsonify({'error': 'Scan não encontrado'}), 404

@app.route("/api/stats")
def api_stats():
    """API com estatísticas em tempo real"""
    conn = get_db_connection()
    
    total_scans = conn.execute("SELECT COUNT(*) as count FROM scans").fetchone()["count"]
    total_devices = conn.execute("SELECT COUNT(DISTINCT mac) FROM dispositivos WHERE mac IS NOT NULL AND mac != 'desconhecido'").fetchone()[0]
    avg_risk = conn.execute("SELECT AVG(risk_score) FROM dispositivos").fetchone()[0] or 0
    active_alerts = conn.execute("SELECT COUNT(*) FROM alertas WHERE resolved = 0").fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'total_scans': total_scans,
        'total_devices': total_devices or 0,
        'avg_risk': round(avg_risk, 2),
        'active_alerts': active_alerts,
        'timestamp': datetime.now().isoformat()
    })

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
