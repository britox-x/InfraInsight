# core/persistence.py - Versão corrigida

import sqlite3
import json
from datetime import datetime
import os

DB_NAME = "storage/infrainsight.db"

def iniciar_banco():
    """Inicializa o banco de dados SQLite com schema correto"""
    os.makedirs('storage', exist_ok=True)
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Verificar se a tabela scans existe e tem a coluna correta
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
    table_exists = cursor.fetchone()
    
    if table_exists:
        # Verificar estrutura atual da tabela
        cursor.execute("PRAGMA table_info(scans)")
        columns = [col[1] for col in cursor.fetchall()]
        
        # Se não tiver as colunas novas, recriar tabela
        if 'risco_medio' not in columns:
            print("[INFO] Atualizando schema do banco de dados...")
            # Renomear tabela antiga
            cursor.execute("ALTER TABLE scans RENAME TO scans_old")
            
            # Criar nova tabela com schema correto
            cursor.execute("""
            CREATE TABLE scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                ambiente TEXT,
                ips_ativos INTEGER,
                uso REAL,
                risco_medio REAL,
                desconhecidos INTEGER,
                mac_randomizados INTEGER,
                recomendacao TEXT,
                data_json TEXT
            )
            """)
            
            # Migrar dados antigos se possível
            try:
                cursor.execute("""
                    INSERT INTO scans (timestamp, ambiente, ips_ativos, uso, risco_medio, data_json)
                    SELECT timestamp, ambiente, ips_ativos, uso, indicador_medio, data_json 
                    FROM scans_old
                """)
                print("[INFO] Dados antigos migrados com sucesso")
            except:
                print("[INFO] Nenhum dado antigo para migrar")
            
            # Remover tabela antiga
            cursor.execute("DROP TABLE IF EXISTS scans_old")
    else:
        # Criar tabela nova
        cursor.execute("""
        CREATE TABLE scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ambiente TEXT,
            ips_ativos INTEGER,
            uso REAL,
            risco_medio REAL,
            desconhecidos INTEGER,
            mac_randomizados INTEGER,
            recomendacao TEXT,
            data_json TEXT
        )
        """)

    # Tabela de dispositivos (verificar e atualizar)
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='dispositivos'")
    table_exists = cursor.fetchone()
    
    if table_exists:
        cursor.execute("PRAGMA table_info(dispositivos)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'risk_score' not in columns:
            cursor.execute("ALTER TABLE dispositivos ADD COLUMN risk_score INTEGER")
        if 'severity' not in columns:
            cursor.execute("ALTER TABLE dispositivos ADD COLUMN severity TEXT")
        if 'open_ports' not in columns:
            cursor.execute("ALTER TABLE dispositivos ADD COLUMN open_ports TEXT")
        if 'risk_details' not in columns:
            cursor.execute("ALTER TABLE dispositivos ADD COLUMN risk_details TEXT")
    else:
        cursor.execute("""
        CREATE TABLE dispositivos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            ip TEXT,
            nome TEXT,
            mac TEXT,
            fabricante TEXT,
            tipo TEXT,
            attention_score INTEGER,
            risk_score INTEGER,
            severity TEXT,
            open_ports TEXT,
            risk_details TEXT
        )
        """)
    
    # Tabela de alertas
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alertas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        device_mac TEXT,
        device_ip TEXT,
        alert_type TEXT,
        severity TEXT,
        description TEXT,
        recommendations TEXT,
        detected_at TIMESTAMP,
        resolved BOOLEAN DEFAULT 0
    )
    """)
    
    # Tabela de histórico de risco
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS risk_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        device_mac TEXT,
        risk_score INTEGER,
        risk_details TEXT,
        recorded_at TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()
    print("[INFO] Banco de dados SQLite inicializado/atualizado")

def init_database():
    """Alias para iniciar_banco"""
    iniciar_banco()

def salvar_scan(scan_data):
    """Salva scan completo no SQLite"""
    iniciar_banco()
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    try:
        # Inserir scan na tabela scans (sem indicador_medio)
        cursor.execute("""
            INSERT INTO scans (
                timestamp, ambiente, ips_ativos, uso, risco_medio,
                desconhecidos, mac_randomizados, recomendacao, data_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_data.get('timestamp', datetime.now().isoformat()),
            scan_data.get('ambiente', 'Casa'),
            scan_data.get('ips_ativos', 0),
            scan_data.get('uso', 0),
            scan_data.get('risco_medio', 0),
            scan_data.get('desconhecidos', 0),
            scan_data.get('mac_randomizados', 0),
            scan_data.get('recomendacao', 'OK'),
            json.dumps(scan_data, ensure_ascii=False)
        ))
        
        scan_id = cursor.lastrowid
        
        # Inserir dispositivos
        for device in scan_data.get('dispositivos', []):
            open_ports_json = json.dumps(device.get('open_ports', []))
            risk_details_json = json.dumps(device.get('risk_details', []))
            
            cursor.execute("""
                INSERT INTO dispositivos (
                    scan_id, ip, nome, mac, fabricante, tipo, 
                    attention_score, risk_score, severity, open_ports, risk_details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                device.get('ip'),
                device.get('nome', device.get('hostname', 'desconhecido')),
                device.get('mac'),
                device.get('fabricante', 'desconhecido'),
                device.get('tipo', 'desconhecido'),
                device.get('risco', 0),
                device.get('risco', 0),
                device.get('severity', 'Baixo'),
                open_ports_json,
                risk_details_json
            ))
            
            # Registrar histórico de risco
            cursor.execute("""
                INSERT INTO risk_history (scan_id, device_mac, risk_score, risk_details, recorded_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                scan_id,
                device.get('mac'),
                device.get('risco', 0),
                risk_details_json,
                datetime.now().isoformat()
            ))
            
            # Criar alerta para dispositivos de alto risco (>=7)
            if device.get('risco', 0) >= 7:
                recommendations_json = json.dumps(device.get('recommendations', []))
                cursor.execute("""
                    INSERT INTO alertas (
                        scan_id, device_mac, device_ip, alert_type, severity,
                        description, recommendations, detected_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    device.get('mac'),
                    device.get('ip'),
                    'high_risk_device',
                    device.get('severity', 'Alto'),
                    f"Dispositivo com risco {device.get('risco')}/10 detectado",
                    recommendations_json,
                    datetime.now().isoformat()
                ))
        
        conn.commit()
        print(f"[INFO] Scan salvo no SQLite com ID: {scan_id}")
        
    except Exception as e:
        print(f"[ERROR] Erro ao salvar scan: {e}")
        conn.rollback()
    finally:
        conn.close()

def carregar_historico(limit=100):
    """Carrega histórico de scans do SQLite"""
    iniciar_banco()
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT * FROM scans ORDER BY id DESC LIMIT ?
        """, (limit,))
        
        scans = []
        for row in cursor.fetchall():
            # Tenta carregar dados do JSON se existir
            if row['data_json']:
                try:
                    scan_data = json.loads(row['data_json'])
                    scans.append(scan_data)
                except:
                    # Fallback para dados da tabela
                    scan_data = {
                        'timestamp': row['timestamp'],
                        'ambiente': row['ambiente'],
                        'ips_ativos': row['ips_ativos'],
                        'uso': row['uso'],
                        'risco_medio': row['risco_medio'],
                        'dispositivos': []
                    }
                    scans.append(scan_data)
            else:
                # Fallback para dados da tabela
                scan_data = {
                    'timestamp': row['timestamp'],
                    'ambiente': row['ambiente'],
                    'ips_ativos': row['ips_ativos'],
                    'uso': row['uso'],
                    'risco_medio': row['risco_medio'],
                    'dispositivos': []
                }
                scans.append(scan_data)
        
        conn.close()
        return scans
    except Exception as e:
        print(f"[ERROR] Erro ao carregar histórico: {e}")
        conn.close()
        return []

def obter_evolucao_risco():
    """Obtém evolução do risco ao longo do tempo"""
    iniciar_banco()
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT timestamp, risco_medio, ips_ativos
            FROM scans
            WHERE risco_medio IS NOT NULL
            ORDER BY timestamp ASC
        """)
        
        results = [{'date': row[0], 'avg_risk': row[1], 'total_devices': row[2]} 
                   for row in cursor.fetchall()]
        
        conn.close()
        return results
    except Exception as e:
        print(f"[ERROR] Erro ao obter evolução do risco: {e}")
        conn.close()
        return []

def obter_alertas_nao_resolvidos():
    """Obtém alertas não resolvidos"""
    iniciar_banco()
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT * FROM alertas WHERE resolved = 0 ORDER BY detected_at DESC
        """)
        
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results
    except Exception as e:
        print(f"[ERROR] Erro ao obter alertas: {e}")
        conn.close()
        return []

def estatisticas_gerais():
    """Obtém estatísticas gerais do banco"""
    iniciar_banco()
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT COUNT(*) FROM scans")
        total_scans = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(DISTINCT mac) FROM dispositivos WHERE mac IS NOT NULL AND mac != 'desconhecido'")
        total_devices = cursor.fetchone()[0]
        
        cursor.execute("SELECT AVG(risk_score) FROM dispositivos WHERE risk_score IS NOT NULL")
        avg_risk = cursor.fetchone()[0] or 0
        
        cursor.execute("SELECT COUNT(*) FROM alertas WHERE resolved = 0")
        total_alerts = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_scans': total_scans,
            'total_devices_unique': total_devices,
            'avg_risk': round(avg_risk, 2),
            'total_alerts': total_alerts
        }
    except Exception as e:
        print(f"[ERROR] Erro ao obter estatísticas: {e}")
        conn.close()
        return {}

# Funções de compatibilidade
def salvar_historico_json(dados, arquivo="storage/historico_dispositivos.json"):
    os.makedirs('storage', exist_ok=True)
    with open(arquivo, "w") as f:
        json.dump(dados, f, indent=4)

def carregar_historico_json(arquivo="storage/historico_dispositivos.json"):
    if os.path.exists(arquivo):
        with open(arquivo, "r") as f:
            return json.load(f)
    return {}

def obter_ultimo_scan():
    """Obtém o último scan realizado"""
    iniciar_banco()
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1")
        scan = cursor.fetchone()
        
        if scan:
            # Carregar dispositivos
            cursor.execute("""
                SELECT ip, nome, mac, fabricante, tipo, risk_score, severity, open_ports
                FROM dispositivos 
                WHERE scan_id = ?
            """, (scan['id'],))
            devices = cursor.fetchall()
            
            scan_dict = dict(scan)
            scan_dict['dispositivos'] = [dict(d) for d in devices]
            conn.close()
            return scan_dict
        
        conn.close()
        return None
    except Exception as e:
        print(f"[ERROR] Erro ao obter último scan: {e}")
        conn.close()
        return None


print("[INFO] Módulo persistence.py carregado com sucesso")
