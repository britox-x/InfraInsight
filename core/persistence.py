# core/persistence.py - Versão corrigida

import sqlite3
import json
from datetime import datetime
import os
import uuid

DB_NAME = os.getenv("INFRA_DB_PATH", "storage/infrainsight.db")

def iniciar_banco():
    """Inicializa o banco de dados SQLite com schema correto"""
    os.makedirs(os.path.dirname(DB_NAME) or '.', exist_ok=True)
    
    conn = sqlite3.connect(DB_NAME)
    conn.execute("PRAGMA foreign_keys = ON")
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

    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS assets (
        id TEXT PRIMARY KEY,
        identity_key TEXT NOT NULL UNIQUE,
        hostname TEXT,
        os_guess TEXT,
        mac_address TEXT,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS endpoints (
        id TEXT PRIMARY KEY,
        asset_id TEXT NOT NULL REFERENCES assets(id),
        ip_address TEXT NOT NULL,
        port INTEGER NOT NULL,
        protocol TEXT NOT NULL,
        service_name TEXT,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1
    );
    CREATE INDEX IF NOT EXISTS idx_endpoints_active
        ON endpoints(asset_id, ip_address, port, protocol, active);
    CREATE TABLE IF NOT EXISTS software_instances (
        id TEXT PRIMARY KEY,
        asset_id TEXT NOT NULL REFERENCES assets(id),
        endpoint_id TEXT NOT NULL REFERENCES endpoints(id),
        product TEXT NOT NULL,
        version TEXT,
        cpe TEXT,
        confidence INTEGER,
        cpe_source TEXT,
        cve_status TEXT,
        cve_status_reason TEXT,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        UNIQUE(endpoint_id, product, version, cpe)
    );
    CREATE INDEX IF NOT EXISTS idx_software_product_version
        ON software_instances(product, version);
    CREATE TABLE IF NOT EXISTS evidence (
        id TEXT PRIMARY KEY,
        endpoint_id TEXT NOT NULL REFERENCES endpoints(id),
        software_instance_id TEXT REFERENCES software_instances(id),
        evidence_type TEXT NOT NULL,
        raw_value TEXT NOT NULL,
        collected_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS cve_findings (
        id TEXT PRIMARY KEY,
        software_instance_id TEXT NOT NULL REFERENCES software_instances(id),
        cve_id TEXT NOT NULL,
        severity TEXT,
        cvss_score REAL,
        description TEXT,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        UNIQUE(software_instance_id, cve_id)
    );
    CREATE TABLE IF NOT EXISTS cve_cache (
        cpe TEXT PRIMARY KEY,
        payload TEXT NOT NULL,
        fetched_at TIMESTAMP NOT NULL,
        expires_at TIMESTAMP NOT NULL
    );
    """)

    cursor.execute("PRAGMA table_info(software_instances)")
    software_columns = {column[1] for column in cursor.fetchall()}
    for column, definition in (
        ("cpe_source", "TEXT"),
        ("cve_status", "TEXT"),
        ("cve_status_reason", "TEXT"),
    ):
        if column not in software_columns:
            cursor.execute(
                f"ALTER TABLE software_instances ADD COLUMN {column} {definition}"
            )

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
    conn.execute("PRAGMA foreign_keys = ON")
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
        
        # Atualizar inventário por ativo lógico e endpoint observado.
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

            _salvar_servicos(cursor, device, scan_data.get('timestamp'))
        
        conn.commit()
        print(f"[INFO] Scan salvo no SQLite com ID: {scan_id}")
        return scan_id
        
    except Exception as e:
        print(f"[ERROR] Erro ao salvar scan: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()


def _salvar_servicos(cursor, device, observed_at=None):
    """Persiste endpoints, software identificado, evidências e CVEs."""
    now = observed_at or datetime.now().isoformat()
    mac = str(device.get('mac') or '').strip().lower()
    hostname = str(device.get('hostname') or device.get('nome') or '').strip()
    os_guess = str(device.get('os_guess') or '').strip()
    ip_address = str(device.get('ip') or '').strip()
    hostname_identity = hostname.casefold().rstrip('.')
    if hostname_identity in {'desconhecido', 'unknown', 'none'}:
        hostname_identity = ''
    if mac and mac not in {'desconhecido', 'unknown', 'none'}:
        identity_key = f"mac:{mac}"
    elif hostname_identity:
        identity_key = f"hostname:{hostname_identity}"
    elif ip_address:
        identity_key = f"ip:{ip_address}"
    else:
        raise ValueError("Dispositivo precisa de MAC, hostname ou IP para criar um ativo.")

    cursor.execute("SELECT id FROM assets WHERE identity_key = ?", (identity_key,))
    asset = cursor.fetchone()
    if asset:
        asset_id = asset[0]
        cursor.execute(
            """
            UPDATE assets
            SET hostname = COALESCE(NULLIF(?, ''), hostname),
                os_guess = COALESCE(NULLIF(?, ''), os_guess),
                mac_address = COALESCE(NULLIF(?, ''), mac_address),
                last_seen = ?
            WHERE id = ?
            """,
            (hostname, os_guess, mac, now, asset_id),
        )
    else:
        asset_id = str(uuid.uuid4())
        cursor.execute(
            """
            INSERT INTO assets
                (id, identity_key, hostname, os_guess, mac_address, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                asset_id, identity_key, hostname or None, os_guess or None,
                mac or None, now, now,
            ),
        )

    if ip_address:
        cursor.execute(
            "UPDATE endpoints SET active = 0, last_seen = ? "
            "WHERE asset_id = ? AND ip_address <> ? AND active = 1",
            (now, asset_id, ip_address),
        )

    for service in device.get('services', []):
        port = service.get('port')
        protocol = str(service.get('protocol') or 'tcp').lower()
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError(f"Porta inválida no serviço: {port!r}")
        if protocol not in {'tcp', 'udp'} or not ip_address:
            raise ValueError("Serviço precisa de protocolo TCP/UDP e IP de endpoint.")

        product = str(service.get('product') or '').strip()
        version = str(service.get('version') or '').strip() or None
        cpe = str(service.get('cpe') or '').strip() or None
        service_name = str(service.get('service') or '').strip() or None

        cursor.execute(
            """
            SELECT e.id, s.product, s.version, s.cpe
            FROM endpoints e
            LEFT JOIN software_instances s ON s.endpoint_id = e.id
            WHERE e.asset_id = ? AND e.ip_address = ? AND e.port = ?
              AND e.protocol = ? AND e.active = 1
            ORDER BY s.last_seen DESC LIMIT 1
            """,
            (asset_id, ip_address, port, protocol),
        )
        current = cursor.fetchone()
        endpoint_id = current[0] if current else None
        if current and product and (current[1], current[2], current[3]) != (
            product, version, cpe
        ):
            cursor.execute(
                "UPDATE endpoints SET active = 0, last_seen = ? WHERE id = ?",
                (now, endpoint_id),
            )
            endpoint_id = None

        if endpoint_id is None:
            endpoint_id = str(uuid.uuid4())
            cursor.execute(
                """
                INSERT INTO endpoints
                    (id, asset_id, ip_address, port, protocol, service_name,
                     first_seen, last_seen, active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (
                    endpoint_id, asset_id, ip_address, port, protocol,
                    service_name, now, now,
                ),
            )
        else:
            cursor.execute(
                "UPDATE endpoints SET service_name = COALESCE(?, service_name), "
                "last_seen = ? WHERE id = ?",
                (service_name, now, endpoint_id),
            )

        software_id = None
        if product:
            cursor.execute(
                """
                SELECT id FROM software_instances
                WHERE endpoint_id = ? AND product = ?
                  AND COALESCE(version, '') = COALESCE(?, '')
                  AND COALESCE(cpe, '') = COALESCE(?, '')
                """,
                (endpoint_id, product, version, cpe),
            )
            software = cursor.fetchone()
            if software:
                software_id = software[0]
                cursor.execute(
                    "UPDATE software_instances SET last_seen = ?, "
                    "confidence = COALESCE(?, confidence), "
                    "cpe_source = COALESCE(?, cpe_source), "
                    "cve_status = COALESCE(?, cve_status), "
                    "cve_status_reason = ? WHERE id = ?",
                    (
                        now,
                        service.get('confidence'),
                        service.get('cpe_source'),
                        service.get('cve_status'),
                        service.get('cve_status_reason'),
                        software_id,
                    ),
                )
            else:
                software_id = str(uuid.uuid4())
                cursor.execute(
                    """
                    INSERT INTO software_instances
                        (id, asset_id, endpoint_id, product, version, cpe,
                         confidence, cpe_source, cve_status, cve_status_reason,
                         first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        software_id, asset_id, endpoint_id, product, version, cpe,
                        service.get('confidence'), service.get('cpe_source'),
                        service.get('cve_status'), service.get('cve_status_reason'),
                        now, now,
                    ),
                )

            for cve in service.get('cves', []):
                cve_id = str(cve.get('cve_id') or cve.get('id') or '').strip()
                if not cve_id:
                    continue
                cursor.execute(
                    """
                    INSERT INTO cve_findings
                        (id, software_instance_id, cve_id, severity, cvss_score,
                         description, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(software_instance_id, cve_id) DO UPDATE SET
                        severity = excluded.severity,
                        cvss_score = excluded.cvss_score,
                        description = excluded.description,
                        last_seen = excluded.last_seen
                    """,
                    (
                        str(uuid.uuid4()), software_id, cve_id,
                        cve.get('severity'), cve.get('cvss_score'),
                        cve.get('description'), now, now,
                    ),
                )

        evidence = service.get('evidence')
        if evidence:
            cursor.execute(
                """
                INSERT INTO evidence
                    (id, endpoint_id, software_instance_id, evidence_type,
                     raw_value, collected_at)
                VALUES (?, ?, ?, 'nmap_service', ?, ?)
                """,
                (str(uuid.uuid4()), endpoint_id, software_id, str(evidence), now),
            )


def obter_inventario_software():
    """Retorna software observado em endpoints ativos, com CVEs conhecidos."""
    iniciar_banco()
    conn = sqlite3.connect(DB_NAME)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT a.id AS asset_id, a.hostname, a.mac_address,
                   e.ip_address, e.port, e.protocol, e.service_name,
                   s.id AS software_instance_id, s.product, s.version, s.cpe,
                   s.confidence, s.cpe_source, s.cve_status,
                   s.cve_status_reason, s.first_seen, s.last_seen,
                   GROUP_CONCAT(c.cve_id, ', ') AS cve_ids
            FROM endpoints e
            JOIN assets a ON a.id = e.asset_id
            LEFT JOIN software_instances s ON s.endpoint_id = e.id
            LEFT JOIN cve_findings c ON c.software_instance_id = s.id
            WHERE e.active = 1
            GROUP BY e.id, s.id
            ORDER BY s.product, s.version, a.hostname, e.ip_address, e.port
            """
        ).fetchall()
        return [dict(row) for row in rows]
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
