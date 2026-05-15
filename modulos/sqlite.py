import sqlite3

DB_NAME = "infra_insight.db"


def iniciar_banco():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        ambiente TEXT,
        ips_ativos INTEGER,
        uso REAL,
        risco_medio REAL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS dispositivos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        ip TEXT,
        nome TEXT,
        mac TEXT,
        fabricante TEXT,
        tipo TEXT,
        risco INTEGER
    )
    """)

    conn.commit()
    conn.close()
