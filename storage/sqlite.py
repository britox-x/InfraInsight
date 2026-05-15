import sqlite3
import json
import os

DB_PATH = "storage/infrainsight.db"


def iniciar_banco():
    os.makedirs("storage", exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        ambiente TEXT,
        wifi TEXT,
        subrede TEXT,
        gateway TEXT,
        ips_ativos INTEGER,
        uso REAL,
        risco_medio REAL,
        desconhecidos INTEGER,
        mac_randomizados INTEGER,
        novos_dispositivos INTEGER,
        recomendacao TEXT,
        dispositivos TEXT
    )
    """)

    conn.commit()
    conn.close()


def salvar_scan(dados):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO scans (
        timestamp,
        ambiente,
        wifi,
        subrede,
        gateway,
        ips_ativos,
        uso,
        risco_medio,
        desconhecidos,
        mac_randomizados,
        novos_dispositivos,
        recomendacao,
        dispositivos
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        dados["timestamp"],
        dados["ambiente"],
        dados["wifi"],
        dados["subrede"],
        dados["gateway"],
        dados["ips_ativos"],
        dados["uso"],
        dados["risco_medio"],
        dados["desconhecidos"],
        dados["mac_randomizados"],
        dados["novos_dispositivos"],
        dados["recomendacao"],
        json.dumps(dados["dispositivos"])
    ))

    conn.commit()
    conn.close()
