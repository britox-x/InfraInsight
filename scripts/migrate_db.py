#!/usr/bin/env python3
"""Script para migrações do banco de dados"""

import sqlite3
import os
import sys
from pathlib import Path

DB_PATH = "storage/infrainsight.db"

def get_current_version():
    if not os.path.exists(DB_PATH):
        return 0
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("PRAGMA user_version")
    version = cursor.fetchone()[0]
    conn.close()
    return version

def set_version(version):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA user_version = {version}")
    conn.commit()
    conn.close()

def migrate_to_v2():
    """Adiciona coluna de fingerprint e last_seen"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Verifica colunas existentes
    cursor.execute("PRAGMA table_info(devices)")
    columns = [col[1] for col in cursor.fetchall()]
    
    if 'fingerprint' not in columns:
        cursor.execute("ALTER TABLE devices ADD COLUMN fingerprint TEXT")
        print("✅ Coluna 'fingerprint' adicionada")
    
    if 'last_seen' not in columns:
        cursor.execute("ALTER TABLE devices ADD COLUMN last_seen TIMESTAMP")
        print("✅ Coluna 'last_seen' adicionada")
    
    # Cria índice
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_fingerprint ON devices(fingerprint)")
    
    conn.commit()
    conn.close()
    set_version(2)
    print("✅ Migração para v2 concluída!")

def migrate_to_v3():
    """Adiciona tabela de eventos/alerts melhorada"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            device_ip TEXT,
            message TEXT,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved BOOLEAN DEFAULT 0
        )
    ''')
    
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity)")
    
    conn.commit()
    conn.close()
    set_version(3)
    print("✅ Migração para v3 concluída!")

def main():
    current = get_current_version()
    print(f"📊 Versão atual do banco: {current}")
    
    if current < 2:
        print("🔄 Aplicando migração para v2...")
        migrate_to_v2()
    
    if current < 3:
        print("🔄 Aplicando migração para v3...")
        migrate_to_v3()
    
    print("✅ Banco atualizado para a versão mais recente!")

if __name__ == "__main__":
    main()
