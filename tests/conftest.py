import pytest
import json
import tempfile
import sqlite3
from pathlib import Path

@pytest.fixture
def sample_device_data():
    return [
        {
            'ip': '192.168.1.1',
            'mac': '00:11:22:33:44:55',
            'vendor': 'TP-Link',
            'hostname': 'router.local',
            'type': 'roteador',
            'ports': [80, 443]
        },
        {
            'ip': '192.168.1.100',
            'mac': 'AA:BB:CC:DD:EE:FF',
            'vendor': 'Apple',
            'hostname': 'iPhone',
            'type': 'smartphone',
            'ports': []
        }
    ]

@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
        conn = sqlite3.connect(tmp.name)
        yield conn
        conn.close()
        Path(tmp.name).unlink()
