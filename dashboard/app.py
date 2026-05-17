from flask import Flask, render_template
import sqlite3
import os

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'storage', 'infrainsight.db')


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def index():
    conn = get_db_connection()

    # Total de scans registrados
    total_scans = conn.execute(
        "SELECT COUNT(*) as count FROM scans"
    ).fetchone()["count"]

    # Último scan
    latest_scan = conn.execute("""
        SELECT *
        FROM scans
        ORDER BY id DESC
        LIMIT 1
    """).fetchone()

    # Histórico recente
    recent_scans = conn.execute("""
        SELECT timestamp, ips_ativos, risco_medio, desconhecidos, novos_dispositivos
        FROM scans
        ORDER BY id DESC
        LIMIT 10
    """).fetchall()

    conn.close()

    return render_template(
        "index.html",
        total_scans=total_scans,
        latest_scan=latest_scan,
        recent_scans=recent_scans
    )


if __name__ == "__main__":
    app.run(debug=True)
@app.route("/history")
def history():
    conn = get_db_connection()

    scans = conn.execute("""
        SELECT *
        FROM scans
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return render_template("history.html", scans=scans)
