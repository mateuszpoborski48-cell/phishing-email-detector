
import sqlite3
import json
from pathlib import Path
from datetime import datetime, timezone

# Store database inside the backend folder
DATABASE_PATH = Path(__file__).resolve().parent / "phishing_scans.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialise_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_date TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                warning_count INTEGER NOT NULL,
                warnings TEXT NOT NULL
            )
        """)


def save_scan(result):
    scan_date = datetime.now(timezone.utc).isoformat()
    warnings = result.get("warnings", [])

    with get_connection() as connection:
        cursor = connection.execute("""
            INSERT INTO scans (
                scan_date,
                risk_score,
                risk_level,
                warning_count,
                warnings
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            scan_date,
            result["risk_score"],
            result["risk_level"],
            len(warnings),
            json.dumps(warnings),
        ))

        return cursor.lastrowid


def get_scan_history(limit=50):
    limit = max(1, min(int(limit), 100))

    with get_connection() as connection:
        rows = connection.execute("""
            SELECT *
            FROM scans
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    history = []

    for row in rows:
        scan = dict(row)
        scan["warnings"] = json.loads(scan["warnings"])
        history.append(scan)

    return history


def get_scan_statistics():
    with get_connection() as connection:
        row = connection.execute("""
            SELECT
                COUNT(*) AS total_scans,
                COALESCE(AVG(risk_score), 0) AS average_risk,
                SUM(CASE WHEN risk_level = 'High'
                    THEN 1 ELSE 0 END) AS high_risk,
                SUM(CASE WHEN risk_level = 'Medium'
                    THEN 1 ELSE 0 END) AS medium_risk,
                SUM(CASE WHEN risk_level = 'Low'
                    THEN 1 ELSE 0 END) AS low_risk
            FROM scans
        """).fetchone()

    return dict(row)


# Initialise automatically when imported
initialise_database()
