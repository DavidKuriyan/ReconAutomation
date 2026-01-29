import os
import sys
import sys
import time
import json
import sqlite3
from jinja2 import Environment, FileSystemLoader

# Configuration
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
DB_PATH = "aether.db"

def connect_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        return conn
    except Exception as e:
        print(f"Error connecting to DB: {e}")
        return None

def save_finding(target, subdomain):
    conn = connect_db()
    if not conn: return
    cursor = conn.cursor()
    
    # ensure target exists
    cursor.execute("INSERT OR IGNORE INTO targets (domain) VALUES (?)", (target,))
    
    # get target id
    cursor.execute("SELECT id FROM targets WHERE domain = ?", (target,))
    target_id = cursor.fetchone()[0]
    
    # insert subdomain finding
    try:
        cursor.execute("INSERT OR IGNORE INTO subdomains (target_id, subdomain) VALUES (?, ?)", (target_id, subdomain))
        
        # For demo purposes, we also create a "Finding" entry so the report has something to show
        # In reality, this would come from a vulnerability scanner event
        cursor.execute("""
            INSERT INTO findings (target_id, title, severity, description, url) 
            VALUES (?, ?, ?, ?, ?)
        """, (target_id, f"Subdomain Found: {subdomain}", "Low", "Discovered new subdomain during reconnaissance", f"https://{subdomain}"))
        
        conn.commit()
    except Exception as e:
        print(f"Error saving finding: {e}")
    finally:
        conn.close()

def generate_report(target):
    print(f"Generating report for {target}...")
    conn = connect_db()
    if not conn: return

    cursor = conn.cursor()
    
    # Get ID
    cursor.execute("SELECT id FROM targets WHERE domain = ?", (target,))
    res = cursor.fetchone()
    if not res: return
    target_id = res[0]

    # --- FETCH DEEP DATA ---
    
    # 1. Domain Info
    cursor.execute("SELECT registrar, creation_date, expiration_date, registrant_name FROM domain_info WHERE target_id = ?", (target_id,))
    row = cursor.fetchone()
    domain_info = {}
    if row:
        domain_info = {
            "registrar": row[0],
            "created": row[1],
            "expires": row[2],
            "registrant": row[3]
        }
        
    # 2. SSL Info
    cursor.execute("SELECT issuer, valid_to FROM ssl_info WHERE target_id = ?", (target_id,))
    row = cursor.fetchone()
    ssl_info = {}
    if row:
        ssl_info = {"issuer": row[0], "valid_to": row[1]}

    # 3. Ports
    cursor.execute("SELECT port, service, version FROM ports WHERE target_id = ?", (target_id,))
    ports = [{"port": r[0], "service": r[1], "version": r[2]} for r in cursor.fetchall()]

    # 4. DNS
    cursor.execute("SELECT record_type, value, ttl FROM dns_records WHERE target_id = ?", (target_id,))
    dns_records = [{"type": r[0], "value": r[1], "ttl": r[2]} for r in cursor.fetchall()]

    # 5. Technologies
    cursor.execute("SELECT name, category FROM technologies WHERE target_id = ?", (target_id,))
    techs = [{"name": r[0], "category": r[1]} for r in cursor.fetchall()]

    # 6. Directories
    cursor.execute("SELECT path, status_code FROM directories WHERE target_id = ?", (target_id,))
    dirs = [{"path": r[0], "code": r[1]} for r in cursor.fetchall()]

    # 7. Subdomains
    cursor.execute("SELECT subdomain FROM subdomains WHERE target_id = ?", (target_id,))
    subdomains = [r[0] for r in cursor.fetchall()]

    # 8. Findings (Vulnerabilities)
    cursor.execute("SELECT title, severity, description, url FROM findings WHERE target_id = ?", (target_id,))
    findings = [{"title": r[0], "severity": r[1], "description": r[2], "url": r[3]} for r in cursor.fetchall()]

    # 9. Threat Intelligence
    cursor.execute("""
        SELECT source, indicator_type, indicator_value, threat_score, 
               malicious_count, suspicious_count, tags, last_analysis_date
        FROM threat_intel WHERE target_id = ?
    """, (target_id,))
    
    threat_intel = []
    for r in cursor.fetchall():
        threat_intel.append({
            "source": r[0],
            "type": r[1],
            "value": r[2],
            "score": r[3],
            "malicious": r[4],
            "suspicious": r[5],
            "tags": r[6],
            "date": r[7]
        })

    # Define Base Directory for reliable paths
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
    REPORT_DIR = os.path.join(BASE_DIR, 'reports')

    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template('report.html')
    
    html_out = template.render(
        target=target,
        generated_at=time.ctime(),
        domain_info=domain_info,
        ssl_info=ssl_info,
        ports=ports,
        dns_records=dns_records,
        techs=techs,
        dirs=dirs,
        subdomains=subdomains,
        findings=findings,
        threat_intel=threat_intel
    )
    
    report_path = os.path.join(REPORT_DIR, f"{target}_report.html")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_out)
    
    print(f"Report saved to {report_path}")
    conn.close()

def main():
    print("Starting Aether-Recon Reporter (SQLite Mode)...")
    print("Watching local event queue (aether.db)...")
    
    conn = connect_db()
    if not conn:
        print("Failed to connect to DB for event loop.")
        return

    try:
        while True:
            try:
                # Poll for new events
                cursor = conn.cursor()
                cursor.execute("SELECT id, message FROM event_queue WHERE channel = 'scan:subdomain_found' AND processed = 0 LIMIT 1")
                row = cursor.fetchone()
                
                if row:
                    event_id, data = row
                    print(f"Received event: {data}")
                    
                    # Process Event
                    parts = data.split('.')
                    if len(parts) >= 2:
                        target = ".".join(parts[-2:]) 
                        save_finding(target, data)
                        generate_report(target)
                    
                    # Mark as processed
                    cursor.execute("UPDATE event_queue SET processed = 1 WHERE id = ?", (event_id,))
                    conn.commit()
                else:
                    # No events, sleep briefly
                    time.sleep(1)
                    
                cursor.close()
            except sqlite3.Error as e:
                print(f"Database error in loop: {e}")
                time.sleep(1)
            except Exception as e:
                print(f"Error in event loop: {e}")
                time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping reporter...")
    finally:
        conn.close()

if __name__ == "__main__":
    main()
