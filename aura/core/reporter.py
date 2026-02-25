import sqlite3
import json
import os
from jinja2 import Template
from datetime import datetime

class AuraReporter:
    """Generates professional security reports from Aura's database."""
    
    HTML_TEMPLATE = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>AURA - Offensive Intelligence Report</title>
        <style>
            :root { --primary: #7d00ff; --danger: #ff0044; --bg: #0a0a0c; --text: #e0e0e0; }
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 40px; }
            .container { max-width: 1000px; margin: 0 auto; }
            header { border-bottom: 2px solid var(--primary); padding-bottom: 20px; margin-bottom: 40px; }
            h1 { color: var(--primary); text-transform: uppercase; letter-spacing: 4px; font-size: 3em; margin: 0; }
            .summary-box { background: #16161d; padding: 25px; border-radius: 8px; border-left: 5px solid var(--primary); margin-bottom: 30px; }
            .target-card { background: #1c1c24; margin-bottom: 20px; padding: 20px; border-radius: 8px; border: 1px solid #333; }
            .priority-CRITICAL { border-left: 5px solid var(--danger); }
            .priority-HIGH { border-left: 5px solid #ffaa00; }
            .priority-MEDIUM { border-left: 5px solid #00aaff; }
            .screenshot-box { margin-top: 15px; border: 1px solid #444; border-radius: 4px; overflow: hidden; max-height: 300px; }
            .screenshot-box img { width: 100%; height: auto; display: block; }
            .badge { padding: 4px 10px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }
            .badge-red { background: var(--danger); }
            table { width: 100%; border-collapse: collapse; margin-top: 15px; }
            th, td { text-align: left; padding: 12px; border-bottom: 1px solid #333; }
            th { color: var(--primary); text-transform: uppercase; font-size: 0.9em; }
            .finding { color: #00ff88; font-family: monospace; font-size: 0.9em; }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>AURA</h1>
                <p>Offensive Intelligence Framework | Generated: {{ timestamp }}</p>
            </header>

            <div class="summary-box">
                <h2>Executive Summary</h2>
                <p>Total Targets Analyzed: <strong>{{ targets|length }}</strong></p>
                <p>Critical Attack Paths Identified: <strong>{{ critical_count }}</strong></p>
            </div>

            <h2>Detailed Target Analysis</h2>
            {% for target in targets %}
            <div class="target-card priority-{{ target.priority }}">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <h3>{{ target.value }}</h3>
                    <span class="badge {% if target.priority == 'CRITICAL' %}badge-red{% endif %}">{{ target.priority }}</span>
                </div>
                <p><strong>Risk Score:</strong> {{ target.risk_score }} | <strong>Source:</strong> {{ target.source }}</p>
                
                {% if target.screenshot %}
                <div class="screenshot-box">
                    <img src="{{ target.screenshot }}" alt="Target Screenshot">
                </div>
                {% endif %}

                {% if target.findings %}
                <h4>Findings & Exploitations</h4>
                <table>
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Detail</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for finding in target.findings %}
                        <tr>
                            <td>{{ finding.finding_type }}</td>
                            <td class="finding">{{ finding.content }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% endif %}
            </div>
            {% endfor %}
        </div>
    </body>
    </html>
    """

    def __init__(self, db_path="aura_intel.db"):
        self.db_path = db_path

    def generate_report(self, output_path="aura_report.html"):
        """Compiles facts from the database and renders the HTML report."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Fetch targets
            cursor.execute("SELECT * FROM targets ORDER BY risk_score DESC")
            targets = [dict(row) for row in cursor.fetchall()]
            
            critical_count = 0
            for target in targets:
                if target["priority"] == "CRITICAL":
                    critical_count += 1
                
                # Fetch findings for each target
                cursor.execute("SELECT content, finding_type FROM findings WHERE target_id = ?", (target["id"],))
                target["findings"] = [dict(row) for row in cursor.fetchall()]
                
                # Check if a screenshot exists in the filesystem
                screenshot_path = f"screenshots/target_{target['id']}.png"
                if os.path.exists(os.path.join(os.path.dirname(output_path), screenshot_path)):
                    target["screenshot"] = screenshot_path
                else:
                    target["screenshot"] = None

        # Render template
        template = Template(self.HTML_TEMPLATE)
        report_html = template.render(
            targets=targets,
            critical_count=critical_count,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_html)
        
        return output_path
