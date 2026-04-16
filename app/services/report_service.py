import csv
import io
import json
from datetime import datetime
from jinja2 import Template
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.asset import AIAsset
from app.models.threat import ThreatEvent
from app.models.vulnerability import Vulnerability

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Specter Report — {{ title }}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 40px; color: #111; }
  h1 { color: #1e293b; }
  table { width: 100%; border-collapse: collapse; margin-top: 20px; }
  th { background: #1e293b; color: white; padding: 10px 12px; text-align: left; }
  td { padding: 8px 12px; border-bottom: 1px solid #e2e8f0; }
  tr:nth-child(even) { background: #f8fafc; }
  .critical { color: #dc2626; font-weight: 600; }
  .high { color: #ea580c; font-weight: 600; }
  .medium { color: #ca8a04; }
  .low { color: #16a34a; }
  .footer { margin-top: 40px; color: #64748b; font-size: 12px; }
</style>
</head>
<body>
<h1>Specter Security Report — {{ title }}</h1>
<p>Generated: {{ generated_at }}</p>
<table>
  <thead><tr>{% for col in columns %}<th>{{ col }}</th>{% endfor %}</tr></thead>
  <tbody>
  {% for row in rows %}
  <tr>{% for cell in row %}<td class="{{ cell.lower() if cell in ('critical','high','medium','low') else '' }}">{{ cell }}</td>{% endfor %}</tr>
  {% endfor %}
  </tbody>
</table>
<div class="footer">Specter AI Security Monitoring Platform</div>
</body>
</html>
"""


async def export_assets(db: AsyncSession, fmt: str) -> tuple[str, str, str]:
    result = await db.execute(select(AIAsset))
    assets = result.scalars().all()
    columns = ["Name", "Type", "Provider", "Namespace", "Risk Score", "First Seen"]
    rows = [[a.name, a.asset_type, a.provider, a.namespace or "", str(a.risk_score), str(a.first_seen)] for a in assets]
    return _render(fmt, "Asset Inventory", columns, rows)


async def export_threats(db: AsyncSession, fmt: str) -> tuple[str, str, str]:
    result = await db.execute(select(ThreatEvent))
    threats = result.scalars().all()
    columns = ["Title", "Severity", "Category", "MITRE ATLAS", "Detected At"]
    rows = [[t.title, t.severity, t.category, t.mitre_atlas or "", str(t.detected_at)] for t in threats]
    return _render(fmt, "Threat Events", columns, rows)


async def export_vulns(db: AsyncSession, fmt: str) -> tuple[str, str, str]:
    result = await db.execute(select(Vulnerability))
    vulns = result.scalars().all()
    columns = ["Title", "Severity", "Category", "CVSS", "First Seen"]
    rows = [[v.title, v.severity, v.category, str(v.cvss_score or ""), str(v.first_seen)] for v in vulns]
    return _render(fmt, "Vulnerabilities", columns, rows)


def _render(fmt: str, title: str, columns: list, rows: list) -> tuple[str, str, str]:
    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(columns)
        writer.writerows(rows)
        return buf.getvalue(), "text/csv", f"{title.replace(' ', '_')}.csv"
    elif fmt == "json":
        data = [dict(zip(columns, row)) for row in rows]
        return json.dumps(data, indent=2), "application/json", f"{title.replace(' ', '_')}.json"
    else:  # html
        tmpl = Template(HTML_TEMPLATE)
        content = tmpl.render(title=title, columns=columns, rows=rows, generated_at=datetime.utcnow().isoformat())
        return content, "text/html", f"{title.replace(' ', '_')}.html"
