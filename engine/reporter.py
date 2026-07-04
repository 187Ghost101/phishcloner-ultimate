"""
PhishCloner Engine — Module 8: Auto-Reporter PDF
Signé Ghost1o1 — v1.0.0

Génère des rapports PDF professionnels avec CVSS 3.1, executive summary,
timeline, credentials table, findings, remediation.
"""

import asyncio
import json
import logging
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("PhishCloner.Reporter")


class CVSSCalculator:
    """Calcule un score CVSS 3.1 simplifié."""

    @staticmethod
    def calculate(av="N", ac="L", pr="N", ui="R", s="U", c="H", i="H", a="N") -> Tuple[float, str]:
        base_scores = {
            ("N","L","N","N","U","H","H","H"): 9.8,
            ("N","L","N","N","U","H","H","N"): 8.2,
            ("N","L","N","R","U","H","H","N"): 8.8,
            ("N","L","N","R","U","H","L","N"): 7.4,
            ("N","L","L","N","U","H","H","N"): 8.1,
            ("N","H","N","R","U","H","H","N"): 7.5,
        }
        key = (av, ac, pr, ui, s, c, i, a)
        score = base_scores.get(key, 6.5)
        severity = (
            "CRITICAL" if score >= 9.0 else
            "HIGH" if score >= 7.0 else
            "MEDIUM" if score >= 4.0 else "LOW"
        )
        return score, severity

    @staticmethod
    def vector_string(av="N", ac="L", pr="N", ui="R", s="U", c="H", i="H", a="N") -> str:
        return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"


class AutoReporter:
    """Génère un rapport de pentest pro à partir des données de campagne."""

    def __init__(self, campaign_data: Dict, output_dir: str = "reports"):
        self.campaign = campaign_data
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.session_id = campaign_data.get("session_id", datetime.utcnow().strftime("%Y%m%d_%H%M%S"))
        self.author = "ghost1o1"
        self.company = "GhostNet Security"
        self.cvss = CVSSCalculator()

    def _build_timeline(self) -> List[Dict]:
        events = [{
            "time": self.campaign.get("start_time", datetime.utcnow().isoformat()),
            "phase": "INIT",
            "description": f"Campaign initiated against {self.campaign.get('target_url', 'target')}",
            "severity": "INFO",
        }]
        for cred in self.campaign.get("credentials", []):
            events.append({
                "time": cred.get("timestamp", datetime.utcnow().isoformat()),
                "phase": "CAPTURE",
                "description": f"Credentials captured for {cred.get('username')}",
                "severity": "HIGH" if cred.get("is_admin") else "MEDIUM",
            })
        for mfa in self.campaign.get("mfa_tokens", []):
            events.append({
                "time": mfa.get("timestamp", datetime.utcnow().isoformat()),
                "phase": "MFA_RELAY",
                "description": f"MFA token relayed for provider: {mfa.get('provider', 'unknown')}",
                "severity": "HIGH",
            })
        return sorted(events, key=lambda e: e["time"])

    def _build_findings(self) -> List[Dict]:
        findings = []
        creds = self.campaign.get("credentials", [])
        if creds:
            admin_creds = [c for c in creds if c.get("is_admin")]
            if admin_creds:
                score, sev = self.cvss.calculate(av="N", ac="L", pr="N", ui="R", c="H", i="H", a="H")
                findings.append({
                    "id": "PHISH-001",
                    "title": "Administrative Credential Compromise via Phishing",
                    "description": f"Captured credentials for {len(admin_creds)} admin-level accounts",
                    "cvss_score": score,
                    "cvss_vector": self.cvss.vector_string(c="H", i="H", a="H"),
                    "severity": sev,
                    "impact": "Full system compromise via administrative access",
                    "remediation": "1. Rotate all compromised credentials immediately\n2. Implement phishing-resistant MFA (FIDO2/WebAuthn)\n3. Deploy DMARC/DKIM/SPF email protections\n4. Conduct organization-wide phishing awareness training",
                })
            non_admin = [c for c in creds if not c.get("is_admin")]
            if non_admin:
                score, sev = self.cvss.calculate(av="N", ac="L", pr="N", ui="R", c="H", i="L", a="N")
                findings.append({
                    "id": "PHISH-002",
                    "title": "User Credential Compromise via Phishing",
                    "description": f"Captured credentials for {len(non_admin)} user-level accounts",
                    "cvss_score": score,
                    "cvss_vector": self.cvss.vector_string(c="H", i="L", a="N"),
                    "severity": sev,
                    "impact": "Unauthorized access to user data",
                    "remediation": "Same as PHISH-001 — rotate credentials, enable MFA",
                })
        if self.campaign.get("mfa_tokens"):
            score, sev = self.cvss.calculate(av="N", ac="L", pr="N", ui="R", c="H", i="H", a="N")
            findings.append({
                "id": "PHISH-003",
                "title": "Multi-Factor Authentication Bypass",
                "description": f"Relayed {len(self.campaign['mfa_tokens'])} MFA tokens via AiTM",
                "cvss_score": score,
                "cvss_vector": self.cvss.vector_string(c="H", i="H", a="N"),
                "severity": sev,
                "impact": "MFA protections rendered ineffective",
                "remediation": "1. Transition to phishing-resistant MFA (FIDO2)\n2. Implement token binding\n3. Deploy Conditional Access policies",
            })
        return findings

    def _build_executive_summary(self, findings: List[Dict]) -> str:
        total = len(findings)
        critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in findings if f["severity"] == "HIGH")
        medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
        risk_level = "CRITICAL" if critical else "HIGH" if high else "MEDIUM" if medium else "LOW"

        return f"""
## EXECUTIVE SUMMARY

**Engagement Type:** Authorized Phishing Simulation
**Target:** {self.campaign.get('target_url', 'Target Organization')}
**Date:** {datetime.utcnow().strftime('%B %d, %Y')}
**Assessor:** {self.author} — {self.company}

**Overall Risk Rating: {risk_level}**

### Key Findings
- {critical} Critical — Immediate remediation required
- {high} High — Significant risk
- {medium} Medium — Moderate risk

### Immediate Actions
1. Rotate all compromised credentials
2. Implement phishing-resistant MFA
3. Deploy email security controls
4. Conduct awareness training

*Report by PhishCloner Ultimate | ghost1o1*
""".strip()

    def _generate_html(self, exec_summary: str, timeline: List[Dict],
                       findings: List[Dict], credentials: List[Dict]) -> str:
        findings_html = ""
        for f in findings:
            color = {"CRITICAL": "#8b0000", "HIGH": "#cc0000", "MEDIUM": "#cc6600", "LOW": "#666600"}.get(f["severity"], "#333")
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color};">
                <div class="finding-header">
                    <span class="finding-id">{f['id']}</span>
                    <span class="finding-severity" style="background:{color};">{f['severity']}</span>
                    <span class="finding-cvss">CVSS: {f['cvss_score']}</span>
                </div>
                <h3>{f['title']}</h3>
                <p><strong>Description:</strong> {f['description']}</p>
                <p><strong>CVSS Vector:</strong> <code>{f.get('cvss_vector', 'N/A')}</code></p>
                <p><strong>Impact:</strong> {f['impact']}</p>
                <div class="remediation"><strong>Remediation:</strong><pre>{f['remediation']}</pre></div>
            </div>"""

        creds_html = ""
        for c in credentials:
            admin_badge = ' <span style="background:#8b0000;color:white;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:bold;">ADMIN</span>' if c.get("is_admin") else ''
            creds_html += f"""<tr>
                <td>{c.get('username','?')}</td>
                <td>{'********'}</td>
                <td>{c.get('source_ip','?')}</td>
                <td>{c.get('user_agent','?')[:60]}</td>
                <td>{admin_badge}</td>
                <td>{c.get('validated', False)}</td>
            </tr>"""

        events_html = ""
        for e in timeline:
            events_html += f"""<tr>
                <td>{e.get('time','?')[:19]}</td>
                <td>{e.get('phase','?')}</td>
                <td>{e.get('description','?')}</td>
                <td>{e.get('severity','?')}</td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Pentest Report — PhishCloner Ultimate | ghost1o1</title>
    <style>
        @page {{ size: A4; margin: 2cm; }}
        body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; max-width: 900px; margin: 0 auto; padding: 20px; color: #1a1a1a; }}
        .cover {{ text-align: center; padding: 60px 0; border-bottom: 3px solid #cc0000; margin-bottom: 40px; }}
        .cover h1 {{ font-size: 36px; color: #cc0000; }}
        h2 {{ color: #cc0000; border-bottom: 2px solid #cc0000; padding-bottom: 8px; }}
        .finding {{ background: #fafafa; padding: 16px; margin: 16px 0; border-radius: 4px; }}
        .finding-header {{ display: flex; gap: 12px; align-items: center; margin-bottom: 8px; }}
        .finding-id {{ font-weight: bold; color: #cc0000; font-family: monospace; }}
        .finding-severity {{ color: white; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: bold; }}
        .remediation {{ background: #f5f5f5; padding: 12px; border-radius: 4px; margin-top: 8px; }}
        .remediation pre {{ font-size: 13px; white-space: pre-wrap; margin: 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 13px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #f0f0f0; }}
        code {{ background: #f5f5f5; padding: 1px 4px; border-radius: 2px; }}
        .watermark {{ position: fixed; top: 50%; left: 50%; transform: translate(-50%,-50%) rotate(-30deg); font-size: 120px; color: rgba(0,0,0,0.03); pointer-events: none; }}
    </style>
</head>
<body>
    <div class="watermark">GHOST1O1</div>

    <div class="cover">
        <h1>PENTEST REPORT</h1>
        <p>Phishing Simulation & Security Assessment</p>
        <p><strong>Target:</strong> {self.campaign.get('target_url','Confidential')}</p>
        <p><strong>Date:</strong> {datetime.utcnow().strftime('%B %d, %Y')}</p>
        <p><strong>Assessor:</strong> {self.author} — {self.company}</p>
    </div>

    <h2>1. Executive Summary</h2>
    <pre>{exec_summary}</pre>

    <h2>2. Campaign Timeline</h2>
    <table>
        <thead><tr><th>Timestamp</th><th>Phase</th><th>Event</th><th>Severity</th></tr></thead>
        <tbody>{events_html}</tbody>
    </table>

    <h2>3. Findings & Vulnerabilities</h2>
    {findings_html}

    <h2>4. Compromised Credentials</h2>
    <table>
        <thead><tr><th>Username</th><th>Password</th><th>Source IP</th><th>User-Agent</th><th>Role</th><th>Validated</th></tr></thead>
        <tbody>{creds_html}</tbody>
    </table>

    <h2>5. Remediation Roadmap</h2>
    <table>
        <thead><tr><th>Priority</th><th>Action</th><th>Timeline</th></tr></thead>
        <tbody>
            <tr><td>1</td><td>Rotate all compromised credentials</td><td>24h</td></tr>
            <tr><td>2</td><td>Revoke all unauthorized OAuth apps</td><td>48h</td></tr>
            <tr><td>3</td><td>Implement phishing-resistant MFA (FIDO2)</td><td>30d</td></tr>
            <tr><td>4</td><td>Deploy DMARC/DKIM/SPF</td><td>30d</td></tr>
            <tr><td>5</td><td>Phishing awareness training</td><td>60d</td></tr>
            <tr><td>6</td><td>Conditional Access / Zero Trust</td><td>90d</td></tr>
        </tbody>
    </table>

    <p style="text-align: center; margin-top: 60px; color: #888; font-size: 12px;">
        PhishCloner Ultimate v1.0.0 — GhostNet Security<br>
        © {datetime.utcnow().year} ghost1o1
    </p>
</body>
</html>"""

    async def generate(self, format: str = "html") -> Path:
        log.info(f"Generating {format} report for session {self.session_id}")

        timeline = self._build_timeline()
        findings = self._build_findings()
        exec_summary = self._build_executive_summary(findings)
        credentials = self.campaign.get("credentials", [])

        html_content = self._generate_html(exec_summary, timeline, findings, credentials)

        if format == "html-only":
            report_path = self.output_dir / f"report_{self.session_id}.html"
            report_path.write_text(html_content, encoding="utf-8")
            return report_path

        html_path = self.output_dir / f"report_{self.session_id}.html"
        html_path.write_text(html_content, encoding="utf-8")

        if format == "html":
            pdf_path = self.output_dir / f"report_{self.session_id}.pdf"
            try:
                from weasyprint import HTML
                HTML(string=html_content).write_pdf(str(pdf_path))
                log.info(f"PDF (WeasyPrint): {pdf_path}")
                return pdf_path
            except ImportError:
                pass
            try:
                from playwright.async_api import async_playwright
                async with async_playwright() as p:
                    browser = await p.chromium.launch(headless=True)
                    page = await browser.new_page()
                    await page.set_content(html_content)
                    await page.pdf(path=str(pdf_path), format="A4", print_background=True)
                    await browser.close()
                log.info(f"PDF (Playwright): {pdf_path}")
                return pdf_path
            except ImportError:
                log.warning("No PDF backend available — HTML only")
                return html_path

        return html_path


async def generate_report(campaign_data: Dict, output_dir: str = "reports", format: str = "html") -> Path:
    reporter = AutoReporter(campaign_data, output_dir)
    return await reporter.generate(format)
