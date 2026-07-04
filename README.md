# 🎣 PhishCloner Ultimate v3.0 — C2 Nocturne

> **"There is no lock."** — **ghost1o1**

Framework **AiTM (Adversary-in-the-Middle) phishing** : 20 brand templates, 9 engine modules, MITM proxy + TLS spoofing + MFA relay + exfil. 100% Docker-ready, 0 CDN, 0 télémétrie.

```
PhishCloner Ultimate v3.0
   ╔═══════════════════════════════════════╗
   ║  20 BRANDS · 9 ENGINES · C2 NOCTURNE ║
   ║  TLS SPOOF · MFA RELAY · C2 + WS      ║
   ╚═══════════════════════════════════════╝
```

## ⚡ Aperçu

| Spec | Valeur |
|------|--------|
| **Version** | 3.0 "C2 Nocturne" |
| **Dashboard** | 32 KB (single-file HTML) |
| **Engine** | 9 modules Python (2206 lignes) |
| **Templates** | 20 brands (M365, Google, Okta, GitHub, AWS, Azure, LinkedIn, etc.) |
| **Dépendances** | Python 3.12+ · Docker optionnel |
| **CDN** | 0 (brand layer 100% locale) |
| **Télémétrie** | 0 |

## 🎯 9 engine modules

1. **TLS Spoofer** — génération de certs fake on-the-fly
2. **MITM Proxy** — reverse proxy AiTM interception HTTP/HTTPS
3. **MFA Relay** — relay temps réel des codes MFA
4. **Cred Validator** — auto-test des creds capturées
5. **Exfil Engine** — exfiltration async disk + network
6. **Delivery** — SMS / email / QR delivery
7. **Proxy Pool** — rotation d'IPs de sortie
8. **Reporter** — génération rapport PDF + HTML
9. **Template Loader** — hot-swap brand templates

## 🎯 20 brand templates

`microsoft` · `google` · `okta` · `github` · `gitlab` · `aws` · `azure` · `linkedin` · `facebook` · `slack` · `duo` · `salesforce` · `servicenow` · `dropbox` · `cisco_anyconnect` · `citrix` · `fortigate` · `paloalto` · `apple` · `manifest`

## 📦 Installation

Voir [INSTALL.md](INSTALL.md).

Quick start :
```bash
git clone https://github.com/187Ghost101/phishcloner-ultimate.git
cd phishcloner-ultimate
chmod +x setup.sh
./setup.sh
# Lancer dashboard
python3 -m http.server 8090 --directory .
# Ouvre http://localhost:8090/c2_admin.html
```

## 📖 Utilisation

Voir [USAGE.md](USAGE.md).

### Workflow red team
1. Cible : `https://login.microsoftonline.com/`
2. Brand : `microsoft`
3. LHOST : `0.0.0.0` / LPORT : `8443`
4. Deploy → victime reçoit URL phishing
5. Creds + tokens capturés
6. MFA relay live
7. Export rapport JSON/HTML

## 🔒 Usage autorisé uniquement

⚠️ **AVERTISSEMENT** : PhishCloner Ultimate est destiné aux **red team autorisés** et **adversary simulation sous scope écrit et autorisation explicite**. Le phishing non-autorisé est **illégal** et passible de poursuites.

## 📂 Structure

```
phishcloner-ultimate/
├── c2_admin.html          # 32 KB — C2 Nocturne dashboard
├── ghost1o1.{css,js}      # design system
├── engine/                # 9 modules Python
│   ├── tls_spoofer.py
│   ├── mitm_proxy.py
│   ├── mfa_relay.py
│   ├── cred_validator.py
│   ├── exfil.py
│   ├── delivery.py
│   ├── proxy_pool.py
│   ├── reporter.py
│   └── template_loader.py
├── templates/             # 20 brand templates
│   ├── microsoft/
│   ├── google/
│   ├── okta/
│   └── ... (17 autres)
├── Dockerfile             # Docker build
├── docker-compose.yml     # orchestration
├── Makefile               # build/test/deploy
├── requirements.txt       # Python deps
├── setup.sh               # installateur
├── README.md
├── INSTALL.md
├── USAGE.md
└── GHOST1O1_BRAND.md
```

---

**© 2026 ghost1o1 · GHOST1O1 Nocturne v1.1**
