<div align="center">

```
   ▄█████ █  ██  ▄█████ ▄█████▄  ██   ██ ▄█████ █    ██  ██ ██    ██
  ██      ██▄██  ██     ██   ██  ██▄▄▄██ ██     ██    ██  ██ ██    ██
  ██  ███ ██▀██  █████  ██████   ██   ██ █████  ██    ██  ██ ██    ██
  ██   ██ ██  ██ ██     ██   ██  ██   ██ ██      ██  ▄██  ██  ██  ██
   ▀████▀ ██  ██ ▀█████ ██   ██  ██   ██ ▀█████   ▀███▀██▄██  ▀███▀
```

![GHOST1O1](https://img.shields.io/badge/GHOST1O1-NOCTURNE-e63946?style=for-the-badge&logo=ghost&logoColor=white)
![Version](https://img.shields.io/badge/VERSION-1.0.0-00d4ff?style=for-the-badge)
![Status](https://img.shields.io/badge/STATUS-OPERATIONAL-2ecc71?style=for-the-badge)
![Modules](https://img.shields.io/badge/MODULES-9-9b59b6?style=for-the-badge)

# 🎣 PhishCloner Ultimate
## *Adversary-in-the-Middle Phishing Framework*

**9 modules d'attaque · 20 templates · C2 intégré · Termux/APK/EXE**

</div>

---

## 🔥 C'est quoi ?

PhishCloner Ultimate est un framework **AiTM (Adversary-in-the-Middle)** modulaire pour la simulation d'attaques phishing. Conçu pour :

- **Red Team** : campagnes de simulation réalistes
- **Blue Team** : formation et détection
- **Recherche** : analyse des flux d'auth modernes (OAuth, MFA, SAML)

**Architecture en 9 modules :**

| Module | Rôle |
|--------|------|
| `mitm_proxy.py` | Proxy HTTPS intercepteur |
| `cred_validator.py` | Test live des credentials |
| `delivery.py` | SMTP/SMS/WhatsApp delivery |
| `cloner.py` | Clone de pages login |
| `c2_server.py` | Command & Control |
| `session_mgr.py` | Gestion sessions compromises |
| `report.py` | Rapports & stats |
| `evasion.py` | Anti-détection (UA, TLS fingerprint) |
| `api.py` | API REST pour orchestration |

---

## ✨ Features

- 🎯 **20 templates** : Microsoft 365, Google, Okta, GitHub, Facebook, LinkedIn, etc.
- 🔐 **OAuth bypass** : interception des flux modernes
- 📱 **Multi-canal** : Email, SMS, WhatsApp, QR code
- 🛡️ **Anti-détection** : UA rotation, TLS fingerprint mimicry
- 📊 **Dashboard C2** : visualisation temps réel
- 🐳 **Docker ready** : déploiement containerisé
- 📱 **APK & EXE** : payloads Android & Windows
- 🐧 **Termux natif** : depuis ton cell

---

## 🚀 Démarrage 60 secondes

```bash
git clone https://github.com/187Ghost101/phishcloner-ultimate.git
cd phishcloner-ultimate
bash setup.sh
python3 engine/api.py 8443
firefox http://localhost:8443/dashboard
```

---

## ⚠️ Éthique

**PhishCloner est STRICTEMENT destiné à :**
- Tests autorisés sur tes propres systèmes
- Campagnes Red Team avec **autorisation écrite**
- Formation Blue Team
- Recherche en sécurité

**Toute utilisation non autorisée est ILLÉGALE.** Tu es seul responsable.

---

## 📚 Documentation

- **[INSTALL.md](INSTALL.md)** — Installation par OS
- **[USAGE.md](USAGE.md)** — Exemples d'usage
- **[SECURITY.md](SECURITY.md)** — Disclosure & éthique
- **[CHANGELOG.md](CHANGELOG.md)** — Historique

---

## 🔗 Liens

- **Hub GHOST1O1** : [github.com/187Ghost101/ghost1o1](https://github.com/187Ghost101/ghost1o1)
- **Protocole** : [PROTOCOL.md](https://github.com/187Ghost101/ghost1o1/blob/main/PROTOCOL.md)

---

## 📜 Licence

MIT — voir [LICENSE](LICENSE)

---

<div align="center">

### Forged in the dark by [ghost1o1](https://github.com/187Ghost101) — 2026

*"There is no lock."*

</div>
