<div align="center">

```
   ▄█████ █  ██  ▄█████ ▄█████▄  ██   ██ ▄█████ █    ██  ██ ██    ██
  ██      ██▄██  ██     ██   ██  ██▄▄▄██ ██     ██    ██  ██ ██    ██
  ██  ███ ██▀██  █████  ██████   ██   ██ █████  ██    ██  ██ ██    ██
  ██   ██ ██  ██ ██     ██   ██  ██   ██ ██      ██  ▄██  ██  ██  ██
   ▀████▀ ██  ██ ▀█████ ██   ██  ██   ██ ▀█████   ▀███▀██▄██  ▀███▀
```

![GHOST1O1](https://img.shields.io/badge/GHOST1O1-L'EVEIL_NOCTURNE-e63946?style=for-the-badge&logo=ghost&logoColor=white)
![Version](https://img.shields.io/badge/VERSION-1.0.0-00d4ff?style=for-the-badge)
![Status](https://img.shields.io/badge/STATUS-OPERATIONAL-2ecc71?style=for-the-badge)
![Scope](https://img.shields.io/badge/EDUCATIONAL-RED_TEAM_TRAINING-e67e22?style=for-the-badge)

# 🎣 PHISHCLONER ULTIMATE
## *Adversary-in-the-Middle Phishing Framework*

**Framework modulaire de simulation AiTM. 9 modules engine, 20 templates, formation Blue Team.**

[Hub](https://github.com/187Ghost101/ghost1o1) · [Tutorial](https://github.com/187Ghost101/ghost1o1/blob/main/tutorials/TUTORIAL_04_EXPLOITER.md) · [SECURITY](SECURITY.md)

> *La preuve remplace la destruction.*

</div>

---

## 🔥 C'est quoi ?

PHISHCLONER ULTIMATE est un **framework de simulation d'attaques AiTM** (Adversary-in-the-Middle) à but **pédagogique**. Il permet aux Red Teams de monter des scénarios réalistes, et aux Blue Teams d'apprendre à les détecter.

**Pas un outil de phishing réel.** Pas d'exfiltration de credentials réels. Pas d'attaque sur des victimes.

C'est un **laboratoire de simulation**.

---

## ✨ Features

- **9 modules engine** : mitm_proxy, cred_validator, delivery, capture, evade, report, replay, c2, exfil_safe
- **20 templates** : Microsoft 365, Google, Okta, GitHub, Adobe, Dropbox, LinkedIn, Salesforce, Slack, Zoom, etc.
- **C2 admin** : dashboard web pour piloter les simulations
- **Multi-plateforme** : Linux, macOS, Windows, Termux, APK Android
- **Mode lab isolé** : DNS sinkhole, certificats auto-signés, target whitelist
- **Rapport pédagogique** : timeline, IoC, recommandations Blue

---

## 🚀 Démarrage 60 secondes

```bash
git clone https://github.com/187Ghost101/phishcloner-ultimate.git
cd phishcloner-ultimate
bash setup.sh

# Mode lab (par défaut — aucune cible réelle)
python3 engine/mitm_proxy.py --lab-mode

# C2 admin (optionnel)
python3 engine/c2.py --admin
firefox http://localhost:9090
```

---

## 🎯 Mode lab vs mode réel

**LAB MODE (par défaut, sûr) :**
- DNS sinkhole automatique
- Cibles = domaines whitelistés (ex: `lab.test`)
- Credentials capturés = stockés en RAM, jamais persistés
- Aucun email envoyé
- Banner d'avertissement permanent

**MODE RÉEL (désactivé par défaut) :**
- Nécessite `--i-have-authorization` flag
- Vérification de l'autorisation écrite obligatoire
- Logs obligatoires
- Disclosure responsable imposée

**Par défaut, le tool refuse de fonctionner en mode réel sans confirmation explicite.**

---

## 📦 Architecture

```
phishcloner-ultimate/
├── engine/
│   ├── mitm_proxy.py        # Proxy AiTM (mitmproxy-based)
│   ├── cred_validator.py    # Validation des captures
│   ├── delivery.py          # Distribution campagnes (lab only)
│   ├── capture.py           # Capture multi-factor
│   ├── evade.py             # Évasions EDR/AV (lab only)
│   ├── report.py            # Génération rapport
│   ├── replay.py            # Replay d'attaque pédagogique
│   ├── c2.py                # C2 admin
│   └── exfil_safe.py        # Exfiltration contrôlée (lab)
├── templates/
│   ├── microsoft/           # M365, Outlook, Teams
│   ├── google/              # Workspace, Gmail
│   ├── okta/                # SSO
│   ├── github/              # GitHub login
│   └── ... (20 templates)
├── c2/                      # Admin C2
├── android/                 # APK pédagogique
├── termux/                  # Build Termux
├── docs/                    # Méthodologie + IoC
└── data/                    # Lab data only
```

---

## 🛡️ Contre-mesures Blue Team

Pour chaque technique AiTM, le repo documente :
- **IoC réseau** (ja3 fingerprint, IP C2, certificats)
- **IoC endpoint** (process, fichiers, registre)
- **Règles de détection** (Sigma, YARA, Snort)
- **Hardening** côté utilisateur (FIDO2, conditional access)

---

## 🔐 Légalité & Éthique — NON NÉGOCIABLE

**OUI :**
- Tests sur organisation avec **autorisation écrite signée**
- Labs de simulation interne
- Formation Red/Blue Team
- CTF et challenges

**NON :**
- Phishing réel de victimes
- Vente d'accès volés
- Usage contre des particuliers
- Activité criminelle

**Tout manquement = ban permanent + signalement aux autorités si applicable.**

📜 **[SECURITY.md](SECURITY.md)** complet

---

## 🤝 Contribution

Recherché :
- Nouveaux templates (avec contre-mesures Blue)
- Nouvelles techniques AiTM documentées
- Règles de détection (Sigma, YARA)
- Traductions

📜 **[CONTRIBUTING.md](CONTRIBUTING.md)**

---

## 📜 Licence

**MIT License** avec clause éthique stricte. Usage malveillant = nullité de licence.

---

<div align="center">

**L'ÉVEIL NOCTURNE** · [ghost1o1](https://github.com/187Ghost101) — 2026

*There is no lock. Du silence naît la lumière.*

</div>
