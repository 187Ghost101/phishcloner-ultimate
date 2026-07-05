# 🔧 PhishCloner Ultimate — Guide d'installation

---

## 🐧 Kali / Debian / Ubuntu (recommandé)

```bash
sudo apt update && sudo apt install -y python3 python3-pip git golang-go docker.io docker-compose
cd ~
git clone https://github.com/187Ghost101/phishcloner-ultimate.git
cd phishcloner-ultimate
bash setup.sh
python3 engine/api.py 8443
```

## 🏔️ Arch / Manjaro

```bash
sudo pacman -S python python-pip git go docker docker-compose
cd ~
git clone https://github.com/187Ghost101/phishcloner-ultimate.git
cd phishcloner-ultimate
bash setup.sh
```

## 🍎 macOS

```bash
brew install python3 git go docker docker-compose
# Lance Docker Desktop
cd ~
git clone https://github.com/187Ghost101/phishcloner-ultimate.git
cd phishcloner-ultimate
bash setup.sh
```

## 🪟 Windows (WSL2)

```powershell
wsl --install -d Ubuntu
```
```bash
sudo apt update && sudo apt install -y python3 python3-pip git golang-go
git clone https://github.com/187Ghost101/phishcloner-ultimate.git
cd phishcloner-ultimate
bash setup.sh
```

## 📱 Termux (Android)

```bash
pkg update && pkg install python git golang
cd ~
git clone https://github.com/187Ghost101/phishcloner-ultimate.git
cd phishcloner-ultimate
bash setup.sh
```

## 🐳 Docker

```bash
docker run -d -p 8443:8443 -p 8080:8080 --name phishcloner 187ghost101/phishcloner-ultimate
firefox http://localhost:8443/dashboard
```

## ✅ Vérification

```bash
python3 engine/api.py --version
# → PhishCloner Ultimate v1.0.0
```

---

*"There is no lock." — ghost1o1*
