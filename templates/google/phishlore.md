# Google Workspace — Phishing Context

## Target Profile
- **User Base:** Education, SMBs, enterprises using Workspace
- **Authentication:** Google Identity
- **MFA Methods:** Google Prompt, Authenticator, FIDO2, SMS, TOTP

## Social Engineering Angles

### 1. Suspicious Sign-in Alert
> "We blocked a sign-in to your account. Review activity."

### 2. Storage Full
> "Your Google Drive is 95% full. Sign in to free up space or buy more."

### 3. Document Shared
> "[Name] has shared a document with you. Sign in to view."

## Bypass
- **Google Prompt:** Real-time push — must intercept WebSocket
- **FIDO2:** Cannot bypass without physical key
- **TOTP:** Can be relayed in real-time
