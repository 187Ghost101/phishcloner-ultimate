# Microsoft 365 — Phishing Context

## Target Profile
- **User Base:** Almost every enterprise globally
- **Authentication:** Azure AD / Entra ID
- **MFA Methods:** Microsoft Authenticator, SMS, FIDO2, OATH tokens

## Social Engineering Angles

### 1. Password Expiry (Most Effective)
> "Your Microsoft 365 password expires today. Sign in to keep your current password."
- Creates urgency (password expiry today)
- Appears legitimate (orgs do have password policies)
- Low suspicion

### 2. Security Alert — Unusual Sign-in
> "We detected an unusual sign-in from Moscow, Russia. If this wasn't you, verify your account."
- Fear trigger (account compromised)
- Geo-location detail adds credibility

### 3. Quarantined Email
> "Your email '[subject]' was quarantined. Review and release it here."
- Curiosity trigger
- Appears to come from Exchange Online Protection

### 4. Teams Voicemail
> "You have a new voicemail in Microsoft Teams from [name]."
- Low suspicion (routine)
- Can use real employee names from LinkedIn

## Bypass Considerations
- **Conditional Access:** Check if target uses CA policies
- **Seamless SSO:** If user already authenticated, may auto-redirect
- **Passwordless:** Some orgs use FIDO2 — password field won't appear
- **Number Matching:** Microsoft Authenticator now uses number matching — relay must handle this
