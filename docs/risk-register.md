# Risk Register: IT Operations 2026

Method: 5x5 Likelihood x Impact, score 1-25. Appetite: **Low 1-6** accept and monitor; **Medium 7-14** treat within 90 days, owner sign-off; **High 15-25** treat immediately, escalate.
Risk tolerance is set at Medium, so anything scoring 15 or more is outside appetite.

## R1: Eramba admin console exposure

The Eramba admin console was reachable from the internet with a self-signed certificate. An attacker could brute-force or phish admin credentials and read or tamper with all GRC data.

- **Assets:** Eramba Lab Server
- **Threats:** Phishing and Spear Phishing, Password Attacks (Brute Force and Credential Stuffing), Zero-Day Exploits
- **Inherent (no controls):** Likely x Major = **16** (High)
- **Current (existing controls):** Unlikely x Major = **8** (Medium)
- **Residual (after planned controls):** Rare x Major = **4** (Low)
- **Treatment:** Mitigate
- **Existing controls:** CTL-02 Restrict admin console to allowlisted IPs, CTL-01 MFA for administrative access
- **Planned controls:** CTL-03 Replace self-signed certificate with trusted TLS
- **Rationale:** MFA and IP allowlisting already cut likelihood from Likely to Unlikely (16 -> 8). A trusted TLS certificate removes the MITM/phishing vector, bringing it to Rare (4, Low).

## R2: Customer PII breach from database

Unauthorised access to or exfiltration of customer PII from the Customer Database (compromised credentials, excessive access, ransomware, or insider misuse).

- **Assets:** Customer Database
- **Threats:** Ransomware, Insider Threats, Data Breach, Leak and Shadow IT
- **Inherent (no controls):** Possible x Severe = **15** (High)
- **Current (existing controls):** Possible x Severe = **15** (High)
- **Residual (after planned controls):** Unlikely x Major = **8** (Medium)
- **Treatment:** Mitigate
- **Existing controls:** CTL-10 Third-party security due diligence, CTL-05 Quarterly access review - customer database
- **Planned controls:** CTL-06 Database activity monitoring & alerting, CTL-04 Database encryption at rest
- **Rationale:** Severe impact (breach notification, fines). Access reviews exist but encryption is not yet complete, so current risk stays High (15). Encryption + activity monitoring target Medium (8); remaining risk accepted by IT Operations Manager.

## R3: Lost or stolen employee laptop

A laptop is lost or stolen while travelling or commuting, exposing locally stored customer data and cached credentials.

- **Assets:** Employee Laptops
- **Threats:** Physical Security Threats (Manipulation and Theft), Mobile Device Threats
- **Inherent (no controls):** Likely x Moderate = **12** (Medium)
- **Current (existing controls):** Likely x Minor = **8** (Medium)
- **Residual (after planned controls):** Possible x Minor = **6** (Low)
- **Treatment:** Mitigate
- **Existing controls:** CTL-07 Full-disk encryption on laptops, CTL-09 Security awareness training
- **Planned controls:** CTL-08 MDM enrolment with remote lock & wipe
- **Rationale:** Laptop loss is Likely over a year. Full-disk encryption already lowers impact to Minor (8). MDM remote wipe plus training reduce likelihood to Possible (6, Low). One device (LT-005) is unencrypted - tracked as a gap.
