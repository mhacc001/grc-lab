# Controls

| ID | Control | Type | CSF function | Status | Due | Assets | Evidence |
|---|---|---|---|---|---|---|---|
| CTL-01 | **MFA for administrative access**<br>TOTP MFA enforced for all Eramba admin accounts; lockout after 5 failed logins. | technical | protect | Active |  | Eramba Lab Server | Eramba admin MFA & security group config |
| CTL-02 | **Restrict admin console to allowlisted IPs**<br>AWS security group limits 8443/22 to the administrator's IP; public access removed. | technical | protect | Active |  | Eramba Lab Server | Eramba admin MFA & security group config |
| CTL-03 | **Replace self-signed certificate with trusted TLS**<br>Issue a CA-signed certificate (e.g. Let's Encrypt with a DNS name) for the Eramba console. | technical | protect | To do | 2026-11-14 | Eramba Lab Server |  |
| CTL-04 | **Database encryption at rest**<br>Enable storage-level encryption (AES-256, KMS-managed keys) for the customer database and backups. | technical | protect | In progress | 2026-11-29 | Customer Database |  |
| CTL-05 | **Quarterly access review - customer database**<br>Data owner reviews every account with access to customer data each quarter; leavers revoked. | process | govern | Active |  | Customer Database | Customer DB access review - Q3 2026 |
| CTL-06 | **Database activity monitoring & alerting**<br>Log and alert on bulk exports and anomalous queries against customer tables. | technical | detect | To do | 2027-01-13 | Customer Database |  |
| CTL-07 | **Full-disk encryption on laptops**<br>FileVault/BitLocker enforced via MDM; recovery keys escrowed. | technical | protect | Active |  | Employee Laptops | Laptop encryption & MDM status report |
| CTL-08 | **MDM enrolment with remote lock & wipe**<br>All laptops enrolled in MDM so lost devices can be locked and wiped remotely. | technical | respond | In progress | 2026-11-05 | Employee Laptops | Laptop encryption & MDM status report |
| CTL-09 | **Security awareness training**<br>Annual phishing & device-handling training with completion tracking. | process | protect | Active |  | Employee Laptops, Customer Database | Security awareness completion 2026 |
| CTL-10 | **Third-party security due diligence**<br>Vendors handling customer data complete a due-diligence questionnaire and provide SOC 2 / ISO 27001 evidence before onboarding and annually. | process | govern | Active |  | Customer Database | CloudVault SOC 2 Type II bridge letter |
