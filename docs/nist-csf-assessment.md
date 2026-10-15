# NIST CSF 2.0 Assessment: IT Operations baseline

All 106 CSF 2.0 subcategories were loaded. The 12 most relevant to the risks in this lab were assessed; the rest are open for a later cycle.

| Subcategory | Result | Observation | Controls | Evidence |
|---|---|---|---|---|
| DE.CM-03 | Non-compliant | No monitoring of database user activity yet (CTL-06 planned). | CTL-06 |  |
| GV.RM-01 | Compliant | Risk management objectives agreed: 5x5 matrix, appetite Low 1-6 / Medium 7-14 / High 15-25. |  |  |
| GV.SC-07 | Partially compliant | CloudVault assessed with due-diligence questionnaire; not yet done for all vendors. | CTL-10 | CloudVault SOC 2 Type II bridge letter |
| ID.AM-01 | Compliant | Hardware inventory maintained (asset register: server, laptops LT-001..005). |  | Laptop encryption & MDM status report |
| ID.AM-07 | Partially compliant | Customer Database data types documented; data-flow diagram still missing. |  |  |
| ID.RA-05 | Compliant | Threats, likelihood and impact used to prioritise risks R1-R3 in RA-2026-01. |  |  |
| PR.AA-03 | Compliant | MFA enforced for Eramba administrators. | CTL-01 | Eramba admin MFA & security group config |
| PR.AA-05 | Compliant | Quarterly access reviews on customer data; leavers revoked. | CTL-05 | Customer DB access review - Q3 2026 |
| PR.AT-01 | Partially compliant | Awareness training 4/5 staff complete (80%). | CTL-09 | Security awareness completion 2026 |
| PR.DS-01 | Partially compliant | Laptops encrypted (1 exception); database encryption at rest in progress. | CTL-07, CTL-04 | Laptop encryption & MDM status report |
| PR.IR-01 | Compliant | Admin console restricted to allowlisted IPs via AWS security group. | CTL-02 | Eramba admin MFA & security group config |
| RS.MI-01 | Partially compliant | Remote wipe available for enrolled laptops only; MDM rollout in progress. | CTL-08 | Laptop encryption & MDM status report |
