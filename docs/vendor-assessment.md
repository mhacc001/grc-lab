# Vendor Due Diligence: CloudVault Backup Inc. (simulated)

> CloudVault Backup Inc. is a fictional vendor created for this lab. The questionnaire is the intuitem Vendor Due Diligence (VDD) framework.

**Service:** Nightly encrypted backups of the Customer Database, 35-day retention, US-East region.  
**Questionnaire:** 46 questions: 39 yes, 4 partial, 2 no, 1 N/A  
**Conclusion:** WARNING

**Reviewer summary:** Generally mature (SOC 2 Type II, encryption, MFA). Gaps: no incident-response tabletop in the period, no tested restore SLA, sub-processor list not shared. Conclusion: WARNING - approve renewal with contractual remediation by Q1 2027.

## Findings

| Question | Requirement | Answer | Notes |
|---|---|---|---|
| APP.07 | The source code is accessible and auditable. | Not applicable | Proprietary SaaS; source code not available. Compensated by SOC 2 report and pentest summary. |
| AUD.02 | Penetration tests (pentests) are conducted regularly by an independent entity. | Partially compliant | Annual external pentest; only an executive summary shared, full report under NDA. |
| BAK.04 | Backup restorations are regularly tested. | Partially compliant | Restores tested internally twice a year, but no customer-specific restore test or contractual restore SLA. |
| GOV.06 | Information security is managed with suppliers. | Non-compliant | Sub-processor list not provided despite two requests; supplier security management could not be verified. |
| GOV.08 | The organisation is covered by a cyber insurance. | Non-compliant | No cyber insurance policy in place. |
| INC.01 | An incident response process (IRP) is in place. | Partially compliant | IR plan exists, but no tabletop exercise in the last 12 months (SOC 2 exception CC7.4). |
| INC.02 | Clients are notified in case of an incident affecting their data. | Partially compliant | Notification commitment is 'without undue delay'; we require 72 hours in the renewal contract. |

All other questions were answered yes, supported by the vendor's SOC 2 Type II report and bridge letter.
