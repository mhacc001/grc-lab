# Builds the GRC Lab in CISO Assistant. Run with:
#   cd backend && DJANGO_DEBUG=True .venv/bin/python manage.py shell < ~/grc-lab/build_lab.py
# Safe to re-run: objects are looked up by name before being created.
from datetime import date, timedelta
from pathlib import Path

from django.core.files import File

from core.models import (
    AppliedControl, Asset, ComplianceAssessment, Evidence, EvidenceRevision,
    Framework, Perimeter, RequirementAssessment, RiskAssessment, RiskMatrix,
    RiskScenario, Threat,
)
from iam.models import Folder, User
from tprm.models import Entity, EntityAssessment, Solution
from tprm.services import create_enclave_audit

EVIDENCE_DIR = Path.home() / "grc-lab" / "evidence"
from core.models import Actor
admin = User.objects.get(email="admin@grclab.local")
admin_actor, _ = Actor.objects.get_or_create(user=admin)
today = date.today()

# --- Domain & perimeter (mirrors the Eramba Business Unit) -------------------
domain = Folder.objects.filter(name="GRC Lab", content_type=Folder.ContentType.DOMAIN).first()
if not domain:
    domain = Folder.objects.create(
        name="GRC Lab", content_type=Folder.ContentType.DOMAIN,
        parent_folder=Folder.get_root_folder(),
        description="Lab organisation for GRC practice (NIST CSF 2.0, risk, TPRM).",
    )
    Folder.create_default_ug_and_ra(domain)
perimeter, _ = Perimeter.objects.get_or_create(
    name="IT Operations", folder=domain,
    defaults=dict(ref_id="BU-ITOPS", lc_status="in_prod",
                  description="IT Operations business unit: lab server, customer data, endpoints."),
)

# --- Assets ------------------------------------------------------------------
def asset(name, type_, desc, ref, bv=""):
    a, _ = Asset.objects.get_or_create(
        name=name, folder=domain,
        defaults=dict(type=type_, description=desc, ref_id=ref, business_value=bv),
    )
    a.owner.add(admin_actor)
    return a

customer_db = asset("Customer Database", "PR",
    "Production database holding customer PII (names, emails, addresses, order history).",
    "AST-002", "Critical - core business data subject to privacy regulation")
eramba_srv = asset("Eramba Lab Server", "SP",
    "AWS EC2 instance hosting the Eramba GRC application and its admin console.", "AST-001")
laptops = asset("Employee Laptops", "SP",
    "Company-issued macOS/Windows laptops used by staff, some with local copies of customer data.", "AST-003")

# --- Applied controls ----------------------------------------------------------
def control(ref, name, desc, cat, csf, status, assets, eta=None, effort="S", impact=4):
    c, _ = AppliedControl.objects.get_or_create(
        name=name, folder=domain,
        defaults=dict(ref_id=ref, description=desc, category=cat, csf_function=csf,
                      status=status, eta=eta, effort=effort, control_impact=impact, priority=2),
    )
    c.owner.add(admin_actor)
    c.assets.add(*assets)
    return c

c_mfa = control("CTL-01", "MFA for administrative access",
    "TOTP MFA enforced for all Eramba admin accounts; lockout after 5 failed logins.",
    "technical", "protect", "active", [eramba_srv])
c_net = control("CTL-02", "Restrict admin console to allowlisted IPs",
    "AWS security group limits 8443/22 to the administrator's IP; public access removed.",
    "technical", "protect", "active", [eramba_srv])
c_tls = control("CTL-03", "Replace self-signed certificate with trusted TLS",
    "Issue a CA-signed certificate (e.g. Let's Encrypt with a DNS name) for the Eramba console.",
    "technical", "protect", "to_do", [eramba_srv], eta=today + timedelta(days=30))
c_enc = control("CTL-04", "Database encryption at rest",
    "Enable storage-level encryption (AES-256, KMS-managed keys) for the customer database and backups.",
    "technical", "protect", "in_progress", [customer_db], eta=today + timedelta(days=45), effort="M", impact=5)
c_rev = control("CTL-05", "Quarterly access review - customer database",
    "Data owner reviews every account with access to customer data each quarter; leavers revoked.",
    "process", "govern", "active", [customer_db])
c_dlp = control("CTL-06", "Database activity monitoring & alerting",
    "Log and alert on bulk exports and anomalous queries against customer tables.",
    "technical", "detect", "to_do", [customer_db], eta=today + timedelta(days=90), effort="L", impact=4)
c_fde = control("CTL-07", "Full-disk encryption on laptops",
    "FileVault/BitLocker enforced via MDM; recovery keys escrowed.",
    "technical", "protect", "active", [laptops], impact=5)
c_mdm = control("CTL-08", "MDM enrolment with remote lock & wipe",
    "All laptops enrolled in MDM so lost devices can be locked and wiped remotely.",
    "technical", "respond", "in_progress", [laptops], eta=today + timedelta(days=21))
c_sat = control("CTL-09", "Security awareness training",
    "Annual phishing & device-handling training with completion tracking.",
    "process", "protect", "active", [laptops, customer_db], impact=3)
c_vrm = control("CTL-10", "Third-party security due diligence",
    "Vendors handling customer data complete a due-diligence questionnaire and provide SOC 2 / ISO 27001 evidence before onboarding and annually.",
    "process", "govern", "active", [customer_db])

# --- Risk assessment & scenarios ---------------------------------------------
matrix = RiskMatrix.objects.get(urn="urn:grclab:risk:matrix:5x5-grclab")
ra, _ = RiskAssessment.objects.get_or_create(
    name="IT Operations Risk Assessment 2026", folder=domain,
    defaults=dict(perimeter=perimeter, risk_matrix=matrix, version="1.0", status="in_progress",
                  ref_id="RA-2026-01", due_date=today + timedelta(days=60),
                  description="Asset risk assessment for the IT Operations business unit. "
                              "Score = Likelihood x Impact (1-25); appetite Low 1-6, Medium 7-14, High 15-25."),
)
ra.risk_tolerance = 1  # Medium: anything at or below Medium (score <= 14) is within appetite
ra.save()
ra.authors.add(admin_actor)

def threats(*refs):
    return list(Threat.objects.filter(ref_id__in=refs, library__urn="urn:intuitem:risk:library:intuitem-common-catalog"))

# Indexes are 0-based: Likelihood 0=Rare..4=Almost Certain, Impact 0=Insignificant..4=Severe
RISKS = [
    dict(ref_id="R1", name="Eramba admin console exposure",
         description="The Eramba admin console was reachable from the internet with a self-signed certificate. "
                     "An attacker could brute-force or phish admin credentials and read or tamper with all GRC data.",
         assets=[eramba_srv], threats=threats("ICT-012", "ICT-004", "ICT-002"),
         existing=[c_mfa, c_net], planned=[c_tls],
         inherent=(3, 3), current=(1, 3), residual=(0, 3), treatment="mitigate",
         justification="MFA and IP allowlisting already cut likelihood from Likely to Unlikely (16 -> 8). "
                       "A trusted TLS certificate removes the MITM/phishing vector, bringing it to Rare (4, Low)."),
    dict(ref_id="R2", name="Customer PII breach from database",
         description="Unauthorised access to or exfiltration of customer PII from the Customer Database "
                     "(compromised credentials, excessive access, ransomware, or insider misuse).",
         assets=[customer_db], threats=threats("ICT-019", "ICT-001", "ICT-005"),
         existing=[c_rev, c_vrm], planned=[c_enc, c_dlp],
         inherent=(2, 4), current=(2, 4), residual=(1, 3), treatment="mitigate",
         justification="Severe impact (breach notification, fines). Access reviews exist but encryption is not yet "
                       "complete, so current risk stays High (15). Encryption + activity monitoring target Medium (8); "
                       "remaining risk accepted by IT Operations Manager."),
    dict(ref_id="R3", name="Lost or stolen employee laptop",
         description="A laptop is lost or stolen while travelling or commuting, exposing locally stored "
                     "customer data and cached credentials.",
         assets=[laptops], threats=threats("ICT-020", "ICT-017"),
         existing=[c_fde, c_sat], planned=[c_mdm],
         inherent=(3, 2), current=(3, 1), residual=(2, 1), treatment="mitigate",
         justification="Laptop loss is Likely over a year. Full-disk encryption already lowers impact to Minor (8). "
                       "MDM remote wipe plus training reduce likelihood to Possible (6, Low). One device (LT-005) "
                       "is unencrypted - tracked as a gap."),
]
scenarios = {}
for r in RISKS:
    s = RiskScenario.objects.filter(name=r["name"], risk_assessment=ra).first() or RiskScenario(risk_assessment=ra, name=r["name"])
    s.ref_id, s.description, s.treatment, s.justification = r["ref_id"], r["description"], r["treatment"], r["justification"]
    s.inherent_proba, s.inherent_impact = r["inherent"]
    s.current_proba, s.current_impact = r["current"]
    s.residual_proba, s.residual_impact = r["residual"]
    s.save()
    s.assets.set(r["assets"]); s.threats.set(r["threats"])
    s.existing_applied_controls.set(r["existing"]); s.applied_controls.set(r["planned"])
    s.owner.set([admin_actor])
    scenarios[r["ref_id"]] = s

# --- Evidence ----------------------------------------------------------------
def evidence(name, desc, fname, status, controls, days_valid=365):
    e, created = Evidence.objects.get_or_create(
        name=name, folder=domain,
        defaults=dict(description=desc, status=status, expiry_date=today + timedelta(days=days_valid)),
    )
    e.owner.add(admin_actor)
    if not e.revisions.exists():
        with open(EVIDENCE_DIR / fname, "rb") as fh:
            EvidenceRevision.objects.create(evidence=e, folder=domain, version=1,
                                            attachment=File(fh, name=fname), original_filename=fname)
    for c in controls:
        c.evidences.add(e)
    return e

ev_mfa = evidence("Eramba admin MFA & security group config",
    "Settings export and AWS security-group rules showing MFA enforcement and IP allowlist.",
    "eramba-admin-mfa-config.txt", "approved", [c_mfa, c_net], 180)
ev_fde = evidence("Laptop encryption & MDM status report",
    "MDM export of encryption and enrolment status for all company laptops (LT-005 non-compliant).",
    "laptop-filevault-status.csv", "in_review", [c_fde, c_mdm], 90)
ev_rev = evidence("Customer DB access review - Q3 2026",
    "Quarterly access review sign-off; 2 accounts revoked (leaver, ended contractor).",
    "customer-db-access-review-2026Q3.csv", "approved", [c_rev], 90)
ev_sat = evidence("Security awareness completion 2026",
    "LMS completion export for the 2026 phishing module (4/5 complete).",
    "security-awareness-completion-2026.csv", "in_review", [c_sat])
ev_soc2 = evidence("CloudVault SOC 2 Type II bridge letter",
    "Vendor-supplied bridge letter covering the gap since the last SOC 2 Type II report.",
    "cloudvault-soc2-bridge-letter.txt", "approved", [c_vrm])

# --- NIST CSF 2.0 compliance assessment --------------------------------------
csf = Framework.objects.get(urn="urn:intuitem:risk:framework:nist-csf-2.0")
ca = ComplianceAssessment.objects.filter(name="NIST CSF 2.0 - IT Operations baseline", folder=domain).first()
if not ca:
    ca = ComplianceAssessment.objects.create(
        name="NIST CSF 2.0 - IT Operations baseline", folder=domain, perimeter=perimeter, framework=csf,
        version="1.0", status="in_progress", ref_id="CA-CSF-2026", min_score=csf.min_score, max_score=csf.max_score,
        description="Baseline self-assessment of the IT Operations unit against NIST CSF 2.0 (106 subcategories).",
    )
    ca.create_requirement_assessments()
ca.authors.add(admin_actor)
ca.assets.set([customer_db, eramba_srv, laptops])

CSF_RESULTS = {
    # ref_id: (result, observation, controls, evidences)
    "ID.AM-01": ("compliant", "Hardware inventory maintained (asset register: server, laptops LT-001..005).", [], [ev_fde]),
    "ID.AM-07": ("partially_compliant", "Customer Database data types documented; data-flow diagram still missing.", [], []),
    "GV.RM-01": ("compliant", "Risk management objectives agreed: 5x5 matrix, appetite Low 1-6 / Medium 7-14 / High 15-25.", [], []),
    "ID.RA-05": ("compliant", "Threats, likelihood and impact used to prioritise risks R1-R3 in RA-2026-01.", [], []),
    "GV.SC-07": ("partially_compliant", "CloudVault assessed with due-diligence questionnaire; not yet done for all vendors.", [c_vrm], [ev_soc2]),
    "PR.AA-03": ("compliant", "MFA enforced for Eramba administrators.", [c_mfa], [ev_mfa]),
    "PR.AA-05": ("compliant", "Quarterly access reviews on customer data; leavers revoked.", [c_rev], [ev_rev]),
    "PR.AT-01": ("partially_compliant", "Awareness training 4/5 staff complete (80%).", [c_sat], [ev_sat]),
    "PR.DS-01": ("partially_compliant", "Laptops encrypted (1 exception); database encryption at rest in progress.", [c_fde, c_enc], [ev_fde]),
    "PR.IR-01": ("compliant", "Admin console restricted to allowlisted IPs via AWS security group.", [c_net], [ev_mfa]),
    "DE.CM-03": ("non_compliant", "No monitoring of database user activity yet (CTL-06 planned).", [c_dlp], []),
    "RS.MI-01": ("partially_compliant", "Remote wipe available for enrolled laptops only; MDM rollout in progress.", [c_mdm], [ev_fde]),
}
for ref, (result, obs, ctrls, evs) in CSF_RESULTS.items():
    rqa = RequirementAssessment.objects.filter(compliance_assessment=ca, requirement__ref_id=ref).first()
    if not rqa:
        print("  (CSF ref not found:", ref, ")"); continue
    rqa.result, rqa.observation, rqa.status = result, obs, "done"
    rqa.save()
    rqa.applied_controls.add(*ctrls); rqa.evidences.add(*evs)

# --- Vendor (third-party) assessment -----------------------------------------
vendor, _ = Entity.objects.get_or_create(
    name="CloudVault Backup Inc.", folder=domain,
    defaults=dict(ref_id="VEN-001", description="(Fictional lab vendor) SaaS provider storing nightly encrypted backups of the Customer Database.",
                  mission="Managed cloud backup and restore", reference_link="https://example.com/cloudvault",
                  default_dependency=3, default_penetration=3, default_maturity=3, default_trust=3),
)
solution, _ = Solution.objects.get_or_create(
    name="Managed database backup", provider_entity=vendor,
    defaults=dict(description="Nightly encrypted backups of the Customer Database, 35-day retention, US-East region.",
                  criticality=3, ref_id="SOL-001"),
)
solution.assets.add(customer_db)
ea = EntityAssessment.objects.filter(name="CloudVault Backup - 2026 due diligence", entity=vendor).first()
if not ea:
    ea = EntityAssessment.objects.create(
        name="CloudVault Backup - 2026 due diligence", entity=vendor, folder=domain, perimeter=perimeter,
        status="in_review", criticality=3, penetration=3, dependency=3, maturity=3, trust=3,
        due_date=today + timedelta(days=14), expiry_date=today + timedelta(days=365),
        conclusion="warning", evidence=None,
        description="Annual due diligence on CloudVault before renewing the backup contract.",
        observation="Generally mature (SOC 2 Type II, encryption, MFA). Gaps: no incident-response tabletop in the "
                    "period, no tested restore SLA, sub-processor list not shared. Conclusion: WARNING - approve "
                    "renewal with contractual remediation by Q1 2027.",
    )
    ea.solutions.add(solution)
    vdd = Framework.objects.get(urn="urn:intuitem:risk:framework:vendor-due-diligence")
    audit = create_enclave_audit(ea, vdd)
    ea.refresh_from_db()
ea.authors.add(admin_actor); ea.reviewers.add(admin_actor)

GAPS = {  # vendor questionnaire answers that are not a clean "yes"
    "APP.07": ("not_applicable", "Proprietary SaaS; source code not available. Compensated by SOC 2 report and pentest summary."),
    "AUD.02": ("partially_compliant", "Annual external pentest; only an executive summary shared, full report under NDA."),
    "BAK.04": ("partially_compliant", "Restores tested internally twice a year, but no customer-specific restore test or contractual restore SLA."),
    "GOV.06": ("non_compliant", "Sub-processor list not provided despite two requests; supplier security management could not be verified."),
    "GOV.08": ("non_compliant", "No cyber insurance policy in place."),
    "INC.01": ("partially_compliant", "IR plan exists, but no tabletop exercise in the last 12 months (SOC 2 exception CC7.4)."),
    "INC.02": ("partially_compliant", "Notification commitment is 'without undue delay'; we require 72 hours in the renewal contract."),
}
audit = ea.compliance_assessment
answered = 0
for rqa in RequirementAssessment.objects.filter(compliance_assessment=audit, requirement__assessable=True).select_related("requirement"):
    rn = rqa.requirement
    result, obs = "compliant", "Confirmed by vendor; supported by SOC 2 Type II report / bridge letter."
    if rn.ref_id in GAPS:
        result, obs = GAPS[rn.ref_id]
    rqa.result, rqa.observation, rqa.status = result, obs, "done"
    rqa.respondent_alignment = {"compliant": "yes", "partially_compliant": "in_progress",
                                "non_compliant": "no", "not_applicable": "not_applicable"}[result]
    rqa.review_state = "accepted"
    rqa.save()
    answered += 1
audit.status = "in_review"
audit.save()
audit.evidences.add(ev_soc2)

# --- Summary -----------------------------------------------------------------
print("\n=== GRC LAB BUILT ===")
print("Domain:", domain.name, "| Perimeter:", perimeter.name)
print("Assets:", list(Asset.objects.filter(folder=domain).values_list("name", flat=True)))
print("Controls:", AppliedControl.objects.filter(folder=domain).count())
lv = {r.id if hasattr(r, 'id') else i: r for i, r in enumerate(matrix.json_definition.get("risk", []))} if isinstance(matrix.json_definition, dict) else {}
for s in RiskScenario.objects.filter(risk_assessment=ra).order_by("ref_id"):
    sc = lambda p, i: (p + 1) * (i + 1)
    print(f"  {s.ref_id} {s.name}: inherent {sc(s.inherent_proba, s.inherent_impact)} -> current "
          f"{sc(s.current_proba, s.current_impact)} -> residual {sc(s.residual_proba, s.residual_impact)} "
          f"(levels {s.inherent_level}/{s.current_level}/{s.residual_level})")
print("CSF 2.0 requirement assessments:", RequirementAssessment.objects.filter(compliance_assessment=ca, requirement__assessable=True).count())
from collections import Counter
print("Vendor questionnaire answered:", answered, Counter(RequirementAssessment.objects.filter(compliance_assessment=audit, requirement__assessable=True).values_list("result", flat=True)))
print("Evidence:", [(e.name, e.revisions.count()) for e in Evidence.objects.filter(folder=domain)])
