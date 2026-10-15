# Exports the lab records to Markdown for the portfolio repo.
from pathlib import Path
from core.models import AppliedControl, Evidence, RequirementAssessment, RiskScenario
from tprm.models import EntityAssessment

OUT = Path.home() / "grc-lab-portfolio" / "docs"
LV = {0: "Low", 1: "Medium", 2: "High", -1: "n/a"}
P = ["Rare", "Unlikely", "Possible", "Likely", "Almost Certain"]
I = ["Insignificant", "Minor", "Moderate", "Major", "Severe"]
def sc(p, i): return f"{P[p]} x {I[i]} = **{(p+1)*(i+1)}** ({LV[[0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,2,2,2,2,2,2,2,2,2,2,2][(p+1)*(i+1)]]})"
def esc(t): return (t or "").replace("|", "/").replace("\n", " ")

rows = ["# Risk Register: IT Operations 2026", "",
        "Method: 5x5 Likelihood x Impact, score 1-25. Appetite: **Low 1-6** accept and monitor; **Medium 7-14** treat within 90 days, owner sign-off; **High 15-25** treat immediately, escalate.",
        "Risk tolerance is set at Medium, so anything scoring 15 or more is outside appetite.", ""]
for s in RiskScenario.objects.filter(risk_assessment__name="IT Operations Risk Assessment 2026").order_by("ref_id"):
    rows += [f"## {s.ref_id}: {s.name}", "", esc(s.description), "",
             f"- **Assets:** {', '.join(a.name for a in s.assets.all())}",
             f"- **Threats:** {', '.join(t.name for t in s.threats.all())}",
             f"- **Inherent (no controls):** {sc(s.inherent_proba, s.inherent_impact)}",
             f"- **Current (existing controls):** {sc(s.current_proba, s.current_impact)}",
             f"- **Residual (after planned controls):** {sc(s.residual_proba, s.residual_impact)}",
             f"- **Treatment:** {s.treatment.title()}",
             f"- **Existing controls:** {', '.join(c.ref_id + ' ' + c.name for c in s.existing_applied_controls.all())}",
             f"- **Planned controls:** {', '.join(c.ref_id + ' ' + c.name for c in s.applied_controls.all())}",
             f"- **Rationale:** {esc(s.justification)}", ""]
(OUT / "risk-register.md").write_text("\n".join(rows))

rows = ["# Controls", "", "| ID | Control | Type | CSF function | Status | Due | Assets | Evidence |", "|---|---|---|---|---|---|---|---|"]
for c in AppliedControl.objects.filter(folder__name="GRC Lab").order_by("ref_id"):
    rows.append(f"| {c.ref_id} | **{c.name}**<br>{esc(c.description)} | {c.category} | {c.csf_function} | {c.get_status_display()} | {c.eta or ''} | "
                f"{', '.join(a.name for a in c.assets.all())} | {', '.join(e.name for e in c.evidences.all())} |")
(OUT / "controls.md").write_text("\n".join(rows) + "\n")

rows = ["# NIST CSF 2.0 Assessment: IT Operations baseline", "",
        "All 106 CSF 2.0 subcategories were loaded. The 12 most relevant to the risks in this lab were assessed; the rest are open for a later cycle.", "",
        "| Subcategory | Result | Observation | Controls | Evidence |", "|---|---|---|---|---|"]
for r in RequirementAssessment.objects.filter(compliance_assessment__name="NIST CSF 2.0 - IT Operations baseline").exclude(result="not_assessed").select_related("requirement").order_by("requirement__ref_id"):
    rows.append(f"| {r.requirement.ref_id} | {r.get_result_display()} | {esc(r.observation)} | {', '.join(c.ref_id for c in r.applied_controls.all())} | {', '.join(e.name for e in r.evidences.all())} |")
(OUT / "nist-csf-assessment.md").write_text("\n".join(rows) + "\n")

ea = EntityAssessment.objects.get(name="CloudVault Backup - 2026 due diligence")
from collections import Counter
ras = RequirementAssessment.objects.filter(compliance_assessment=ea.compliance_assessment, requirement__assessable=True).select_related("requirement").order_by("requirement__ref_id")
cnt = Counter(r.result for r in ras)
rows = ["# Vendor Due Diligence: CloudVault Backup Inc. (simulated)", "",
        "> CloudVault Backup Inc. is a fictional vendor created for this lab. The questionnaire is the intuitem Vendor Due Diligence (VDD) framework.", "",
        f"**Service:** {ea.solutions.first().description}  ",
        f"**Questionnaire:** {ras.count()} questions: {cnt['compliant']} yes, {cnt['partially_compliant']} partial, {cnt['non_compliant']} no, {cnt['not_applicable']} N/A  ",
        f"**Conclusion:** {ea.get_conclusion_display().upper()}", "", f"**Reviewer summary:** {esc(ea.observation)}", "",
        "## Findings", "", "| Question | Requirement | Answer | Notes |", "|---|---|---|---|"]
for r in ras:
    if r.result == "compliant": continue
    t = (r.requirement.translations or {}).get("en", {})
    rows.append(f"| {r.requirement.ref_id} | {esc(t.get('description') or r.requirement.description)} | {r.get_result_display()} | {esc(r.observation)} |")
rows += ["", "All other questions were answered yes, supported by the vendor's SOC 2 Type II report and bridge letter."]
(OUT / "vendor-assessment.md").write_text("\n".join(rows) + "\n")
print("exported", sorted(p.name for p in OUT.iterdir()))
