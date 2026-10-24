#!/usr/bin/env python3
"""Operation Shadow R1 - lightweight sign-in / phishing detector (offline, no live systems).
Usage: python detector.py [csv_path]   (default: bundled CSV). Writes report.md
"""
import csv, sys, os

# ---------- Part 1: scoring rules for the CSV sign-in events ----------
RULES = [  # (name, predicate, points, explanation)
    ("new_device",       lambda e: e["device_known"] == "no",  2, "Device not previously seen for this account"),
    ("location_change",  lambda e: e["location_change"] == "yes", 2, "Sign-in location differs from baseline"),
    ("mfa_anomaly",      lambda e: e["mfa_result"] == "failed_then_passed", 3, "MFA failed then passed (possible prompt fatigue / stolen factor)"),
    ("recovery_viewed",  lambda e: e["account_change"] == "recovery_settings_viewed", 3, "Recovery settings viewed - typical takeover reconnaissance"),
    ("forwarding_rule",  lambda e: "forward" in e["account_change"], 4, "Mailbox forwarding rule - classic data-exfil persistence"),
    ("mfa_method_change",lambda e: e["account_change"] in ("mfa_method_added", "password_changed"), 4, "Credential/MFA change after sign-in"),
]
# Mitigating context: a single weak signal must NOT be called an attack.
def severity(score):
    return "HIGH" if score >= 6 else "MEDIUM" if score >= 4 else "LOW" if score >= 2 else "BENIGN"

ACTIONS = {
    "HIGH":   ["Revoke active sessions/tokens for the account", "Force password reset via a verified channel",
               "Review & remove recovery/MFA changes and forwarding rules", "Contact the user out-of-band to confirm activity", "Escalate to incident response"],
    "MEDIUM": ["Contact the user via a known channel to verify", "Require step-up (phishing-resistant) MFA", "Monitor the account for follow-on changes"],
    "LOW":    ["Log and monitor; no disruptive action", "Ask the user to confirm only if more signals appear"],
    "BENIGN": ["No action"],
}

def analyze_csv(path):
    out = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        for e in csv.DictReader(f):
            hits = [(n, pts, why) for n, p, pts, why in RULES if p(e)]
            score = sum(h[1] for h in hits)
            out.append(dict(id=e["event_id"], time=e["time"], score=score, sev=severity(score),
                            reasons=[h[2] for h in hits] or ["No risk signals; " + e["analyst_note"].lower()],
                            actions=ACTIONS[severity(score)]))
    return out

# ---------- Part 2: Northstar Labs case-file timeline (correlation rules) ----------
TIMELINE = [  # (time, type, attrs)
    ("08:41", "email",    dict(sender="payroll-northstar.example", external=True, subject="Urgent: payroll access expires today", ask="verify her account")),
    ("08:44", "signin",   dict(ok=True,  new_ip=True,  new_browser=True,  office=False)),
    ("08:45", "mfa",      dict(approved=True, user_initiated=False)),
    ("08:47", "mailrule", dict(forward_external=True)),
    ("08:51", "signin",   dict(ok=False, new_ip=False, new_browser=False, office=True)),
    ("08:54", "report",   dict(by="Mira", to="IT")),
]
URGENCY = ("urgent", "expires", "verify", "immediately", "suspend")
def mins(t): h, m = t.split(":"); return int(h) * 60 + int(m)

def analyze_timeline(tl=TIMELINE):
    F, ev = [], {t: (tm, a) for tm, t, a in tl for _ in [0]}
    def add(time, title, sev, why): F.append(dict(time=time, title=title, sev=sev, why=why))
    mail = next(((tm, a) for tm, t, a in tl if t == "email"), None)
    if mail and mail[1]["external"] and any(w in (mail[1]["subject"] + mail[1]["ask"]).lower() for w in URGENCY):
        add(mail[0], "Phishing email", "HIGH", "External lookalike sender + urgency language + credential-verification request")
    for tm, t, a in tl:
        if t == "signin" and a["ok"] and (a["new_ip"] or a["new_browser"]):
            gap = f"{mins(tm) - mins(mail[0])} min after the phish" if mail else "n/a"
            add(tm, "Suspicious sign-in", "HIGH", f"Success from unfamiliar IP and new browser, {gap} (phish -> credential use)")
        if t == "mfa" and a["approved"] and not a["user_initiated"]:
            add(tm, "Unrequested MFA approval", "HIGH", "Push approved but user did not initiate it: MFA fatigue/social-engineered approval; attacker session now has MFA claim")
        if t == "mailrule" and a["forward_external"]:
            add(tm, "External forwarding rule", "CRITICAL", "Persistence + data exfiltration; created 3 min after takeover")
        if t == "signin" and not a["ok"] and a["office"]:
            add(tm, "Legit sign-in failed", "MEDIUM", "User blocked from usual network shortly after compromise - consistent with credential/session change by attacker; verify, not proof")
        if t == "report":
            add(tm, "User reported to IT", "INFO", "Good reporting behaviour; 13 min since the phish. Containment clock starts now")
    chain = [x["title"] for x in F if x["sev"] in ("HIGH", "CRITICAL")]
    verdict = "ACCOUNT COMPROMISE (likely)" if len(chain) >= 3 else "SUSPICIOUS"
    return F, verdict

CONTAIN = [
    "Revoke all Mira's sessions & refresh tokens; block the 08:44 IP / browser fingerprint",
    "Reset password from a trusted device; re-register MFA after cleanup",
    "Delete the external forwarding rule; audit other inbox rules, delegates, OAuth app grants",
    "Block payroll-northstar.example at the mail gateway; search & purge the message from other mailboxes",
    "Check what was forwarded 08:47 onward; assess data exposure; notify payroll/finance",
    "Warn staff; consider number-matching / phishing-resistant MFA",
]

def report(rows, tl, verdict):
    L = ["# Operation Shadow R1 - Detection Report", "", "## A. CSV sign-in events", "",
         "| Event | Time | Score | Severity | Why |", "|---|---|---|---|---|"]
    L += [f"| {r['id']} | {r['time']} | {r['score']} | **{r['sev']}** | {'; '.join(r['reasons'])} |" for r in rows]
    L += ["", "Recommended actions (highest-severity event):", *[f"- {a}" for a in max(rows, key=lambda r: r['score'])['actions']],
          "", "## B. Northstar Labs timeline", "", f"**Verdict: {verdict}**", "", "| Time | Finding | Severity | Why |", "|---|---|---|---|"]
    L += [f"| {x['time']} | {x['title']} | {x['sev']} | {x['why']} |" for x in tl]
    L += ["", "### Safe containment", *[f"{i}. {c}" for i, c in enumerate(CONTAIN, 1)]]
    return "\n".join(L)

if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "events.csv")
    rows = analyze_csv(path); tl, verdict = analyze_timeline()
    md = report(rows, tl, verdict); print(md)
    open(os.path.join(here, "report.md"), "w").write(md)
