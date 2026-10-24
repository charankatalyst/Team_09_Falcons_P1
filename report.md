# Operation Shadow R1 - Detection Report

## A. CSV sign-in events

| Event | Time | Score | Severity | Why |
|---|---|---|---|---|
| A-101 | 09:12 | 4 | **MEDIUM** | Device not previously seen for this account; Sign-in location differs from baseline |
| A-102 | 09:14 | 10 | **HIGH** | Device not previously seen for this account; Sign-in location differs from baseline; MFA failed then passed (possible prompt fatigue / stolen factor); Recovery settings viewed - typical takeover reconnaissance |
| A-103 | 09:19 | 0 | **BENIGN** | No risk signals; known device; context appears consistent |
| A-104 | 09:23 | 2 | **LOW** | Device not previously seen for this account |

Recommended actions (highest-severity event):
- Revoke active sessions/tokens for the account
- Force password reset via a verified channel
- Review & remove recovery/MFA changes and forwarding rules
- Contact the user out-of-band to confirm activity
- Escalate to incident response

## B. Northstar Labs timeline

**Verdict: ACCOUNT COMPROMISE (likely)**

| Time | Finding | Severity | Why |
|---|---|---|---|
| 08:41 | Phishing email | HIGH | External lookalike sender + urgency language + credential-verification request |
| 08:44 | Suspicious sign-in | HIGH | Success from unfamiliar IP and new browser, 3 min after the phish (phish -> credential use) |
| 08:45 | Unrequested MFA approval | HIGH | Push approved but user did not initiate it: MFA fatigue/social-engineered approval; attacker session now has MFA claim |
| 08:47 | External forwarding rule | CRITICAL | Persistence + data exfiltration; created 3 min after takeover |
| 08:51 | Legit sign-in failed | MEDIUM | User blocked from usual network shortly after compromise - consistent with credential/session change by attacker; verify, not proof |
| 08:54 | User reported to IT | INFO | Good reporting behaviour; 13 min since the phish. Containment clock starts now |

### Safe containment
1. Revoke all Mira's sessions & refresh tokens; block the 08:44 IP / browser fingerprint
2. Reset password from a trusted device; re-register MFA after cleanup
3. Delete the external forwarding rule; audit other inbox rules, delegates, OAuth app grants
4. Block payroll-northstar.example at the mail gateway; search & purge the message from other mailboxes
5. Check what was forwarded 08:47 onward; assess data exposure; notify payroll/finance
6. Warn staff; consider number-matching / phishing-resistant MFA