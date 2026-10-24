# Operation Shadow R1 – Sign-in & Phishing Detector
Offline rules engine (Python stdlib only). No live systems touched.
- `python detector.py [csv]` → prints and writes `report.md`
- `pytest` → 7 tests pass

## Detection logic
**CSV events:** additive risk score – new device (+2), location change (+2), MFA failed→passed (+3), recovery settings viewed (+3), forwarding rule (+4). HIGH ≥6, MEDIUM 4–5, LOW 2–3, BENIGN 0.
**Case timeline:** correlation – external urgent phish → sign-in from new IP/browser within minutes → unrequested MFA approval → external forwarding rule.

## Findings
- A-102 HIGH (10), A-101 MEDIUM (4), A-104 LOW (2, new device alone ≠ attack), A-103 BENIGN (0).
- Northstar: likely account compromise; forwarding rule (08:47) is the critical persistence/exfil step.

## Limitations
Hand-tuned weights, tiny sample, no baseline/IP reputation, single account; 08:51 failure is ambiguous (verify). Confidence: high for Northstar chain, medium for CSV scoring.
