from detector import *
import os
rows = {r["id"]: r for r in analyze_csv(os.path.join(os.path.dirname(__file__), "events.csv"))}
def test_a102_high():   assert rows["A-102"]["sev"] == "HIGH"
def test_a101_medium(): assert rows["A-101"]["sev"] == "MEDIUM"
def test_a103_benign(): assert rows["A-103"]["sev"] == "BENIGN"
def test_a104_not_attack(): assert rows["A-104"]["sev"] == "LOW"   # new device alone != attack
def test_ranking(): assert rows["A-102"]["score"] > rows["A-101"]["score"] > rows["A-104"]["score"] > rows["A-103"]["score"]
def test_timeline():
    f, v = analyze_timeline(); t = {x["title"]: x["sev"] for x in f}
    assert t["External forwarding rule"] == "CRITICAL" and "COMPROMISE" in v
def test_benign_timeline():
    f, v = analyze_timeline([("09:00","signin",dict(ok=True,new_ip=False,new_browser=False,office=True))])
    assert v == "SUSPICIOUS" and f == []
