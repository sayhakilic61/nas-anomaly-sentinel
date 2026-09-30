import random
import time

from sentinel import config
from sentinel.detector import CRITICAL, WARNING, Detector, robust_z, score
from sentinel.seed import generate
from sentinel.storage import Storage


def _detector(days=30):
    cfg = config.load()
    store = Storage(":memory:")
    now = time.time()
    store.write_rows(generate("demo", days, 300, 1.0, 1.0, random.Random(1), now=now - 300))
    return Detector(store, cfg), now


def test_robust_z_flat_history_does_not_explode():
    med, z = robust_z(5, [0] * 100, min_delta=60)
    assert med == 0 and z < 1


def test_normal_values_are_quiet():
    det, now = _detector()
    hist = det._baseline("demo", "written_mb_per_h", now)
    med = sorted(hist)[len(hist) // 2]
    findings = det.statistical("demo", {"written_mb_per_h": med, "created_per_h": 5}, now)
    assert findings == []


def test_bulk_write_is_warning_not_critical():
    det, now = _detector()
    findings = det.statistical("demo", {"written_mb_per_h": 5000, "created_per_h": 2000}, now)
    assert findings and max(f.severity for f in findings) == WARNING


def test_write_plus_delete_is_critical():
    det, now = _detector()
    findings = det.statistical("demo", {"written_mb_per_h": 5000, "modified_per_h": 3000}, now)
    assert max(f.severity for f in findings) == CRITICAL
    assert any(f.kind == "correlated" for f in findings)


def test_learning_phase_skips_statistics_but_rules_work():
    det, now = _detector(days=3)
    assert det.statistical("demo", {"written_mb_per_h": 99999}, now) == []
    rules = det.rules("demo", {"ransom_notes": 1}, {})
    assert rules and rules[0].severity == CRITICAL


def test_score():
    assert score([]) == (0, 0.0)
