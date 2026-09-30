from sentinel import config
from sentinel.alerts import Alerter
from sentinel.detector import CRITICAL, WARNING, Finding, score


def f(metric, sev, kind="stat", z=10.0):
    return Finding("demo", kind, metric, sev, 1.0, 0.0, z)


def test_score_matches_status():
    s, v = score([f("created_per_h", WARNING, z=200), f("written_mb_per_h", WARNING, z=300)])
    assert s == WARNING and 30 <= v < 70
    s, v = score([f("ransom_notes", CRITICAL, "rule", None)])
    assert s == CRITICAL and v >= 70


def test_one_mail_per_incident():
    a = Alerter(config.load())
    attack = [f("ransom_notes", CRITICAL, "rule"), f("deleted_per_h", CRITICAL)]
    aftermath = [f("deleted_per_h", CRITICAL), f("growth_mb_per_h", WARNING)]
    assert a.should_send(CRITICAL, attack, 1000)
    assert not a.should_send(CRITICAL, aftermath, 1060)       # same incident, no new info
    assert a.should_send(CRITICAL, [f("magic_mismatch", CRITICAL, "rule")], 1120)  # new rule hit
    assert a.should_send(CRITICAL, aftermath, 1120 + 1801)     # cooldown over (restarts at last mail)


def test_escalation_is_sent_immediately():
    a = Alerter(config.load())
    assert a.should_send(WARNING, [f("written_mb_per_h", WARNING)], 1000)
    assert a.should_send(CRITICAL, [f("ransom_notes", CRITICAL, "rule")], 1060)
