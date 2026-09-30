import os
import subprocess
import sys

from sentinel.scanner import Scanner, is_ransom_note, shannon_entropy

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sim(*args):
    subprocess.run([sys.executable, "-m", "simulator.simulate", *args], check=True, cwd=ROOT,
                   stdout=subprocess.DEVNULL)


def test_entropy():
    assert shannon_entropy(b"aaaa") == 0
    assert shannon_entropy(os.urandom(65536)) > 7.9


def test_ransom_note_names():
    assert is_ransom_note("/x/HOW_TO_DECRYPT_FILES.txt")
    assert is_ransom_note("/x/restore_my_files.html")
    assert not is_ransom_note("/x/README.txt")
    assert not is_ransom_note("/x/decrypt_tool.py")


def test_ransomware_simulation_is_detected_and_reversible(tmp_path):
    d = str(tmp_path / "sandbox")
    sim("prepare", "--dir", d, "--files", "120")
    sc = Scanner("t", d)
    assert sc.scan(now=1000) is None
    quiet = sc.scan(now=1300)
    assert quiet.metrics["created_per_h"] == 0

    sim("ransomware", "--dir", d, "--mode", "mixed")
    m = sc.scan(now=1600).metrics
    assert m["ransom_notes"] >= 1
    assert m["ransom_ext"] >= 20
    assert m["ext_changed"] >= 20
    assert m["magic_mismatch"] + m["high_entropy"] >= 10

    sim("restore", "--dir", d)
    m = sc.scan(now=1900).metrics
    assert m["ransom_ext"] == 0 and m["ransom_notes"] == 0


def test_simulator_refuses_unprepared_dir(tmp_path):
    (tmp_path / "important.docx").write_text("x")
    r = subprocess.run([sys.executable, "-m", "simulator.simulate", "ransomware", "--dir", str(tmp_path)],
                       cwd=ROOT, capture_output=True)
    assert r.returncode != 0
    assert (tmp_path / "important.docx").read_text() == "x"


def test_sliding_window_gives_true_rate_with_short_scans(tmp_path):
    d = tmp_path / "w"
    d.mkdir()
    sc = Scanner("w", str(d))
    sc.scan(now=0)
    # 10 new files every 60 s = 600 files/hour of continuous activity
    for i in range(1, 8):
        for j in range(10):
            (d / f"f{i}_{j}.txt").write_text("x")
        m = sc.scan(now=i * 60).metrics
    assert abs(m["created_per_h"] - 600) < 1
