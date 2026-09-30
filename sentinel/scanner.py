"""Filesystem scanner.

Keeps an in-memory snapshot {path: (size, mtime_ns)} of each watched share and,
on every scan, turns the diff into rate metrics plus ransomware indicators:

* created / modified / deleted files per hour, MB written per hour, growth
* bulk extension changes  (report.docx  ->  report.docx.locked)
* known ransomware extensions and ransom-note file names
* magic-byte mismatch      (a ".pdf" that no longer starts with %PDF)
* high Shannon entropy in files that are normally compressible text

Watched paths are mounted read-only; the scanner only reads the first 64 KB of a
bounded random sample of changed files, so it stays cheap on large shares.
"""
from __future__ import annotations

import math
import os
import random
import re
import time
from collections import Counter, deque
from dataclasses import dataclass, field

HEAD_BYTES = 64 * 1024
# Rates are computed over a sliding window of at least this many seconds. With
# 60 s scans, continuous activity is reported at its true hourly rate, while a
# short burst (5 edits) is not extrapolated to 300/h.
MIN_RATE_WINDOW = 300.0

RANSOM_EXTENSIONS = {
    ".locked", ".encrypted", ".enc", ".crypt", ".crypted", ".cry", ".crypto", ".locky",
    ".zepto", ".odin", ".cerber", ".cerber3", ".wannacry", ".wncry", ".wnry", ".ryk",
    ".ryuk", ".conti", ".lockbit", ".djvu", ".stop", ".phobos", ".dharma", ".makop",
    ".akira", ".blackcat", ".hive", ".royal", ".babyk", ".medusa", ".deadbolt",
    ".qlocker", ".ech0raix", ".eking", ".pay2key", ".sodinokibi", ".revil", ".crab",
}

# Words that together with a note-like extension indicate a ransom note.
_NOTE_WORDS = re.compile(r"(decrypt|recover|restore|ransom|unlock|how_to_back|your_files|files_back)", re.I)
_NOTE_EXTS = {".txt", ".html", ".htm", ".hta", ".url", ".rtf"}

# Text-like formats: normally low entropy. High entropy here is a strong signal.
LOW_ENTROPY_EXTS = {
    ".txt", ".csv", ".tsv", ".log", ".md", ".json", ".xml", ".html", ".htm", ".sql",
    ".py", ".js", ".ts", ".css", ".ini", ".conf", ".cfg", ".yml", ".yaml", ".svg",
    ".sh", ".bat", ".ps1", ".rtf", ".tex", ".php", ".java", ".c", ".h", ".cpp", ".go",
}

MAGIC = {
    ".pdf": (b"%PDF",),
    ".png": (b"\x89PNG",),
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".gif": (b"GIF87a", b"GIF89a"),
    ".zip": (b"PK\x03\x04", b"PK\x05\x06"),
    ".docx": (b"PK\x03\x04",),
    ".xlsx": (b"PK\x03\x04",),
    ".pptx": (b"PK\x03\x04",),
    ".odt": (b"PK\x03\x04",),
    ".ods": (b"PK\x03\x04",),
    ".doc": (b"\xd0\xcf\x11\xe0",),
    ".xls": (b"\xd0\xcf\x11\xe0",),
    ".ppt": (b"\xd0\xcf\x11\xe0",),
    ".gz": (b"\x1f\x8b",),
    ".7z": (b"7z\xbc\xaf\x27\x1c",),
    ".rar": (b"Rar!",),
    ".bmp": (b"BM",),
    ".sqlite": (b"SQLite format 3",),
}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def full_ext(path: str) -> str:
    return os.path.splitext(path)[1].lower()


def is_ransom_note(path: str) -> bool:
    name = os.path.basename(path)
    return full_ext(name) in _NOTE_EXTS and bool(_NOTE_WORDS.search(name))


@dataclass
class ScanResult:
    metrics: dict[str, float]
    samples: dict[str, list[str]] = field(default_factory=dict)  # indicator -> example paths


class Scanner:
    def __init__(self, name: str, root: str, exclude_dirs: set[str] | None = None,
                 entropy_sample: int = 200):
        self.name = name
        self.root = root
        self.exclude_dirs = exclude_dirs or set()
        self.entropy_sample = entropy_sample
        self._snapshot: dict[str, tuple[int, int]] | None = None
        self._last_ts: float | None = None
        self._window: deque = deque()  # (start_ts, end_ts, counts)

    # ------------------------------------------------------------------
    def _walk(self) -> dict[str, tuple[int, int]]:
        snap: dict[str, tuple[int, int]] = {}
        stack = [self.root]
        while stack:
            directory = stack.pop()
            try:
                with os.scandir(directory) as it:
                    for entry in it:
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                if entry.name not in self.exclude_dirs:
                                    stack.append(entry.path)
                            elif entry.is_file(follow_symlinks=False):
                                st = entry.stat(follow_symlinks=False)
                                snap[entry.path] = (st.st_size, st.st_mtime_ns)
                        except OSError:
                            continue
            except OSError:
                continue
        return snap

    @staticmethod
    def _read_head(path: str) -> bytes | None:
        try:
            with open(path, "rb") as fh:
                return fh.read(HEAD_BYTES)
        except OSError:
            return None

    # ------------------------------------------------------------------
    def scan(self, now: float | None = None) -> ScanResult | None:
        """Return metrics for the interval since the previous scan (None on first scan)."""
        now = now if now is not None else time.time()
        current = self._walk()
        previous, prev_ts = self._snapshot, self._last_ts
        self._snapshot, self._last_ts = current, now
        if previous is None or prev_ts is None:
            return None  # first pass only establishes the snapshot


        cur_keys, prev_keys = current.keys(), previous.keys()
        created = [p for p in cur_keys - prev_keys]
        deleted = [p for p in prev_keys - cur_keys]
        modified = [p for p in cur_keys & prev_keys if current[p] != previous[p]]

        total_bytes = sum(v[0] for v in current.values())
        prev_bytes = sum(v[0] for v in previous.values())
        written = sum(current[p][0] for p in created) + sum(current[p][0] for p in modified)

        # --- extension changes (rename-and-encrypt pattern) ----------------
        deleted_set = set(deleted)
        deleted_stems = {os.path.splitext(p)[0]: full_ext(p) for p in deleted}
        ext_changed = []
        for p in created:
            stem, ext = os.path.splitext(p)
            if stem in deleted_set:  # a.docx -> a.docx.locked
                ext_changed.append(p)
            elif stem in deleted_stems and deleted_stems[stem] != ext.lower():  # a.docx -> a.xyz
                ext_changed.append(p)

        ransom_ext = [p for p in created + modified if full_ext(p) in RANSOM_EXTENSIONS]
        ransom_notes = [p for p in created + modified if is_ransom_note(p)]

        # --- content checks on a bounded sample ----------------------------
        changed = [p for p in created + modified if current[p][0] > 0]
        sample = changed if len(changed) <= self.entropy_sample else random.sample(changed, self.entropy_sample)
        magic_mismatch, high_entropy = [], []
        for p in sample:
            head = self._read_head(p)
            if not head:
                continue
            ext = full_ext(p)
            if ext in MAGIC and len(head) >= 8 and not head.startswith(MAGIC[ext]):
                magic_mismatch.append(p)
            if len(head) >= 512 and (ext in LOW_ENTROPY_EXTS or ext in RANSOM_EXTENSIONS):
                if shannon_entropy(head) > 7.2:
                    high_entropy.append(p)
        sampled = len(sample)

        counts = {
            "created": len(created), "modified": len(modified), "deleted": len(deleted),
            "written": written, "growth": total_bytes - prev_bytes,
        }
        self._window.append((prev_ts, now, counts))
        while self._window and self._window[0][1] <= now - MIN_RATE_WINDOW:
            self._window.popleft()
        covered = now - self._window[0][0]
        per_hour = 3600.0 / max(covered, MIN_RATE_WINDOW)
        total = {k: sum(c[k] for _, _, c in self._window) for k in counts}

        metrics = {
            "total_gb": total_bytes / 1e9,
            "file_count": float(len(current)),
            "growth_mb_per_h": total["growth"] / 1e6 * per_hour,
            "created_per_h": total["created"] * per_hour,
            "modified_per_h": total["modified"] * per_hour,
            "deleted_per_h": total["deleted"] * per_hour,
            "written_mb_per_h": total["written"] / 1e6 * per_hour,
            "ext_changed": float(len(ext_changed)),
            "ransom_ext": float(len(ransom_ext)),
            "ransom_notes": float(len(ransom_notes)),
            "magic_mismatch": float(len(magic_mismatch)),
            "high_entropy": float(len(high_entropy)),
            "high_entropy_ratio": (len(high_entropy) / sampled) if sampled else 0.0,
        }
        samples = {
            "ext_changed": ext_changed[:5],
            "ransom_ext": ransom_ext[:5],
            "ransom_notes": ransom_notes[:5],
            "magic_mismatch": magic_mismatch[:5],
            "high_entropy": high_entropy[:5],
        }
        return ScanResult(metrics=metrics, samples=samples)
