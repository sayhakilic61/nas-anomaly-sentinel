"""Safe, reversible attack simulator for the demo sandbox.

It ONLY touches a directory it prepared itself (marked with .sentinel-sandbox)
and the "encryption" is a reversible XOR keystream whose key is stored in that
marker, so `restore` brings every file back.

    python -m simulator.simulate prepare    --dir /sandbox --files 400
    python -m simulator.simulate normal     --dir /sandbox
    python -m simulator.simulate bulk-copy  --dir /sandbox --mb 300
    python -m simulator.simulate ransomware --dir /sandbox --mode mixed --delay 0
    python -m simulator.simulate restore    --dir /sandbox
    python -m simulator.simulate cleanup    --dir /sandbox
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import random
import secrets
import shutil
import sys
import time
import zipfile

MARKER = ".sentinel-sandbox"
LOCK_EXT = ".locked"
NOTE_NAME = "HOW_TO_DECRYPT_FILES.txt"
WORDS = ("fatura rapor müşteri proje bütçe teklif sözleşme toplantı plan analiz stok sipariş "
         "invoice report customer project budget meeting plan analysis order").split()


# ---------------------------------------------------------------- helpers
def _guard(d: str) -> dict:
    real = os.path.realpath(d)
    if real in ("/", os.path.expanduser("~")) or not os.path.isfile(os.path.join(real, MARKER)):
        sys.exit(f"Refusing: {real} is not a sandbox prepared by this tool (missing {MARKER}).")
    with open(os.path.join(real, MARKER)) as fh:
        return json.load(fh)


def _text(rng: random.Random, n_words: int) -> str:
    lines = []
    for _ in range(max(1, n_words // 12)):
        lines.append(" ".join(rng.choice(WORDS) for _ in range(12)) + f" {rng.randint(1, 99999)}")
    return "\n".join(lines) + "\n"


def _keystream(key: bytes, n: int) -> bytes:
    out, counter = bytearray(), 0
    while len(out) < n:
        out += hashlib.sha256(key + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:n])


def _xor(data: bytes, key: bytes, path_salt: str) -> bytes:
    ks = _keystream(key + path_salt.encode(), len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


def _files(d: str):
    for root, _, files in os.walk(d):
        for f in files:
            if f != MARKER:
                yield os.path.join(root, f)


# ---------------------------------------------------------------- commands
def prepare(d: str, n: int, seed: int) -> None:
    rng = random.Random(seed)
    os.makedirs(d, exist_ok=True)
    marker = os.path.join(d, MARKER)
    if os.listdir(d) and not os.path.exists(marker):
        sys.exit(f"Refusing: {d} is not empty and not a sandbox.")
    with open(marker, "w") as fh:
        json.dump({"key": secrets.token_hex(32), "created": time.time()}, fh)
    folders = ["Muhasebe", "Projeler", "IK", "Satis", "Fotograflar", "Arsiv"]
    for i in range(n):
        folder = os.path.join(d, rng.choice(folders))
        os.makedirs(folder, exist_ok=True)
        kind = rng.choice(["txt", "csv", "md", "pdf", "docx", "png", "json"])
        name = f"{rng.choice(WORDS)}_{i:04d}.{kind}"
        path = os.path.join(folder, name)
        body = _text(rng, rng.randint(200, 4000))
        if kind == "pdf":
            data = b"%PDF-1.4\n" + body.encode() + b"\n%%EOF\n"
        elif kind == "png":
            data = b"\x89PNG\r\n\x1a\n" + os.urandom(rng.randint(4_000, 60_000))
        elif kind == "docx":
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                z.writestr("word/document.xml", f"<w:document><w:body>{body}</w:body></w:document>")
            data = buf.getvalue()
        elif kind == "json":
            data = json.dumps({"id": i, "text": body[:500]}, ensure_ascii=False).encode()
        else:
            data = body.encode()
        with open(path, "wb") as fh:
            fh.write(data)
    print(f"Prepared sandbox {d} with {n} files.")


def normal(d: str, seed: int) -> None:
    _guard(d)
    rng = random.Random(seed)
    files = [f for f in _files(d) if f.endswith((".txt", ".md", ".csv"))]
    for f in rng.sample(files, min(5, len(files))):
        with open(f, "a", encoding="utf-8") as fh:
            fh.write(_text(rng, 40))
    for i in range(3):
        with open(os.path.join(d, "Projeler", f"not_{int(time.time())}_{i}.txt"), "w", encoding="utf-8") as fh:
            fh.write(_text(rng, 200))
    print("Normal activity: edited 5 files, created 3 notes.")


def bulk_copy(d: str, mb: int) -> None:
    _guard(d)
    target = os.path.join(d, "Arsiv", f"yedek_kopya_{int(time.time())}")
    os.makedirs(target, exist_ok=True)
    chunk = 10
    for i in range(max(1, mb // chunk)):
        with open(os.path.join(target, f"video_{i:03d}.mp4"), "wb") as fh:
            fh.write(b"\x00\x00\x00\x18ftypmp42" + os.urandom(chunk * 1_000_000))
    print(f"Legit-looking bulk copy: {mb} MB written into {target}")


def ransomware(d: str, mode: str, delay: float, limit: int) -> None:
    meta = _guard(d)
    if meta.get("attacked"):
        sys.exit("Sandbox is already 'encrypted'. Run `restore` first.")
    key = bytes.fromhex(meta["key"])
    targets = [f for f in _files(d) if not f.endswith(LOCK_EXT) and os.path.basename(f) != NOTE_NAME
               and os.path.getsize(f) < 5_000_000]  # keep the demo fast
    random.shuffle(targets)
    if limit:
        targets = targets[:limit]
    dirs = set()
    for i, path in enumerate(targets):
        with open(path, "rb") as fh:
            data = fh.read()
        rel = os.path.relpath(path, d)
        enc = _xor(data, key, rel)
        in_place = mode == "inplace" or (mode == "mixed" and i % 2 == 0)
        if in_place:
            with open(path, "wb") as fh:
                fh.write(enc)
        else:
            with open(path + LOCK_EXT, "wb") as fh:
                fh.write(enc)
            os.remove(path)
        dirs.add(os.path.dirname(path))
        if delay:
            time.sleep(delay)
    for folder in dirs:
        with open(os.path.join(folder, NOTE_NAME), "w", encoding="utf-8") as fh:
            fh.write("SIMULATION ONLY - NAS Anomaly Sentinel demo. No real encryption.\n"
                     "Run: python -m simulator.simulate restore --dir <sandbox>\n")
    with open(os.path.join(d, MARKER), "w") as fh:
        json.dump({**meta, "attacked": [os.path.relpath(p, d) for p in targets], "mode": mode}, fh)
    print(f"Simulated ransomware ({mode}): {len(targets)} files, notes in {len(dirs)} folders.")


def restore(d: str) -> None:
    meta = _guard(d)
    key = bytes.fromhex(meta["key"])
    restored = 0
    for rel in meta.get("attacked", []):
        path = os.path.join(d, rel)
        src = path + LOCK_EXT if os.path.exists(path + LOCK_EXT) else path
        if not os.path.exists(src):
            continue
        with open(src, "rb") as fh:
            data = _xor(fh.read(), key, rel)
        with open(path, "wb") as fh:
            fh.write(data)
        if src != path:
            os.remove(src)
        restored += 1
    for f in list(_files(d)):
        if os.path.basename(f) == NOTE_NAME:
            os.remove(f)
    meta.pop("attacked", None)
    with open(os.path.join(d, MARKER), "w") as fh:
        json.dump(meta, fh)
    print(f"Restored {restored} files.")


def cleanup(d: str) -> None:
    _guard(d)
    for entry in os.listdir(d):
        p = os.path.join(d, entry)
        shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
    print(f"Sandbox {d} emptied.")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["prepare", "normal", "bulk-copy", "ransomware", "restore", "cleanup"])
    ap.add_argument("--dir", default=os.getenv("SANDBOX_DIR", "/sandbox"))
    ap.add_argument("--files", type=int, default=400)
    ap.add_argument("--mb", type=int, default=300)
    ap.add_argument("--mode", choices=["rename", "inplace", "mixed"], default="mixed")
    ap.add_argument("--delay", type=float, default=0.0, help="seconds per file (slow, stealthy attack)")
    ap.add_argument("--limit", type=int, default=0, help="only attack N files")
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    {
        "prepare": lambda: prepare(a.dir, a.files, a.seed),
        "normal": lambda: normal(a.dir, a.seed),
        "bulk-copy": lambda: bulk_copy(a.dir, a.mb),
        "ransomware": lambda: ransomware(a.dir, a.mode, a.delay, a.limit),
        "restore": lambda: restore(a.dir),
        "cleanup": lambda: cleanup(a.dir),
    }[a.command]()


if __name__ == "__main__":
    main()
