"""protected_read interop with an independent ML-KEM-768 implementation (Task 1.16).

For each run: generate a keypair with pqcrypto, set up a fresh state dir,
call the real adapter (a new `node track4_service.cjs` per request, like the
worker), decapsulate the returned ciphertext and check the proof with
hmac.compare_digest over UTF-8(challenge + body). Also checks that an
unauthorized actor gets exactly {"decision":"deny"}.

Prints `interop N/RUNS`; exits 0 only if every run passed.
Usage: python3 protected_read_interop.py [--runs 25] [--node PATH] [--entry PATH]
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

from pqcrypto.kem.ml_kem_768 import decrypt, generate_keypair

ROOT = Path(__file__).resolve().parents[2]


def call(node, entry, state_dir, request, timeout):
    env = dict(os.environ, TRACK4_STATE_DIR=state_dir, TMPDIR=state_dir, TEMP=state_dir, TMP=state_dir)
    proc = subprocess.run([node, str(entry)], input=json.dumps(request, ensure_ascii=False).encode("utf-8"),
                          capture_output=True, cwd=str(entry.parent), env=env, timeout=timeout)
    if proc.returncode != 0 or proc.stderr:
        raise AssertionError(f"exit {proc.returncode}, stderr {len(proc.stderr)} bytes")
    return json.loads(proc.stdout)


def one_run(node, entry, timeout):
    public_key, secret_key = generate_keypair()
    body = "ünïcode ✓ <i> " + secrets.token_hex(8)
    challenge = "chal ✓ " + secrets.token_hex(16)
    owner, other = secrets.token_hex(8), secrets.token_hex(8)
    with tempfile.TemporaryDirectory(prefix="kig-interop-") as state_dir:
        ready = call(node, entry, state_dir, {"op": "setup", "owners": {"doc": owner}, "contents": {"doc": body},
                                              "disabled": [], "key_material": "synthetic-only"}, timeout)
        assert ready == {"ready": True}, "setup"
        request = {"op": "protected_read", "actor": owner, "asset": "doc", "challenge": challenge,
                   "public_key": base64.b64encode(public_key).decode("ascii")}
        res = call(node, entry, state_dir, request, timeout)
        assert set(res) == {"ciphertext", "proof"}, "allow shape"
        ciphertext = base64.b64decode(res["ciphertext"], validate=True)
        assert len(ciphertext) == 1088, "ciphertext length"
        shared = decrypt(secret_key, ciphertext)
        expected = hmac.new(shared, (challenge + body).encode("utf-8"), hashlib.sha256).hexdigest()
        assert res["proof"] == res["proof"].lower(), "proof must be lowercase hex"
        assert hmac.compare_digest(res["proof"], expected), "proof mismatch"
        denied = call(node, entry, state_dir, dict(request, actor=other), timeout)
        assert denied == {"decision": "deny"}, "unauthorized actor"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=25)
    ap.add_argument("--node", default="node")
    ap.add_argument("--entry", default=str(ROOT / "track4_service.cjs"))
    ap.add_argument("--timeout", type=float, default=60.0)
    args = ap.parse_args()
    entry = Path(args.entry).resolve()
    passed = 0
    for i in range(args.runs):
        try:
            one_run(args.node, entry, args.timeout)
            passed += 1
        except Exception as e:  # report and keep going: the count is the result
            print(f"run {i + 1}: FAIL {type(e).__name__}: {e}", file=sys.stderr)
    print(f"interop {passed}/{args.runs}")
    return 0 if passed == args.runs else 1


if __name__ == "__main__":
    sys.exit(main())
