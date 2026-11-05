"""Shared helper: read a key from the macOS keychain, never logging it.
(The retry/abort latch for PILOT-2 lives in harness.spend.Meter.)
"""
import subprocess


def read_keychain(service: str) -> str:
    r = subprocess.run(["security", "find-generic-password", "-s", service, "-w"], capture_output=True, text=True)
    if r.returncode or not r.stdout.strip():
        raise SystemExit(f"no keychain entry {service!r} (security exit {r.returncode})")
    return r.stdout.strip()
