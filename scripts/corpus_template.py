"""Corpus requests are templates (shared by the e2e scripts).

Each run gives every request issued_at = now + setup.issued_at_offset and
replaces every distinct nonce with a fresh random one. Requests that share a
nonce in the entry still share one, which is how replay attacks are written.
stopbard has no clock setting, so this rewrite is the only way old fixtures
stay fresh.
"""
import base64, datetime, os, re


class Templater:
    def __init__(self, offset="0s"):
        m = re.fullmatch(r"([+-]?\d+)s", offset or "0s")
        if not m:
            raise ValueError(f"bad issued_at_offset {offset!r}")
        self.offset = datetime.timedelta(seconds=int(m.group(1)))
        self.nonces = {}

    def render(self, request):
        r = dict(request)
        now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0) + self.offset
        r["issued_at"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        if r.get("nonce") not in self.nonces:
            self.nonces[r.get("nonce")] = base64.urlsafe_b64encode(os.urandom(18)).decode()
        r["nonce"] = self.nonces[r.get("nonce")]
        return r
