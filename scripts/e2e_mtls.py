"""mTLS / SPIFFE client identity end to end (CS-103 increment 3, ADR 0006;
scripts/e2e.sh and the CI go job).

Usage: e2e_mtls.py PATH/TO/stopbard PATH/TO/stopbar
Needs `cryptography` (certificates are minted here, per run, into a temp dir:
no private key is committed) and, for the TypeScript check, the built
sdk/typescript/dist (scripts/e2e_sdk.sh builds it).

Startup: stopbard refuses TLS without a client CA, a client CA without a
server cert, a world-readable server key, mTLS combined with -auth-keys, and an
unreadable certificate; with mTLS configured it accepts a non-loopback listen
address (the CS-103 gate). Then a gatekeeper stopbard serves https with
client-certificate auth: the Python SDK and the TypeScript SDK, each presenting
the bot's certificate (SPIFFE ID mapped to tenant demo, agent bot), get an allow
with a signed tx (the adapter accepted a token bound to auth_method mtls); no
certificate, an unmapped SPIFFE ID and a certificate without a SAN are 401; a
certificate from another CA fails the handshake; a body naming another agent is
403 IDENTITY_MISMATCH; the CLI reaches the API with --cert. Afterwards the audit
log verifies offline and its records carry identity method mtls with the SPIFFE
ID as key_id.
"""
import datetime as dt
import ipaddress
import json
import os
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk", "python"))
from stopbar import Client  # noqa: E402

stopbard, cli = sys.argv[1], sys.argv[2]
BOT = "spiffe://demo.test/agents/bot"
WALLET = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"  # Anvil account 0: public test key, never funded
BOB = "0x000000000000000000000000000000000000b0b0"
failures = 0


def check(name, ok, detail=""):
    global failures
    failures += not ok
    print("ok  " if ok else "FAIL", name + (f": {detail}" if detail else ""))


class CA:
    def __init__(self, name):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        self.cert = self._sign(self.name, self.key, ca=True)

    def _sign(self, subject, key, ca=False, sans=(), eku=None):
        now = dt.datetime.now(dt.timezone.utc)
        b = (x509.CertificateBuilder().subject_name(subject).issuer_name(self.name).public_key(key.public_key())
             .serial_number(x509.random_serial_number())
             .not_valid_before(now - dt.timedelta(hours=1)).not_valid_after(now + dt.timedelta(hours=2))
             .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False)
             .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=ca, crl_sign=ca, content_commitment=False,
                                          key_encipherment=False, data_encipherment=False, key_agreement=False,
                                          encipher_only=False, decipher_only=False), critical=True))
        if sans:
            b = b.add_extension(x509.SubjectAlternativeName(list(sans)), critical=False)
        if eku:
            b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
        return b.sign(self.key, hashes.SHA256())

    def issue(self, tmp, name, sans=(), eku=(ExtendedKeyUsageOID.CLIENT_AUTH,)):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = self._sign(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]), key, sans=sans, eku=list(eku))
        crt, kp = os.path.join(tmp, name + ".crt"), os.path.join(tmp, name + ".key")
        open(crt, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
        fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
        os.close(fd)
        return crt, kp

    def write(self, tmp, name):
        p = os.path.join(tmp, name)
        open(p, "wb").write(self.cert.public_bytes(serialization.Encoding.PEM))
        return p


def start(args):
    proc = subprocess.Popen([stopbard, *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = proc.stdout.readline()
    if "listening on" not in line:
        proc.kill()
        raise SystemExit(f"stopbard did not start: {line!r} {proc.stderr.read()}")
    return proc, line.rsplit(" ", 1)[1].strip()


def refused(args):
    try:
        out = subprocess.run([stopbard, *args], capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        return False, "still running"
    return out.returncode != 0, out.stderr.strip().splitlines()[-1] if out.stderr.strip() else ""


def ctx(ca, cert=None):
    c = ssl.create_default_context(cafile=ca)
    if cert:
        c.load_cert_chain(*cert)
    return c


def post(url, body, context):
    r = urllib.request.Request(url + "/v1/evaluate", data=json.dumps(body).encode(), method="POST",
                               headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=10, context=context) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def request(agent, nonce):
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"id": "req_" + uuid.uuid4().hex[:12], "tenant": "demo", "actor": {"agent_id": agent, "session_id": "s1"},
            "action": {"kind": "evm_tx", "chain_id": 8453, "from": WALLET.lower(), "to": BOB, "value_wei": "1000",
                       "data": "0x", "tx_type": 2, "tx_nonce": "0", "gas_limit": "21000",
                       "max_fee_per_gas": "200000000", "max_priority_fee_per_gas": "100000000"},
            "provenance": {"labels": ["trusted_user"]}, "issued_at": now, "ttl_seconds": 60, "nonce": nonce}


with tempfile.TemporaryDirectory() as tmp:
    ca, other = CA("stopbar-e2e-client-ca"), CA("stopbar-e2e-other-ca")
    ca_pem = ca.write(tmp, "ca.pem")
    server = ca.issue(tmp, "server", sans=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))],
                      eku=(ExtendedKeyUsageOID.SERVER_AUTH,))
    bot = ca.issue(tmp, "bot", sans=[x509.UniformResourceIdentifier(BOT)])
    ghost = ca.issue(tmp, "ghost", sans=[x509.UniformResourceIdentifier("spiffe://demo.test/agents/ghost")])
    nosan = ca.issue(tmp, "nosan")
    foreign = other.issue(tmp, "foreign", sans=[x509.UniformResourceIdentifier(BOT)])
    ids = os.path.join(tmp, "ids.json")
    json.dump([{"spiffe_id": BOT, "tenant": "demo", "agent_id": "bot", "scopes": ["evaluate"]}], open(ids, "w"))
    world = os.path.join(tmp, "world.json")
    json.dump({"balances": {"ETH": "10"}, "prices_usd": {"ETH": "3500"}, "known_destinations": [BOB],
               "limits": [{"scope": "wallet", "window": "24h", "max_usd": "50000", "max_count": 10}]}, open(world, "w"))
    wallet = os.path.join(tmp, "wallet")
    fd = os.open(wallet, os.O_WRONLY | os.O_CREAT, 0o600)
    os.write(fd, b"stopbar-dev-wallet-secp256k1-v1\nac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n")
    os.close(fd)
    open_key = os.path.join(tmp, "open.key")
    open(open_key, "wb").write(open(server[1], "rb").read())
    os.chmod(open_key, 0o644)
    keys_json = os.path.join(tmp, "keys.json")
    json.dump([{"id": "ak", "tenant": "demo", "agent_id": "bot", "scopes": ["evaluate"], "sha256": "0" * 64}], open(keys_json, "w"))
    mtls = ["-tls-cert", server[0], "-tls-key", server[1], "-tls-client-ca", ca_pem, "-mtls-identities", ids]

    print("--- startup refuses insecure combinations")
    for name, args in {
        "TLS without a client CA": ["-tls-cert", server[0], "-tls-key", server[1], "-mtls-identities", ids],
        "client CA without a server cert": ["-tls-client-ca", ca_pem, "-mtls-identities", ids],
        "world-readable server key": ["-tls-cert", server[0], "-tls-key", open_key, "-tls-client-ca", ca_pem, "-mtls-identities", ids],
        "unreadable server cert": ["-tls-cert", os.path.join(tmp, "missing.crt"), "-tls-key", server[1], "-tls-client-ca", ca_pem, "-mtls-identities", ids],
        "mTLS with -auth-keys": [*mtls, "-auth-keys", keys_json],
    }.items():
        ok, why = refused(["-listen", "127.0.0.1:0", *args])
        check(f"refused: {name}", ok, why)
    proc, addr = start(["-listen", "0.0.0.0:0", *mtls])
    proc.terminate()
    proc.wait()
    check("non-loopback listen allowed with mTLS (CS-103 gate)", True, addr)

    print("--- gatekeeper stopbard over mTLS")
    state, dkey = os.path.join(tmp, "state"), os.path.join(tmp, "decision.key")
    subprocess.run([cli, "keygen", "decision-key", dkey], check=True, capture_output=True)
    proc, addr = start(["-listen", "127.0.0.1:0", "-dev-world", world, "-tenant", "demo", "-state-dir", state,
                        "-decision-key", dkey, "-dev-wallet", wallet, *mtls])
    url = "https://" + addr
    try:
        sb = Client(url, tenant="demo", agent_id="bot", client_cert=bot[0], client_key=bot[1], ca_cert=ca_pem)
        d = sb.evaluate(sb.evm_tx(chain_id=8453, from_addr=WALLET, to=BOB, value_wei="1000", tx_nonce="0", gas_limit="21000",
                                  max_fee_per_gas="200000000", max_priority_fee_per_gas="100000000"), labels=["trusted_user"])
        check("Python SDK with client cert: allow with a signed tx", d.outcome == "allow" and bool(d.signed_tx), d.outcome)

        ts = subprocess.run(["node", "--input-type=module", "-e", """
import { readFileSync } from "node:fs";
import { Client } from "./sdk/typescript/dist/src/index.js";
const [url, cert, key, ca, wallet, bob] = process.argv.slice(1);
const sb = new Client(url, { tenant: "demo", agentId: "bot",
  tls: { cert: readFileSync(cert), key: readFileSync(key), ca: readFileSync(ca) } });
const d = await sb.evaluate(Client.evmTx({ chainId: 8453, from: wallet, to: bob, valueWei: "1000", txNonce: "0",
  gasLimit: "21000", maxFeePerGas: "200000000", maxPriorityFeePerGas: "100000000" }), { labels: ["trusted_user"] });
console.log(d.outcome, Boolean(d.signedTx));
""", url, bot[0], bot[1], ca_pem, WALLET, BOB], capture_output=True, text=True,
            cwd=os.path.join(os.path.dirname(__file__), ".."))
        check("TypeScript SDK with client cert: allow with a signed tx", ts.stdout.strip() == "allow true",
              (ts.stdout + ts.stderr).strip()[-300:])

        for name, cert in {"no client cert": None, "unmapped SPIFFE ID": ghost, "cert without a SAN": nosan}.items():
            status, b = post(url, request("bot", uuid.uuid4().hex), ctx(ca_pem, cert))
            check(f"{name}: 401", status == 401 and b.get("code") == "UNAUTHENTICATED", f"{status} {b.get('code')}")
        try:
            post(url, request("bot", uuid.uuid4().hex), ctx(ca_pem, foreign))
            check("cert from another CA: handshake refused", False, "request went through")
        except (ssl.SSLError, urllib.error.URLError, ConnectionError) as e:
            check("cert from another CA: handshake refused", True, type(e).__name__)
        status, b = post(url, request("mallory", uuid.uuid4().hex), ctx(ca_pem, bot))
        check("body names another agent: 403 IDENTITY_MISMATCH", status == 403 and b.get("code") == "IDENTITY_MISMATCH",
              f"{status} {b.get('code')}")

        out = subprocess.run([cli, "breaker", "status", "--tenant", "demo", "--url", url, "--cert", bot[0],
                              "--cert-key", bot[1], "--cacert", ca_pem], capture_output=True, text=True)
        check("CLI with --cert reaches the authenticated API", out.returncode == 0, (out.stdout + out.stderr).strip()[:200])
        out = subprocess.run([cli, "breaker", "status", "--tenant", "demo", "--url", url, "--cacert", ca_pem],
                             capture_output=True, text=True)
        check("CLI without a cert: 401", out.returncode != 0 and "401" in out.stdout + out.stderr, out.stderr.strip()[:200])

        with urllib.request.urlopen(url + "/v1/keys", timeout=10, context=ctx(ca_pem)) as r:
            open(os.path.join(tmp, "jwks.json"), "wb").write(r.read())
    finally:
        proc.terminate()
        proc.wait(timeout=15)

    v = subprocess.run([cli, "audit", "verify", "--state-dir", state, "--keys", os.path.join(tmp, "jwks.json"),
                        "--require-covered"], capture_output=True, text=True)
    check("audit log verifies offline", v.returncode == 0, (v.stdout + v.stderr).strip()[-200:])
    ex = subprocess.run([cli, "audit", "export", "--state-dir", state], capture_output=True, text=True, check=True)
    idents = [json.loads(l)["body"].get("identity") for l in ex.stdout.splitlines() if l.strip()]
    idents = [i for i in idents if isinstance(i, dict)]  # the registry seed records identity "dev-world"
    bad = [i for i in idents if not ( i.get("method") == "mtls" and i.get("key_id") == BOT
                                     and i.get("agent_id") == "bot")]
    check("audit records carry the mTLS identity", bool(idents) and not bad, f"{len(idents)} records, unexpected {bad[:3]}")

if failures:
    raise SystemExit(f"{failures} mTLS check(s) failed")
print("ok   mTLS / SPIFFE client identity end to end")
