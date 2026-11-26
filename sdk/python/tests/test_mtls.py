"""mTLS (CS-103): the client presents its certificate to an https stopbard and
sends no bearer header. Certificates are minted per run (cryptography, a dev
extra); no private key is committed."""
import datetime as dt
import ipaddress
import ssl
import threading
from http.server import HTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from stopbar import Client, StopbarUnavailable
from test_client import _Handler, evm


def _certs(tmp_path):
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])

    def issue(key, issuer_key, *, ca=False, sans=(), eku=None):
        b = (x509.CertificateBuilder().subject_name(ca_name if ca else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")]))
             .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - dt.timedelta(hours=1)).not_valid_after(now + dt.timedelta(hours=1))
             .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
             # Python 3.13's strict verification needs SKI/AKI (and key usage on the CA)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False))
        if ca:
            b = b.add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                              key_encipherment=False, data_encipherment=False, key_agreement=False,
                                              encipher_only=False, decipher_only=False), critical=True)
        if sans:
            b = b.add_extension(x509.SubjectAlternativeName(list(sans)), critical=False)
        if eku:
            b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
        return b.sign(issuer_key, hashes.SHA256())

    def write(name, cert, key=None):
        (tmp_path / f"{name}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        if key is not None:
            (tmp_path / f"{name}.key").write_bytes(key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        return str(tmp_path / f"{name}.crt"), str(tmp_path / f"{name}.key")

    srv_key, cli_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca = issue(ca_key, ca_key, ca=True)
    srv = issue(srv_key, ca_key, sans=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))], eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    cli = issue(cli_key, ca_key, sans=[x509.UniformResourceIdentifier("spiffe://acme/bot")], eku=[ExtendedKeyUsageOID.CLIENT_AUTH])
    return write("ca", ca)[0], write("server", srv, srv_key), write("client", cli, cli_key)


def test_mtls_presents_client_certificate(tmp_path):
    ca, (srv_cert, srv_key), (cli_cert, cli_key) = _certs(tmp_path)
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    srv.responder = lambda path, body: (200, {"request_id": body["id"], "outcome": "allow"})
    srv.get_responder = None
    srv.last_auth = None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(srv_cert, srv_key)
    ctx.load_verify_locations(ca)
    ctx.verify_mode = ssl.CERT_REQUIRED  # no client certificate: no handshake
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"https://127.0.0.1:{srv.server_address[1]}"

    c = Client(url, tenant="acme", agent_id="bot", client_cert=cli_cert, client_key=cli_key, ca_cert=ca)
    assert c.evaluate(evm(c)).outcome == "allow"
    assert srv.last_auth is None  # the certificate is the identity; no bearer header
    no_cert = Client(url, tenant="acme", agent_id="bot", ca_cert=ca)
    with pytest.raises(StopbarUnavailable):  # handshake refused: fail closed
        no_cert.evaluate(evm(no_cert))
    with pytest.raises(ValueError):
        Client(url, client_cert=cli_cert)
    srv.shutdown()
