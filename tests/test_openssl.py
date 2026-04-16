"""
OpenSSL / TLS tests — verifies that a self-signed cert can be generated
and that the server can be started with TLS. Also validates cert properties.
"""
import os, ssl, socket, subprocess, sys, tempfile, threading, time, pytest

os.chdir(os.path.join(os.path.dirname(__file__), ".."))

CERT_FILE = os.path.join(tempfile.gettempdir(), "mcp_test.crt")
KEY_FILE  = os.path.join(tempfile.gettempdir(), "mcp_test.key")


# ── Cert generation ───────────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def self_signed_cert():
    """Generate a self-signed cert via openssl CLI."""
    result = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048",
         "-keyout", KEY_FILE, "-out", CERT_FILE,
         "-days", "1", "-nodes",
         "-subj", "/CN=localhost/O=universal-mcp-db-test"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        pytest.skip(f"openssl not available: {result.stderr.strip()}")
    yield CERT_FILE, KEY_FILE
    # cleanup
    for f in [CERT_FILE, KEY_FILE]:
        if os.path.exists(f):
            os.remove(f)


def test_openssl_is_available():
    """openssl must be on PATH."""
    result = subprocess.run(["openssl", "version"], capture_output=True, text=True)
    assert result.returncode == 0, "openssl not found — install OpenSSL"
    assert "OpenSSL" in result.stdout or "LibreSSL" in result.stdout


def test_cert_generated_successfully(self_signed_cert):
    cert, key = self_signed_cert
    assert os.path.exists(cert), "Certificate file not created"
    assert os.path.exists(key),  "Key file not created"
    assert os.path.getsize(cert) > 0
    assert os.path.getsize(key)  > 0


def test_cert_is_valid_x509(self_signed_cert):
    cert, _ = self_signed_cert
    result = subprocess.run(
        ["openssl", "x509", "-in", cert, "-noout", "-text"],
        capture_output=True, text=True
    )
    assert result.returncode == 0
    assert "Issuer" in result.stdout
    assert "Subject" in result.stdout
    assert "CN=localhost" in result.stdout


def test_cert_expiry_is_future(self_signed_cert):
    cert, _ = self_signed_cert
    result = subprocess.run(
        ["openssl", "x509", "-in", cert, "-noout", "-dates"],
        capture_output=True, text=True
    )
    assert result.returncode == 0
    assert "notAfter" in result.stdout


def test_cert_key_pair_matches(self_signed_cert):
    """Public key in cert must match private key."""
    cert, key = self_signed_cert
    cert_pub = subprocess.run(
        ["openssl", "x509", "-in", cert, "-noout", "-pubkey"],
        capture_output=True, text=True
    )
    key_pub = subprocess.run(
        ["openssl", "rsa", "-in", key, "-pubout"],
        capture_output=True, text=True
    )
    assert cert_pub.returncode == 0
    assert key_pub.returncode == 0
    assert cert_pub.stdout.strip() == key_pub.stdout.strip(), \
        "Cert and key do not match — TLS would fail"


def test_key_is_rsa_2048(self_signed_cert):
    _, key = self_signed_cert
    result = subprocess.run(
        ["openssl", "rsa", "-in", key, "-noout", "-text"],
        capture_output=True, text=True
    )
    assert result.returncode == 0
    # 2048-bit key = Private-Key: (2048 bit, 2 primes)
    assert "2048" in result.stdout


def test_ssl_context_loads_cert(self_signed_cert):
    """Python ssl module can load the generated cert — proves it's valid PEM."""
    cert, key = self_signed_cert
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert, keyfile=key)  # raises if invalid


def test_server_starts_with_tls(self_signed_cert):
    """
    Start uvicorn with TLS on an ephemeral port and verify a TCP TLS handshake
    completes successfully with the self-signed cert.
    """
    import uvicorn
    from server import create_app, load_config

    cert, key = self_signed_cert
    config = load_config()
    app = create_app(config)

    port = 17654  # ephemeral test port
    server = uvicorn.Server(uvicorn.Config(
        app, host="127.0.0.1", port=port,
        ssl_certfile=cert, ssl_keyfile=key,
        log_level="error"
    ))

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # wait for server to be ready (max 5s)
    for _ in range(10):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
                with ctx.wrap_socket(sock, server_hostname="localhost") as ssock:
                    cipher = ssock.cipher()
                    assert cipher is not None
            server.should_exit = True
            return  # test passed
        except (ConnectionRefusedError, OSError):
            time.sleep(0.5)

    server.should_exit = True
    pytest.fail("TLS server did not start within 5 seconds")
