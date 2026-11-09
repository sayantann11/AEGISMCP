"""Create throwaway local TLS/ACL credentials for the Redis integration test.

This is for a developer workstation only. Generated files are gitignored.
Never use these self-signed certificates or local key files in production.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
from ipaddress import ip_address
from pathlib import Path
import base64
import argparse
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


ROOT = Path(__file__).resolve().parents[1]
TLS_DIR = ROOT / "secrets" / "redis-tls"
ACL_FILE = ROOT / "docker" / "users.acl"
ENV_FILE = ROOT / ".env.redis"


def private_key_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def issue_cert(subject_cn: str, key: rsa.RSAPrivateKey, ca_name: x509.Name,
               ca_key: rsa.RSAPrivateKey, *, server: bool = False) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(minutes=5))
               .not_valid_after(now + timedelta(days=90))
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False))
    if server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"), x509.DNSName("redis-vault"),
                x509.IPAddress(ip_address("127.0.0.1")),
            ]), critical=False)
        usage = ExtendedKeyUsageOID.SERVER_AUTH
    else:
        usage = ExtendedKeyUsageOID.CLIENT_AUTH
    return (builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
            .sign(ca_key, hashes.SHA256()))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--replace", action="store_true", help="replace only the local test credentials this script generates")
    args = parser.parse_args()
    paths = [TLS_DIR, ACL_FILE, ENV_FILE]
    if any(p.exists() for p in paths):
        if not args.replace:
            raise SystemExit("Local test TLS/ACL/.env.redis already exist. Use --replace to rotate them.")
        for name in ("ca.crt", "server.crt", "server.key", "client.crt", "client.key"):
            candidate = TLS_DIR / name
            if candidate.exists():
                candidate.unlink()
        if TLS_DIR.exists():
            TLS_DIR.rmdir()
        for candidate in (ACL_FILE, ENV_FILE):
            if candidate.exists():
                candidate.unlink()
    TLS_DIR.mkdir(parents=True)
    ACL_FILE.parent.mkdir(parents=True, exist_ok=True)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Sutraksh local test CA")])
    now = datetime.now(timezone.utc)
    ca_cert = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
               .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(minutes=5))
               .not_valid_after(now + timedelta(days=90))
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
               .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
               .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False,
                    key_cert_sign=True, crl_sign=True, content_commitment=False,
                    data_encipherment=False, key_agreement=False, encipher_only=False,
                    decipher_only=False), critical=True)
               .sign(ca_key, hashes.SHA256()))
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_cert = issue_cert("localhost", server_key, ca_name, ca_key, server=True)
    client_cert = issue_cert("sutraksh-live-test", client_key, ca_name, ca_key)

    (TLS_DIR / "ca.crt").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    (TLS_DIR / "server.crt").write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    (TLS_DIR / "server.key").write_bytes(private_key_pem(server_key))
    (TLS_DIR / "client.crt").write_bytes(client_cert.public_bytes(serialization.Encoding.PEM))
    (TLS_DIR / "client.key").write_bytes(private_key_pem(client_key))

    password = secrets.token_urlsafe(36)
    password_hash = sha256(password.encode("utf-8")).hexdigest()
    ACL_FILE.write_text(
        "user default off\n"
        f"user aegismcp on #{password_hash} ~aegis:v1:* -@all +get +set +expire +del +pttl\n",
        encoding="utf-8")
    env_values = {
        "SUTRAKSH_REDIS_HOST": "127.0.0.1", "SUTRAKSH_REDIS_PORT": "6380",
        # Redis ACL identity and namespace are intentionally retained so
        # existing local Redis deployments keep working during the rename.
        "SUTRAKSH_REDIS_USERNAME": "aegismcp", "SUTRAKSH_REDIS_PASSWORD": password,
        "SUTRAKSH_AES_KEY_B64": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        "SUTRAKSH_INDEX_KEY_B64": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
    }
    ENV_FILE.write_text("".join(f"{k}={v}\n" for k, v in env_values.items()), encoding="utf-8")
    try:
        ENV_FILE.chmod(0o600)
        (TLS_DIR / "server.key").chmod(0o600)
        (TLS_DIR / "client.key").chmod(0o600)
    except OSError:
        pass  # Windows permissions are inherited from the current user/workspace.
    print("Generated local Sutraksh Redis test TLS certificates, ACL, and ignored .env.redis credentials.")
    print("These files are for localhost development only; they are not production credentials.")


if __name__ == "__main__":
    main()
