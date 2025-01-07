import base64
import dateutil
import json
import mariadb
from cryptography import x509
from cryptography.hazmat.primitives import asymmetric, hashes, serialization
from datetime import datetime, timedelta, timezone
from models.config import config
from struct import unpack


config()
conn = mariadb.connect(
    host=config.database_host,
    user=config.database_user,
    password=config.database_password,
    database=config.database_name,
)


class list:
    certs = []

    def __new__(cls, sort_key=None):
        cur = conn.cursor()
        cur.execute("SELECT nkey FROM ssh_certs")

        for (cert_serial,) in cur:
            cert_object = cert(cert_serial)
            cls.certs.append(cert_object)

        cur.close()

        if sort_key is not None:
            cls.certs.sort(key=lambda item: getattr(item, sort_key))

        return cls.certs


class cert:
    def __init__(self, serial):
        cert_raw = self.get_cert(serial)
        size = unpack(">I", cert_raw[:4])[0] + 4
        alg = cert_raw[4:size]

        cert_pub_id = b" ".join([alg, base64.b64encode(cert_raw)])
        cert_revoked = self.get_cert_revoked(serial)
        self.load(cert_pub_id, cert_revoked, alg)

    def load(self, cert_pub_id, cert_revoked, cert_alg):
        cert = serialization.load_ssh_public_identity(cert_pub_id)
        self.serial = cert.serial
        self.alg = cert_alg
        if cert.type == serialization.SSHCertificateType.USER:
            self.type = "User"
        self.key_id = cert.key_id
        self.principals = cert.valid_principals
        self.not_after = datetime.fromtimestamp(cert.valid_before).replace(
            tzinfo=timezone(offset=timedelta()), microsecond=0
        )
        self.not_before = datetime.fromtimestamp(cert.valid_after).replace(
            tzinfo=timezone(offset=timedelta()), microsecond=0
        )
        # TODO: Implement critical options parsing
        # cert.critical_options
        self.extensions = cert.extensions

        (self.signing_key, self.signing_key_type, self.signing_key_hash) = (
            self.get_public_key_params(cert.signature_key())
        )

        (self.public_key, self.public_key_type, self.public_key_hash) = (
            self.get_public_key_params(cert.public_key())
        )

        self.public_identity = cert.public_bytes()

        if cert_revoked is not None:
            self.revoked_at = dateutil.parser.isoparse(
                cert_revoked.get("RevokedAt")
            ).replace(microsecond=0)
        else:
            self.revoked_at = None

        now_with_tz = datetime.utcnow().replace(
            tzinfo=timezone(offset=timedelta()), microsecond=0
        )

        if self.revoked_at is not None and self.revoked_at < now_with_tz:
            self.status = status(status.REVOKED)
        elif self.not_after < now_with_tz:
            self.status = status(status.EXPIRED)
        else:
            self.status = status(status.VALID)

    def get_cert(self, cert_serial):
        cur = conn.cursor()
        cur.execute("SELECT nvalue FROM ssh_certs WHERE nkey=?", (cert_serial,))
        if cur.rowcount > 0:
            (cert,) = cur.fetchone()
        else:
            cert = None

        cur.close()
        return cert

    def get_cert_revoked(self, cert_serial):
        cur = conn.cursor()
        cur.execute("SELECT nvalue FROM revoked_ssh_certs WHERE nkey=?", (cert_serial,))
        if cur.rowcount > 0:
            (cert_revoked_raw,) = cur.fetchone()
            cert_revoked = json.loads(cert_revoked_raw)
        else:
            cert_revoked = None

        cur.close()
        return cert_revoked

    def get_public_key_params(self, public_key):
        if isinstance(public_key, asymmetric.ec.EllipticCurvePublicKey):
            key_type = "ECDSA"
        elif isinstance(public_key, asymmetric.ed25519.Ed25519PublicKey):
            key_type = "ED25519"
        elif isinstance(public_key, asymmetric.rsa.RSAPublicKey):
            key_type = "RSA"

        key_str = public_key.public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
        )

        key_data = key_str.strip().split()[1]
        digest = hashes.Hash(hashes.SHA256())
        digest.update(base64.b64decode(key_data))
        hash_sha256 = digest.finalize()
        key_hash = base64.b64encode(hash_sha256)

        return key_str, key_type, key_hash


class status:
    REVOKED = 1
    EXPIRED = 2
    VALID = 3

    def __init__(self, status):
        self.value = status

    def __str__(self):
        if self.value == self.EXPIRED:
            return "Expired"
        elif self.value == self.REVOKED:
            return "Revoked"
        elif self.value == self.VALID:
            return "Valid"
        else:
            return "Undefined"
