import binascii
import dateutil
import json
import mariadb
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from datetime import datetime, timedelta, timezone
from models.config import config


config()
conn = mariadb.connect(
    host = config.database_host,
    user = config.database_user,
    password = config.database_password,
    database = config.database_name
)


class list:
    certs = []

    def __new__(cls, sort_key=None):
        cur = conn.cursor()
        cur.execute("SELECT nkey FROM x509_certs")

        for (cert_serial,) in cur:
            cert_object = cert(cert_serial)
            cls.certs.append(cert_object)

        cur.close()

        if sort_key is not None:
            cls.certs.sort(key=lambda item: getattr(item, sort_key))

        return cls.certs



class cert:
    def __init__(self, serial):
        cert_der = self.get_cert(serial)
        cert_data = self.get_cert_data(serial)
        cert_revoked = self.get_cert_revoked(serial)
        self.load(cert_der, cert_data, cert_revoked)


    def load(self, cert_der, cert_data, cert_revoked):
        cert = x509.load_der_x509_certificate(cert_der)

        self.pem = cert.public_bytes(serialization.Encoding.PEM)
        self.serial = str(cert.serial_number)
        self.sha256 = binascii.b2a_hex(cert.fingerprint(hashes.SHA256()))
        self.sha1 = binascii.b2a_hex(cert.fingerprint(hashes.SHA1()))
        self.md5 = binascii.b2a_hex(cert.fingerprint(hashes.MD5()))
        self.pub_alg = cert.public_key_algorithm_oid._name
        self.sig_alg = cert.signature_algorithm_oid._name
        self.issuer = cert.issuer.rfc4514_string()
        self.subject = cert.subject.rfc4514_string({x509.NameOID.EMAIL_ADDRESS: "E"})
        self.not_before = cert.not_valid_before_utc.replace(microsecond=0)
        self.not_after = cert.not_valid_after_utc.replace(microsecond=0)
        san_data = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        self.san_names = san_data.value.get_values_for_type(x509.GeneralName)
        self.provisioner = cert_data.get("provisioner", None)

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
        cur.execute("SELECT nvalue FROM x509_certs WHERE nkey=?", (cert_serial,))
        if cur.rowcount > 0:
            (cert,) = cur.fetchone()
        else:
            cert = None

        cur.close()
        return cert


    def get_cert_data(self, cert_serial):
        cur = conn.cursor()
        cur.execute("SELECT nvalue FROM x509_certs_data WHERE nkey=?", (cert_serial,))
        (cert_data_raw,) = cur.fetchone()
        cur.close()
        cert_data = json.loads(cert_data_raw)
        return cert_data


    def get_cert_revoked(self, cert_serial):
        cur = conn.cursor()
        cur.execute(
            "SELECT nvalue FROM revoked_x509_certs WHERE nkey=?", (cert_serial,)
        )
        if cur.rowcount > 0:
            (cert_revoked_raw,) = cur.fetchone()
            cert_revoked = json.loads(cert_revoked_raw)
        else:
            cert_revoked = None

        cur.close()
        return cert_revoked


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
