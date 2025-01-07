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
    host=config.database_host,
    user=config.database_user,
    password=config.database_password,
    database=config.database_name,
)


class list:
    certs = []

    def __new__(cls, sort_key=None):
        cur = conn.cursor()
        cur.execute(
            """SELECT x509_certs.nvalue AS cert,
                      x509_certs_data.nvalue AS data,
                      revoked_x509_certs.nvalue AS revoked
               FROM x509_certs
               INNER JOIN x509_certs_data USING(nkey)
               LEFT JOIN revoked_x509_certs USING(nkey)"""
        )

        for result in cur:
            cert_object = cert(result)
            cls.certs.append(cert_object)

        cur.close()

        if sort_key is not None:
            cls.certs.sort(key=lambda item: getattr(item, sort_key))

        return cls.certs


class cert:
    def __init__(self, cert):
        (cert_der, cert_data_raw, cert_revoked_raw) = cert

        cert_data = json.loads(cert_data_raw)
        if cert_revoked_raw is not None:
            cert_revoked = json.loads(cert_revoked_raw)
        else:
            cert_revoked = None

        self.load(cert_der, cert_data, cert_revoked)

    @classmethod
    def from_serial(cls, serial):
        return cls(cert=cls.get_cert(cls, serial))

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
        try:
            san_data = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            self.san_names = san_data.value.get_values_for_type(x509.GeneralName)
        except x509.extensions.ExtensionNotFound:
            self.san_names = []

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
        cur.execute(
            """SELECT x509_certs.nvalue AS cert,
                      x509_certs_data.nvalue AS data,
                      revoked_x509_certs.nvalue AS revoked
               FROM x509_certs
               INNER JOIN x509_certs_data USING(nkey)
               LEFT JOIN revoked_x509_certs USING(nkey)
               WHERE nkey=?""",
            (cert_serial,),
        )

        if cur.rowcount > 0:
            cert = cur.fetchone()
        else:
            cert = None

        cur.close()
        return cert


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
