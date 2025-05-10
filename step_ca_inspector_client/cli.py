#!/usr/bin/env python3

import argparse
import requests
from urllib.parse import urljoin
from datetime import datetime, timedelta, timezone
from tabulate import tabulate
from step_ca_inspector_client.config import config

config()

SSH_CERT_TYPES = ["Host", "User"]


def delta_text(delta):
    s = "s"[: abs(delta.days) ^ 1]

    if delta < timedelta(days=-1):
        return f"in {abs(delta.days)} day{s}"
    elif delta < timedelta(days=0):
        return "in less than a day"
    elif delta < timedelta(days=1):
        return "less than a day ago"
    else:
        return f"{delta.days} day{s} ago"


def fetch_api(endpoint, params={}):
    try:
        results = requests.get(urljoin(config.url, endpoint), params=params)
        results.raise_for_status()
    except requests.HTTPError as e:
        raise e
    except requests.Timeout as e:
        raise e
        # request took too long

    return results.json()


def list_ssh_certs(
    sort_key,
    revoked=False,
    expired=False,
    cert_type=SSH_CERT_TYPES,
    key=None,
    principal=None,
):
    params = {
        "sort_key": sort_key,
        "revoked": revoked,
        "expired": expired,
        "cert_type": cert_type,
        "key": key,
        "principal": principal,
    }
    cert_list = fetch_api("ssh/certs", params=params)

    cert_tbl = []
    for cert in cert_list:
        cert_row = {}
        cert_row["Serial"] = cert["serial"]
        cert_row["Type"] = cert["type"]
        cert_row["Key ID"] = cert["key_id"]
        principals_count = len(cert["principals"])
        if principals_count > 2:
            principals = cert["principals"][:2] + [f"+{principals_count - 2} more"]
        else:
            principals = cert["principals"]
        cert_row["Principals"] = "\n".join(principals)

        now_with_tz = datetime.now(timezone.utc).replace(microsecond=0)

        if cert["revoked_at"] is not None:
            delta = now_with_tz - datetime.fromtimestamp(
                cert["revoked_at"], tz=timezone.utc
            )
        else:
            delta = now_with_tz - datetime.fromtimestamp(
                cert["not_after"], tz=timezone.utc
            )

        cert_row["Expires"] = delta_text(delta).capitalize()
        cert_row["Status"] = cert["status"]

        cert_tbl.append(cert_row)

    print(tabulate(cert_tbl, headers="keys", tablefmt="fancy_grid"))


def get_ssh_cert(serial):
    cert = fetch_api(f"ssh/certs/{serial}")
    if cert is None:
        return

    cert_tbl = []
    cert_tbl.append(["Serial", cert["serial"]])
    cert_tbl.append(["Certificate type", cert["type"]])
    cert_tbl.append(["Certificate key type", cert["alg"]])
    public_key = f"{cert['public_key_type']} SHA256:{cert['public_key_hash']}"
    cert_tbl.append(["Public key", public_key])
    signing_key = f"{cert['signing_key_type']} SHA256:{cert['signing_key_hash']}"
    cert_tbl.append(["Signing key", signing_key])
    cert_tbl.append(["Key ID", cert["key_id"]])
    cert_tbl.append(["Principals", "\n".join(cert["principals"])])

    now_with_tz = datetime.now(timezone.utc).replace(microsecond=0)

    delta_after = now_with_tz - datetime.fromtimestamp(
        cert["not_after"], tz=timezone.utc
    )
    delta_before = now_with_tz - datetime.fromtimestamp(
        cert["not_before"], tz=timezone.utc
    )

    cert_tbl.append(
        [
            "Not valid before",
            f"{datetime.fromtimestamp(cert['not_before']).astimezone()} ({delta_text(delta_before)})",
        ]
    )
    cert_tbl.append(
        [
            "Not valid after",
            f"{datetime.fromtimestamp(cert['not_after']).astimezone()} ({delta_text(delta_after)})",
        ]
    )

    if cert["revoked_at"] is not None:
        delta_revoked = now_with_tz - datetime.fromtimestamp(
            cert["revoked_at"], tz=timezone.utc
        )
        cert_tbl.append(
            [
                "Revoked at",
                f"{datetime.fromtimestamp(cert['revoked_at']).astimezone()} ({delta_text(delta_revoked)})",
            ]
        )

    cert_tbl.append(["Extensions", "\n".join(cert["extensions"])])
    # cert_tbl.append(["Signing key", cert["signing_key"]])
    cert_tbl.append(["Status", cert["status"]])

    print(tabulate(cert_tbl, tablefmt="fancy_grid"))


def dump_ssh_cert(serial):
    cert = fetch_api(f"ssh/certs/{serial}")
    if cert is None:
        return

    print(cert["public_identity"])


def list_x509_certs(sort_key, revoked=False, expired=False):
    params = {
        "sort_key": sort_key,
        "revoked": revoked,
        "expired": expired,
    }
    cert_list = fetch_api(f"x509/certs", params=params)
    cert_tbl = []
    for cert in cert_list:
        cert_row = {}
        cert_row["Serial"] = cert["serial"]
        cert_row["Subject/Subject Alt Names (SAN)"] = "\n".join(
            [
                "%.33s" % x
                for x in [cert["subject"]]
                + [f"{x['type']}: {x['value']}" for x in cert["san_names"]]
            ]
        )
        cert_row["Provisioner"] = (
            f"{cert['provisioner']['name']} ({cert['provisioner']['type']})"
        )

        now_with_tz = datetime.now(timezone.utc).replace(microsecond=0)

        if cert["revoked_at"] is not None:
            delta = now_with_tz - datetime.fromtimestamp(
                cert["revoked_at"], tz=timezone.utc
            )
        else:
            delta = now_with_tz - datetime.fromtimestamp(
                cert["not_after"], tz=timezone.utc
            )

        cert_row["Expires"] = delta_text(delta).capitalize()
        cert_row["Status"] = cert["status"]

        cert_tbl.append(cert_row)

    print(tabulate(cert_tbl, headers="keys", tablefmt="fancy_grid"))


def get_x509_cert(serial, show_cert=False, show_pubkey=False):
    cert = fetch_api(f"x509/certs/{serial}")

    if cert is None:
        return

    cert_tbl = []
    cert_tbl.append(["Serial", cert["serial"]])
    cert_tbl.append(["Subject", cert["subject"]])
    cert_tbl.append(
        [
            "Subject Alt Names (SAN)",
            "\n".join([f"{x['type']}: {x['value']}" for x in cert["san_names"]]),
        ]
    )
    cert_tbl.append(["Issuer", cert["issuer"]])

    now_with_tz = datetime.now(timezone.utc).replace(microsecond=0)

    delta_after = now_with_tz - datetime.fromtimestamp(
        cert["not_after"], tz=timezone.utc
    )
    delta_before = now_with_tz - datetime.fromtimestamp(
        cert["not_before"], tz=timezone.utc
    )

    cert_tbl.append(
        [
            "Not valid before",
            f"{datetime.fromtimestamp(cert['not_before']).astimezone()} ({delta_text(delta_before)})",
        ]
    )
    cert_tbl.append(
        [
            "Not valid after",
            f"{datetime.fromtimestamp(cert['not_after']).astimezone()} ({delta_text(delta_after)})",
        ]
    )
    if cert["revoked_at"] is not None:
        delta_revoked = now_with_tz - datetime.fromtimestamp(
            cert["revoked_at"], tz=timezone.utc
        )
        cert_tbl.append(
            [
                "Revoked at",
                f"{datetime.fromtimestamp(cert['revoked_at']).astimezone()} ({delta_text(delta_revoked)})",
            ]
        )
        cert_tbl.append(["Valid for", f"{delta_revoked.days} days"])
    else:
        cert_tbl.append(["Valid for", f"{abs(delta_after.days)} days"])

    cert_tbl.append(
        [
            "Provisioner",
            f"{cert['provisioner']['name']} ({cert['provisioner']['type']})",
        ]
    )
    fingerprints = []
    fingerprints.append(f"MD5:     {cert['md5']}")
    fingerprints.append(f"SHA-1:   {cert['sha1']}")
    fingerprints.append(f"SHA-256: {cert['sha256']}")
    cert_tbl.append(["Fingerprints", "\n".join(fingerprints)])
    cert_tbl.append(["Public key algorithm", cert["pub_alg"]])
    cert_tbl.append(["Signature algorithm", cert["sig_alg"]])
    cert_tbl.append(["Status", cert["status"]])

    if show_pubkey:
        cert_tbl.append(["Public key", cert["pub_key"]])
    if show_cert:
        cert_tbl.append(["PEM", cert["pem"]])

    print(tabulate(cert_tbl, tablefmt="fancy_grid"))


def dump_x509_cert(serial, cert_format="pem"):
    cert = fetch_api(f"x509/certs/{serial}")

    if cert is None:
        return

    print(cert["pem"].rstrip())


def main():
    parser = argparse.ArgumentParser(description="Step CA Inspector")
    subparsers = parser.add_subparsers(
        help="Object to inspect", dest="object", required=True
    )
    x509_parser = subparsers.add_parser("x509", help="x509 certificates")
    x509_subparsers = x509_parser.add_subparsers(
        help="Action for perform", dest="action", required=True
    )
    x509_list_parser = x509_subparsers.add_parser("list", help="List x509 certificates")
    x509_list_parser.add_argument(
        "--show-expired",
        "-e",
        action="store_true",
        default=False,
        help="Show expired certificates",
    )
    x509_list_parser.add_argument(
        "--show-revoked",
        "-r",
        action="store_true",
        default=False,
        help="Show revoked certificates",
    )
    x509_list_parser.add_argument(
        "--sort-by",
        "-s",
        type=str,
        choices=["not_after", "not_before"],
        default="not_after",
        help="Sort certificates",
    )
    x509_details_parser = x509_subparsers.add_parser(
        "details", help="Show an x509 certificate details"
    )
    x509_details_parser.add_argument(
        "--serial", "-s", type=str, required=True, help="Certificate serial"
    )
    x509_details_parser.add_argument(
        "--show-cert",
        "-c",
        action="store_true",
        default=False,
        help="Show certificate (PEM)",
    )
    x509_details_parser.add_argument(
        "--show-pubkey",
        "-p",
        action="store_true",
        default=False,
        help="Show public key (PEM)",
    )
    x509_dump_parser = x509_subparsers.add_parser(
        "dump", help="Dump an x509 certificate"
    )
    x509_dump_parser.add_argument(
        "--serial", "-s", type=str, required=True, help="Certificate serial"
    )
    x509_dump_parser.add_argument(
        "--format",
        "-f",
        type=str,
        choices=["pem"],
        required=False,
        help="Certificate format",
    )
    ssh_parser = subparsers.add_parser("ssh", help="ssh certificates")
    ssh_subparsers = ssh_parser.add_subparsers(
        help="Action for perform", dest="action", required=True
    )
    ssh_list_parser = ssh_subparsers.add_parser("list", help="List ssh certificates")
    ssh_list_parser.add_argument(
        "--show-expired",
        "-e",
        action="store_true",
        default=False,
        help="Show expired certificates",
    )
    ssh_list_parser.add_argument(
        "--show-revoked",
        "-r",
        action="store_true",
        default=False,
        help="Show revoked certificates",
    )
    ssh_list_parser.add_argument(
        "--sort-by",
        "-s",
        type=str,
        choices=["not_after", "not_before"],
        default="not_after",
        help="Sort certificates (default: not_after)",
    )
    ssh_list_parser.add_argument(
        "--type",
        "-t",
        type=str,
        choices=SSH_CERT_TYPES,
        default=SSH_CERT_TYPES,
        nargs="+",
        help="Filter by SSH certificate type",
    )
    ssh_list_parser.add_argument(
        "--key",
        "-k",
        type=str,
        default=None,
        help="Search for key ID",
    )
    ssh_list_parser.add_argument(
        "--principal",
        "-p",
        type=str,
        default=None,
        help="Search for principal",
    )
    ssh_details_parser = ssh_subparsers.add_parser(
        "details", help="Show an ssh certificate details"
    )
    ssh_details_parser.add_argument(
        "--serial", "-s", type=str, required=True, help="Certificate serial"
    )
    ssh_dump_parser = ssh_subparsers.add_parser("dump", help="Dump an ssh certificate")
    ssh_dump_parser.add_argument(
        "--serial", "-s", type=str, required=True, help="Certificate serial"
    )
    args = parser.parse_args()

    if args.object == "x509":
        if args.action == "list":
            list_x509_certs(
                revoked=args.show_revoked,
                expired=args.show_expired,
                sort_key=args.sort_by,
            )
        elif args.action == "details":
            get_x509_cert(
                serial=args.serial,
                show_cert=args.show_cert,
                show_pubkey=args.show_pubkey,
            )
        elif args.action == "dump":
            dump_x509_cert(serial=args.serial)
    elif args.object == "ssh":
        if args.action == "list":
            list_ssh_certs(
                revoked=args.show_revoked,
                expired=args.show_expired,
                sort_key=args.sort_by,
                cert_type=args.type,
                key=args.key,
                principal=args.principal,
            )
        elif args.action == "details":
            get_ssh_cert(serial=args.serial)
        elif args.action == "dump":
            dump_ssh_cert(serial=args.serial)


if __name__ == "__main__":
    main()
