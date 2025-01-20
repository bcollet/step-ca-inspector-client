#!/usr/bin/env python3

import argparse
import os
import sys
import yaml
from tabulate import tabulate
from models import ssh_cert, x509_cert


def list_ssh_certs(sort_key, revoked=False, expired=False):
    cert_list = ssh_cert.list(sort_key=sort_key)
    cert_tbl = []
    for cert in cert_list:
        if cert.status.value == ssh_cert.status.EXPIRED and not expired:
            continue
        if cert.status.value == ssh_cert.status.REVOKED and not revoked:
            continue

        cert_row = {}
        cert_row["Serial"] = cert.serial
        cert_row["Type"] = cert.type
        cert_row["Key ID"] = cert.key_id
        principals_count = len(cert.principals)
        principals_list = [x.decode() for x in cert.principals]
        if principals_count > 2:
            principals = principals_list[:2] + [f"+{principals_count - 2} more"]
        cert_row["Principals"] = "\n".join(principals)

        validity = []
        validity.append(f"Not before: {cert.not_before}")
        validity.append(f"Not after:  {cert.not_after}")
        if cert.revoked_at is not None:
            validity.append(f"Revoked at: {cert.revoked_at}")
            validity.append(f"Valid for: {cert.revoked_at - cert.not_before}")
        else:
            validity.append(f"Valid for: {cert.not_after - cert.not_before}")

        cert_row["Validity"] = "\n".join(validity)
        cert_row["Status"] = cert.status

        cert_tbl.append(cert_row)

    print(tabulate(cert_tbl, headers="keys", tablefmt="fancy_grid"))


def get_ssh_cert(serial):
    cert = ssh_cert.cert.from_serial(serial)
    cert_tbl = []

    cert_tbl.append(["Serial", cert.serial])
    cert_tbl.append(["Certificate type", cert.type])
    cert_tbl.append(["Certificate key type", cert.alg.decode()])
    public_key = f"{cert.public_key_type} SHA256:{cert.public_key_hash.decode()}"
    cert_tbl.append(["Public key", public_key])
    signing_key = f"{cert.signing_key_type} SHA256:{cert.signing_key_hash.decode()}"
    cert_tbl.append(["Signing key", signing_key])
    cert_tbl.append(["Key ID", cert.key_id.decode()])
    principals = [x.decode() for x in cert.principals]
    cert_tbl.append(["Principals", "\n".join(principals)])
    cert_tbl.append(["Not valid before", cert.not_before])
    cert_tbl.append(["Not valid after", cert.not_after])
    if cert.revoked_at is not None:
        cert_tbl.append(["Revoked at", cert.revoked_at])
        cert_tbl.append(["Valid for", cert.revoked_at - cert.not_before])
    else:
        cert_tbl.append(["Valid for", cert.not_after - cert.not_before])
    extensions = [x.decode() for x in cert.extensions]
    cert_tbl.append(["Extensions", "\n".join(extensions)])
    # cert_tbl.append(["Signing key", cert.signing_key.decode()])
    cert_tbl.append(["Status", cert.status])

    print(tabulate(cert_tbl, tablefmt="fancy_grid"))


def dump_ssh_cert(serial):
    cert = ssh_cert.cert.from_serial(serial)
    print(cert.public_identity.decode())


def list_x509_certs(sort_key, revoked=False, expired=False):
    cert_list = x509_cert.list(sort_key=sort_key)
    cert_tbl = []
    for cert in cert_list:
        if cert.status.value == x509_cert.status.EXPIRED and not expired:
            continue
        if cert.status.value == x509_cert.status.REVOKED and not revoked:
            continue

        cert_row = {}
        cert_row["Serial"] = cert.serial
        cert_row["Subject/Subject Alt Names (SAN)"] = "\n".join(
            [
                "%.33s" % x
                for x in [cert.subject]
                + [f"{x['type']}: {x['value']}" for x in cert.san_names]
            ]
        )
        cert_row["Provisioner"] = (
            f"{cert.provisioner['name']} ({cert.provisioner['type']})"
        )
        validity = []
        validity.append(f"Not before: {cert.not_before}")
        validity.append(f"Not after:  {cert.not_after}")
        if cert.revoked_at is not None:
            validity.append(f"Revoked at: {cert.revoked_at}")
            validity.append(f"Valid for: {cert.revoked_at - cert.not_before}")
        else:
            validity.append(f"Valid for: {cert.not_after - cert.not_before}")

        cert_row["Validity"] = "\n".join(validity)
        cert_row["Status"] = cert.status

        cert_tbl.append(cert_row)

    print(tabulate(cert_tbl, headers="keys", tablefmt="fancy_grid"))


def get_x509_cert(serial, show_cert=False, show_pubkey=False):
    cert = x509_cert.cert.from_serial(serial)
    cert_tbl = []

    cert_tbl.append(["Serial", cert.serial])
    cert_tbl.append(["Subject", cert.subject])
    cert_tbl.append(
        [
            "Subject Alt Names (SAN)",
            "\n".join([f"{x['type']}: {x['value']}" for x in cert.san_names]),
        ]
    )
    cert_tbl.append(["Issuer", cert.issuer])
    cert_tbl.append(["Not valid before", cert.not_before])
    cert_tbl.append(["Not valid after", cert.not_after])
    if cert.revoked_at is not None:
        cert_tbl.append(["Revoked at", cert.revoked_at])
        cert_tbl.append(["Valid for", cert.revoked_at - cert.not_before])
    else:
        cert_tbl.append(["Valid for", cert.not_after - cert.not_before])
    cert_tbl.append(
        ["Provisioner", f"{cert.provisioner['name']} ({cert.provisioner['type']})"]
    )
    fingerprints = []
    fingerprints.append(f"MD5:     {cert.md5.decode()}")
    fingerprints.append(f"SHA-1:   {cert.sha1.decode()}")
    fingerprints.append(f"SHA-256: {cert.sha256.decode()}")
    cert_tbl.append(["Fingerprints", "\n".join(fingerprints)])
    cert_tbl.append(["Public key algorithm", cert.pub_alg])
    cert_tbl.append(["Signature algorithm", cert.sig_alg])
    cert_tbl.append(["Status", cert.status])
    # cert_tbl.append(["Extensions", cert.extensions])
    if show_pubkey:
        cert_tbl.append(["Public key", cert.pub_key.decode("utf-8")])
    if show_cert:
        cert_tbl.append(["PEM", cert.pem.decode("utf-8")])

    print(tabulate(cert_tbl, tablefmt="fancy_grid"))


def dump_x509_cert(serial, cert_format="pem"):
    cert = x509_cert.cert.from_serial(serial)
    print(cert.pem.decode("utf-8").rstrip())


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
x509_dump_parser = x509_subparsers.add_parser("dump", help="Dump an x509 certificate")
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
            revoked=args.show_revoked, expired=args.show_expired, sort_key=args.sort_by
        )
    elif args.action == "details":
        get_x509_cert(
            serial=args.serial, show_cert=args.show_cert, show_pubkey=args.show_pubkey
        )
    elif args.action == "dump":
        dump_x509_cert(serial=args.serial)
elif args.object == "ssh":
    if args.action == "list":
        list_ssh_certs(
            revoked=args.show_revoked, expired=args.show_expired, sort_key=args.sort_by
        )
    elif args.action == "details":
        get_ssh_cert(serial=args.serial)
    elif args.action == "dump":
        dump_ssh_cert(serial=args.serial)
