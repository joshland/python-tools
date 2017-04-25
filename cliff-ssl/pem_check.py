#!/usr/bin/python
# Copyright 2017, Clifford (Damn) Wells <cliff.wells@gmail.com>
# This code is released under the Modified BSD License.
# See LICENSE for details.

from __future__ import print_function

import sys
from datetime import datetime
import certifi
import pem
import OpenSSL
from acme import crypto_util as acme_crypto_util
import click
from blessings import Terminal

term = Terminal()

def error_msg(*msg):
    msg = ' '.join(msg)
    print('{t.red}FAILED: {msg}{t.normal}'.format(t=term, msg=msg), file=sys.stderr)

def verified_msg(*msg):
    msg = ' '.join(msg)
    print('{t.green}VERIFIED: {msg}{t.normal}'.format(t=term, msg=msg))


def certificate_expired(cert_pem):
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
    return datetime.strptime(cert.get_notAfter().decode('utf-8'), "%Y%m%d%H%M%SZ") <= datetime.utcnow()


def verify_chain_of_trust(cert_pem, trusted_cert_pems):
    certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)

    # Create and fill a X509Sore with trusted certs
    store = OpenSSL.crypto.X509Store()
    for trusted_cert_pem in trusted_cert_pems:
        trusted_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, trusted_cert_pem)
        try:
            store.add_cert(trusted_cert)
        except OpenSSL.crypto.Error:
            pass # cert already in store

    # Create a X590StoreContext with the cert and trusted certs and verify the the chain of trust
    # Returns None if certificate can be validated
    store_ctx = OpenSSL.crypto.X509StoreContext(store, certificate)

    try:
        result = store_ctx.verify_certificate()
    except:
        return False

    return result is None


def private_key_matches_certificate(private_key_pem, cert_pem):
    try:
        private_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, private_key_pem)
    except OpenSSL.crypto.Error:
        return False

    try:
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
    except OpenSSL.crypto.Error:
        return False

    context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
    context.use_privatekey(private_key)
    context.use_certificate(cert)
    try:
        context.check_privatekey()
        return True
    except OpenSSL.SSL.Error:
        return False


def get_subject(cert_pem):
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
    return cert.get_subject()


def get_san(cert_pem):
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
    return ', '.join(acme_crypto_util._pyopenssl_cert_or_req_san(cert))


@click.command()
@click.argument('files', type=click.Path(exists=True), nargs=-1, required=True)
@click.option('--check-chain', '-c', is_flag=True)
@click.option('--root-certs',  '-r', type=click.Path(exists=True), default=certifi.where())
@click.option('--details',     '-d', is_flag=True)
@click.option('--quiet',       '-q', is_flag=True)
def main(files, check_chain, root_certs, details, quiet):
    ''' Expects PEM files formatted as

    Private key -> Certificate -> Certificate chain

    Checks each file in turn for private key/cert mismatches, expired certs, and valid chain of trust.
    '''
    root_certs = [ str(c) for c in pem.parse_file(root_certs) ]

    for filename in files:
        certs = [ str(c) for c in pem.parse_file(filename) ]
        key, crt, chain = (lambda key, crt, *chain: (key, crt, list(chain)))(*certs)

        if details:
            msg_details = "{} (CN: {} SAN: {})".format(filename, get_subject(crt).commonName, get_san(crt))
        else:
            msg_details = filename

        if not private_key_matches_certificate(key, crt):
            error_msg("key/cert mismatch", msg_details)
            continue

        if certificate_expired(crt):
            error_msg("certificate expired", msg_details)
            continue

        if check_chain and not verify_chain_of_trust(crt, root_certs + chain):
            error_msg("can't verify chain of trust", msg_details)
            continue

        if not quiet:
            verified_msg(msg_details)


if __name__ == '__main__':
    main()
