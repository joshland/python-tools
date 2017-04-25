#!/usr/bin/python

import glob
import pem
import OpenSSL
import click

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


def check_associate_cert_with_private_key(cert, private_key):
    """
    :type cert: str
    :type private_key: str
    :rtype: bool
    """
    try:
        private_key_obj = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, private_key)
    except OpenSSL.crypto.Error:
        raise Exception('private key is not correct: %s' % private_key)

    try:
        cert_obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    except OpenSSL.crypto.Error:
        raise Exception('certificate is not correct: %s' % cert)

    context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
    context.use_privatekey(private_key_obj)
    context.use_certificate(cert_obj)
    try:
        context.check_privatekey()
        return True
    except OpenSSL.SSL.Error:
        return False

@click.command()
@click.argument('filename', type=click.Path(exists=True))
@click.option('--check-chain', '-c', is_flag=True)
def main(filename, check_chain):
    certs = [ str(c) for c in pem.parse_file(filename) ]
    root_certs = [str(c) for c in pem.parse_file('/etc/pki/tls/certs/ca-bundle.crt') ]
    if check_associate_cert_with_private_key(certs[1], certs[0]):
        if check_chain:
            if verify_chain_of_trust(certs[1], certs[2:] + root_certs):
                print filename, "VERIFIED"
            else:
                print filename, "FAILED: can't verify chain of trust"
        else:
            print filename, "VERIFIED"
    else:
        print filename, "FAILED: key/cert mismatch"


if __name__ == '__main__':
    main()