#!/usr/bin/python

from __future__ import print_function

import os
import OpenSSL
import pem
import click

def get_cn(cert_pem):
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
    return cert.get_subject().commonName

@click.command()
@click.argument('files', type=click.Path(exists=True), nargs=-1, required=True)
@click.option('--overwrite', '-o', is_flag=True)
def main(files, overwrite):
    for filename in files:
        certs = [ str(c) for c in pem.parse_file(filename) ]
        key, crt, chain = (lambda key, crt, *chain: (key, crt, list(chain)))(*certs)
        basename = get_cn(crt).replace('*', 'STAR').replace('.', '_')
        try:
            keyfile, crtfile, chainfile = (
                basename + ext
                for ext in (".key", ".crt", ".chain")
                if not os.path.exists(basename + ext) or overwrite
            )
        except ValueError:
            print("{}.* already exists, cowardly refusing to overwrite (use -o to force overwrite)".format(basename))
            continue

        open(keyfile, 'wb').write(key)
        open(crtfile, 'wb').write(crt)
        open(chainfile, 'wb').write(''.join(chain))

if __name__ == '__main__':
    main()