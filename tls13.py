#!/usr/bin/python3

import hashlib
import re
import sys
import argparse
import yaml
import datetime as dt
from pprint import pprint
from tls.handshake.certificate import CertificateEntry

from tls import Client
from util.asn1 import *
from util.pem import Pem
from crypto.rsa import *

class Tool:
    def run(self) -> None:
        self.process_url(args.url)
        request = self.create_request()
        self.connect()
        if args.verify_certificates:
            self.verify_certificates()
        if args.show_certificates:
            for i,cert in enumerate(self.client.certificates, 1):
                info = cert.get_cert_info()
                print(yaml.dump({f'Entry_{i}':simplify(info)}, sort_keys=False, indent=2))
        if request:
            status_code, status_text, head, body = self.send_request(request)
            if args.http_status:
                print(status_text)
            if args.http_head:
                print(head)
            if args.http_get:
                if args.http_head:
                    print('')
                sys.stdout.buffer.write(body)

    def process_url(self, url) -> None:
        match = re.match(r'((\w+)://)?([-a-z0-9.]+)(:(\d+))?(.*)', url)
        if match is None:
            fail("Invalid url or hostname")
        _, scheme, hostname, _, port, path = match.groups()
        scheme = scheme or 'https'
        port = int(port or 443)
        path = path or '/'
        if path[0] != '/':
            fail("Invalid url or hostname")
        if args.http_get or args.http_head:
            if scheme != 'https':
                fail(f"Scheme '{scheme}' not supported")
        if port < 1 or port > 65535:
            fail(f"Invalid port {port}")
        self.scheme = scheme
        self.hostname = hostname
        self.port = port
        self.path = path

    def create_request(self) -> str|None:
        if args.http_get:
            request = 'GET'
        elif args.http_head or args.http_status:
            request = 'HEAD'
        else:
            return None
        return f'{request} {self.path} HTTP/1.1\r\n' + \
               f'host: {self.hostname}\r\n' + \
                'connection: close\r\n' + \
                '\r\n'

    def connect(self) -> None:
        self.client = Client(
            hostname = self.hostname,
            port = self.port,
#>            key_share_group = KEY_SHARE_GROUP,
        )
        try:
            self.client.connect()
        except Exception as exc:
            if args.debug:
                raise exc
            else:
                fail("Could not connect to server")

    def send_request(self, request: str|None) -> tuple[int, str, str, bytes]:
        self.client.send(request)
        data = b'-'
        response = b''
        while data:
            data = self.client.receive()
            response += data
        status, response = response.split(b'\r\n', 1)
        header, body = response.split(b'\r\n\r\n', 1)
        status_code = int(status[9:12])
        status_text = status.decode()
        header = header.decode()
        return status_code, status_text, header, body

    def verify_certificates(self):
        # TODO: This should get into Certificate handshake, but that must be
        # refactored anyway
        # TODO: Only SHA256+RSA signed certs are supported
        cert_info = self.extract_cert_info()
        print('Loading root certificate')
        iss = cert_info[-1]['issuer']
        root = iss[iss.rindex('/') + 1:]
        rootfile = f'{args.cert_dir}/{root.replace(" ","_")}.pem'
        try:
            with open(rootfile, 'r') as f:
                rootpem = f.read()
            rootber = Pem.parse(rootpem)[1]
            rootcert = self.extract_single(rootber)
            cert_info.append(rootcert)
            print('    OK')
        except OSError as exc:
            print('    Could not load root certificate')
            print(exc)
        subci = cert_info[0]
        print('Checking validity')
        ok = True
        for i, ci in enumerate(cert_info):
            now = dt.datetime.now()
            if now < ci['notBefore'] or now > ci['notAfter']:
                ok = False
                if ci is cert_info[-1]:
                    print(f'    Local root certificate "{ci["subject"]}" is invalid')
                    print(f'        file:  {rootfile}')
                else:
                    print(f'    Certificate "{ci["subject"]}" is invalid')
                print(f'        start: {ci["notBefore"].isoformat(timespec="seconds")}')
                print(f'        end:   {ci["notAfter"].isoformat(timespec="seconds")}')
        if ok:
            print('    OK')
        print('Checking certificate chain & signatures')
        # TODO: check order
        ok = True
        for issci in cert_info[1:]:
            if issci['subject'] != subci['issuer']:
                ok = False
                print('    Invalid certificate chain')
            calchash = self.digest(subci['tbsc'], 'sha256')
            d = self.decrypt_signature(subci['signature'], issci['key'])
            decrhash = self.decode(d)
            if calchash != decrhash:
                ok = False
                print('    Signature error')
            subci = issci
        if ok:
            print('    OK')
        print('Verifying server information')
        if self.hostname in cert_info[0]['subjects']:
            print('    OK')
        else:
            print('    Certificate subject does not match hostname')
        print('Verifying TLS certificate signature')
        print('    Not implemented')
#>        raw = self.client.certificate.raw_content
#>        algorithm = self.client.certificateVerify.algorithm
#>        signature = self.client.certificateVerify.signature
#>        print(len(signature), signature.hex())
#>        d = self.decrypt_signature(signature, cert_info[0]['key'])
#>        print(len(d), d.hex())
#>        print(d)

    def extract_cert_info(self):
        certs = []
        for ce in self.client.certificates:
            cert = self.extract_single(ce)
            certs.append(cert)
        return certs

    def extract_single(self, ce):
        if isinstance(ce, bytes):
            entry = CertificateEntry(0)
            entry.unpack(ce)
            ce = entry
        info = ce.get_cert_info()
        exts = info['extensions']
        alt_subjects = {info['subject']['commonName']}
        for ext in exts:
            if ext['name'] == 'subjectAltName':
                for sub in ext['value']:
                    alt_subjects.add(sub['value'])
        c = Asn1.from_ber(ce.cert_data)
        c.process_encapsulated(selector=[0,6,1])
        t = c[0]
        key = t[6][1][0]
        cert = {
            'key': {
                'size': key[0].value.bit_length(),
                'n': key[0].value,
                'e': key[1].value,
            },
            'tbsc': t._ber,
            'issuer': self.extractInfo(t[3]),
            'subject': self.extractInfo(t[5]),
            'notBefore': t[4][0].value,
            'notAfter': t[4][1].value,
            'algorithm': c[1],
            'signature': c[2]._raw[1:], # BIT STRING
            'subjects': alt_subjects,
        }
        return cert

    def extractInfo(self, obj):
        info = {}
        for s in obj:
            info[s[0][0].oid_name] = s[0][1].value
        text = info.get('countryName', '-') + '/' + \
            info.get('organizationName', '-') + '/' + \
            info.get('commonName', '-');
        return text

    def digest(self, m, alg):
        return hashlib.sha256(m).digest()

    def decrypt_signature(self, ed, pubkey):
        rsa = Rsa()
        d = rsa._decrypt(RsaKey(pubkey['size'], pubkey['n'], pubkey['e']), ed)
        return d

    def decode(self, d):
        obj = Asn1.from_ber(d)
        return obj[1].data

def simplify(obj):
    if isinstance(obj, (int, bool, str, type(None))):
        return obj
    if isinstance(obj, list):
        return [simplify(item) for item in obj]
    if isinstance(obj, dict):
        return {key: simplify(value) for key, value in obj.items()}
    if isinstance(obj, dt.datetime):
        return obj.isoformat()
    return str(obj)

def get_args():
    global args, parser
    parser = argparse.ArgumentParser(description="""
        This tool helps to get certain information from a TLSv1.3 server.
    """)

    parser.add_argument('url', metavar='HOSTNAME/URL')

    parser.add_argument('-c', '--show-certificates', action='store_true', help = """
        Display server certificate information
    """)
    parser.add_argument('-v', '--verify-certificates', action='store_true', help = """
        Verify server certificates and certification signsture. Verifies
        validity, signatures, certification order and server information.
        Signature chain is also shown.
    """)
    parser.add_argument('-p', '--show-parameters', action='store_true', help = """
        Display TLS connection parametrs
    """)
    parser.add_argument('-G', '--http-get', action='store_true', help = """
        Send HTTP GET request and display the result
    """)
    parser.add_argument('-H', '--http-head', action='store_true', help = """
        Send HTTP HEAD request and display the result. If used with `-G`, GET
        request will br sent, but head will be shown, too.
    """)
    parser.add_argument('-S', '--http-status', action='store_true', help = """
        Display HTTP status line. If no further HTTP option is set, HEAD request
        will be sent.
    """)

    parser.add_argument('-g', '--keyshare-group', metavar='GROUP', default='x25519',
        choices=['x25519', 'x448', 'secp256r1', 'secp384r1', 'secp521r1'],
        help = """
        KeyShare group used in TLS communication.
        Values of GROUP: %(choices)s
        (Default: %(default)s).
    """)
#>    parser.add_argument('-v', '--verbose', action='store_true')  # on/off flag

    parser.add_argument('--cert-dir', metavar='DIR', default='/usr/lib/ssl/certs', help="""
        Directory containing certificate pem files. (Default: "%(default)s")
    """)
    # alternative '/etc/ssl/certs'. '/usr/lib/ssl/certs' is a link to it, but 
    # this contains also links to certs

    parser.add_argument('--debug', action='store_true', help=argparse.SUPPRESS)

#>    parser.add_argument('integers', metavar='N', type=int, nargs='+',
#>                        help='an integer for the accumulator')
#>    parser.add_argument('--sum', dest='accumulate', action='store_const',
#>                        const=sum, default=max,
#>                        help='sum the integers (default: find the max)')
    # dest: args name
    # action: store, store_const, store_true, store_false, append, append_const
    # nargs: N, ?, *, +
    # const (action=*_const / nargs=?)
    # default
    # type: int, float, ascii, ord, open, pathlib.Path
    # choices: [...], range(...)
    # required True/False
    # help: Help text (%(prog)s, %(default)s, %(type)s)
    # metavar (name for help)

    args = parser.parse_args()


def verbose(*args, **kwargs):
    if args.verbose:
        print(*args, **kwargs)

def fail(errstr: str):
    parser.error(errstr)


def main():
    tool = Tool()
    tool.run()

get_args()
main()
