#!/usr/bin/python3

import re
import sys
import argparse
import yaml
import datetime as dt
from pprint import pprint

from tls import Client

class Tool:
    def run(self) -> None:
        self.process_url(args.url)
        request = self.create_request()
        self.connect()
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
