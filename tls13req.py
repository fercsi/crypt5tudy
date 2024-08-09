#!/usr/bin/python3

import re
import sys

from tls import Client

KEY_SHARE_GROUP = 'x25519' #x448, secp256r1, secp384r1, secp521r1
    # Note: ffdhe2048... does not work, yet
#>KEY_SHARE_GROUP = 'ffdhe2048'

def fail(errstr: str|None = None):
    if errstr is not None:
        print(errstr, file=sys.stderr)
    print(f"Usage: {sys.argv[0]} URL", file=sys.stderr)
    sys.exit(errstr is not None)

def retrieve(url: str):
    match = re.match(r'((\w+)://)?([^/:]+)(:(\d+))?(.*)', url)
    if match is None:
        fail("Invalid url")
    _, scheme, hostname, _, port, path = match.groups()
    scheme = scheme or 'https'
    port = int(port or 443)
    path = path or '/'
    if scheme != 'https':
        fail(f"Scheme '{scheme}' not supported")
    if port < 1 or port > 65535:
        fail(f"Invalid port {port}")

    client = Client(
        hostname = hostname,
        port = port,
        key_share_group = KEY_SHARE_GROUP,
    )
    try:
        client.connect()
    except Exception as exc:
        raise exc
#>        fail("Could not connect to server")
    client.send(
        f'GET {path} HTTP/1.1\r\n' +
        f'host: {hostname}\r\n' +
         'connection: close\r\n' +
         '\r\n')

    data = b'-'
    response = b''
    while data:
        data = client.receive()
        response += data
    status, response = response.split(b'\r\n', 1)
    header, body = response.split(b'\r\n\r\n', 1)
    status = int(status[9:12])
    header = header.decode()
    return status, header, body

def main():
    if len(sys.argv) == 1:
        fail("URL is missing")
    if sys.argv[1] in ('-h', '--help'):
        fail()
    url = sys.argv[1]
    status, header, body = retrieve(url)
    if status >= 200 and status < 400:
        sys.stdout.buffer.write(body)
    else:
        fail(f"HTTP error {status}")

main()
