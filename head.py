#!/usr/bin/python3

import tls

def main():
#>    hostname = "localhost"
    hostname='portal.fercsi.com'
#>    hostname='www.google.com'
#>    hostname='telex.hu'
    try:
        client = tls.Client(
            hostname = hostname,
#>            port = 8765,
#>            timeout = 3,
#>            key_share_group = 'x448',
#>            key_share_group = 'secp256r1',
#>            key_share_group = 'secp384r1',
#>            key_share_group = 'secp521r1',
#>            key_share_group = 'ffdhe2048',
#>            debug_level = 10,
#>            warning = 'show', # skip, fatal
            )
        client.connect()
        client.send(f"HEAD / HTTP/1.1\r\nhost: {hostname}\r\nconnection: close\r\n\r\n")
#>        print(client.receive()[:300])
        print(client.receive(0))
    except Exception as e:
#>        print(e)
        raise(e)

if __name__ == "__main__":
    main()
