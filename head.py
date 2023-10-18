#!/usr/bin/python3

import tls

def main():
    try:
        client = tls.Client(
#>            hostname='portal.fercsi.com',
            hostname='www.google.com',
#>            hostname='www.telex.hu',
#>            key_share_group = 'x448',
#>            key_share_group = 'secp256r1',
#>            key_share_group = 'secp384r1',
#>            key_share_group = 'secp521r1',
#>            key_share_group = 'ffdhe2048',
#>            debug_level = 10,
            )
        client.connect()
        client.send("HEAD / HTTP/1.1\r\nhost: portal.fercsi.com\r\nconnection: close\r\n\r\n")
        print(client.receive())
    except Exception as e:
#>        print(e)
        raise(e)

if __name__ == "__main__":
    main()
