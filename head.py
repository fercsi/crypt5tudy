#!/usr/bin/python3

import tls

def main():
    client = tls.Client(
        hostname='portal.fercsi.com',
        key_share_group = 'x448',
#>        key_share_group = 'secp256r1',
        )
    client.connect()
    client.send("HEAD / HTTP/1.1\r\nhost: portal.fercsi.com\r\nconnection: close\r\n\r\n")
    print(client.receive())

if __name__ == "__main__":
    main()
