# Example programs

## berutil

Ez egy egyszerű PEM/BER/DER fájl manipuláló program. Lehtőséget biztosít ilyen típusú fájlok
tartalmának megtekintésére, egyes részeinek módosításokra, részletek kiemeléséte vagy akár egy
teljesen új fájl létrehozására.
Részletekért nézd meg a help-et:

    ./berutil -h

Álljon itt néhány példa. Nézzük meg egy fájl tartalmát:

    ./berutil key.pem

Emeljük ki egy orivat key-ből ("PRIVATE KEY"), magát a kulcsot ("RSA PRIVATE KEY"):

    openssl genpkey -algorithm rsa -out key.pem
    ./berutil key.pem -q 2 -p 'RSA PRIVATE KEY' -o rsakey.pem
    openssl rsa -in rsakey.pem -text -noout

Or the other way around:

    ./berutil.py -a root int -a root seq -a 1 'objid("rsaEncryption")' -a 1 null \
        -a root octstr -e 2 'pem("rsakey.pem")' -p 'PRIVATE KEY' -o key.pem

Adjunk egy új mezőt egy certificate request-hez:

    ./berutil.py csr.pem -a 0.1 'attr("OU","My super organization unit")' -o csr2.pem

Convert pem file to der/ber (note that this is not a simple extraction, if the original content is
not a valid DER data the result will still be one):

    ./berutil.py pubkey.pem -fb -out pubkey.der
