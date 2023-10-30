#!/usr/bin/python3

OBJECT_ID_REFERENCE = {
    # iso(1) member-body(2) us(840
    '1.2.840.113549': 'rsadsi',
    '1.2.840.113549.1': 'pkcs',
    '1.2.840.113549.1.1': 'pkcs-1',
    '1.2.840.113549.1.1.1': 'rsaEncryption',

    # iso(1) org(3) oiw(14) secsig(3)
    '1.3.14.3.2': 'algorithms',
    '1.3.14.3.2.12': 'dsa',
    '1.3.14.3.2.27': 'dsaWithSHA1',

    # joint-iso-itu-t(2) ds(5) attributeType(4)
    '2.5.4.3': 'commonName', # CN
    '2.5.4.6': 'countryName', # C
    '2.5.4.7': 'localityName', # L
    '2.5.4.8': 'stateOrProvinceName', # S
    '2.5.4.10': 'organizationName', # O
    '2.5.4.11': 'organizationUnitName', # OU
}
