#!/usr/bin/python3

OBJECT_ID_REFERENCE = {
    # iso(1) member-body(2) us(840)
    '1.2.840.113549': 'rsadsi',
    '1.2.840.113549.1': 'pkcs',
    '1.2.840.113549.1.1': 'pkcs-1',
    '1.2.840.113549.1.1.1': 'rsaEncryption',
    '1.2.840.113549.1.1.4': 'md5WithRSAEncryption',
    '1.2.840.113549.1.1.5': 'sha1-with-rsa-signature',
    '1.2.840.113549.1.1.10': 'rsassa-pss',
    '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
    '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
    '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
    '1.2.840.113549.1.1.14': 'sha224WithRSAEncryption',

    # iso(1) org(3) oiw(14) secsig(3) algorithms(2)
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
