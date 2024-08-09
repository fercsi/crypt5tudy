#!/usr/bin/python3

OBJECT_ID_REFERENCE = {
    # iso(1) member-body(2) us(840)
    '1.2.840.10040': 'x9-57',
    '1.2.840.10040.4': 'x9algorithm',
    '1.2.840.10040.4.1': 'dsa',
    '1.2.840.10040.4.3': 'dsa-with-sha1',
    '1.2.840.10045': 'ansi-x962',
    '1.2.840.10045.2': 'keyType',
    '1.2.840.10045.2.1': 'ecPublicKey',
    '1.2.840.10045.4': 'signatures',
    '1.2.840.10045.4.3': 'ecdsa-with-SHA2',
    '1.2.840.10045.4.3.1': 'ecdsa-with-SHA224',
    '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
    '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
    '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
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
    '1.2.840.113549.1.7': 'pkcs-7',
    '1.2.840.113549.1.7.1': 'data',
    '1.2.840.113549.1.7.3': 'envelopedData',
    '1.2.840.113549.1.7.6': 'encryptedData',
    '1.2.840.113549.1.9': 'pkcs-9',
    '1.2.840.113549.1.9.1': 'emailAddress',
    '1.2.840.113549.1.9.2': 'unstructuredName',
    '1.2.840.113549.1.12': 'pkcs-12',
    '1.2.840.113549.1.12.1': 'pkcs-12PbeIds',
    '1.2.840.113549.1.12.1.3': 'pbeWithSHAAnd3-KeyTripleDES-CBC',
    '1.2.840.113549.1.12.10': 'pkcs-12Version1',
    '1.2.840.113549.1.12.10.1': 'pkcs-12BagIds',
    '1.2.840.113549.1.12.10.1.2': 'pkcs-8ShroudedKeyBag',
    '1.2.840.113549.2': 'digestAlgorithm',

    # 1.3.6.1.4.1.11129.2.4.2
    # 1.3.6.1.4.1.44947.1.1.1

    # iso(1) org(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7)
    '1.3.6.1.5.5.7.1': 'pe',
    '1.3.6.1.5.5.7.1.1': 'authorityInfoAccess',
    '1.3.6.1.5.5.7.2': 'qt',
    '1.3.6.1.5.5.7.2.1': 'cps',
    '1.3.6.1.5.5.7.3': 'kp',
    '1.3.6.1.5.5.7.3.1': 'serverAuth',
    '1.3.6.1.5.5.7.3.2': 'clientAuth',
    '1.3.6.1.5.5.7.48': 'ad',
    '1.3.6.1.5.5.7.48.1': 'ocsp',
    '1.3.6.1.5.5.7.48.2': 'calssuers',

    # iso(1) org(3) oiw(14) secsig(3) algorithms(2)
    '1.3.14.3.2.12': 'dsa',
    '1.3.14.3.2.26': 'hashAlgorithmIdentifier',
    '1.3.14.3.2.27': 'dsaWithSHA1',

    # iso(1) org(3) thawte(101)
    '1.3.101.110': 'id-X25519',
    '1.3.101.111': 'id-X448',
    '1.3.101.112': 'id-Ed25519',
    '1.3.101.113': 'id-Ed448',
    '1.3.101.112': 'id-EdDSA25519-ph', #prehashing
    '1.3.101.113': 'id-EdDSA448',

    # joint-iso-itu-t(2) ds(5)
    '2.5.4': 'attributeType',
    # Followung attributes can be used in certificates:
    '2.5.4.3': 'commonName', # CN
    '2.5.4.4': 'surname', # SN
    '2.5.4.5': 'serialNumber',
    '2.5.4.6': 'countryName', # C
    '2.5.4.7': 'localityName', # L
    '2.5.4.8': 'stateOrProvinceName', # ST
    '2.5.4.10': 'organizationName', # O
    '2.5.4.11': 'organizationUnitName', # OU
    '2.5.4.12': 'title',
    '2.5.4.42': 'givenName',
    '2.5.4.43': 'initials',
    '2.5.4.44': 'generationQualifier',
    '2.5.4.46': 'dnQualifier', # distinguished name qualifier
    '2.5.4.65': 'pseudonym',

    '2.5.29': 'certificateExtension',
    '2.5.29.14': 'subjectKeyIdentifier',
    '2.5.29.15': 'keyUsage',
    '2.5.29.17': 'subjectAltName',
    '2.5.29.19': 'basicConstraints',
    '2.5.29.31': 'cRLDistributionPoints',
    '2.5.29.32': 'certificatePolicies',
    '2.5.29.35': 'authorityKeyIdentifier',
    '2.5.29.37': 'extKeyUsage',

    # joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4)
    '2.16.840.1.101.3.4.2': 'hashAlgs',
    '2.16.840.1.101.3.4.2.1': 'sha256',
    '2.16.840.1.101.3.4.2.2': 'sha384',
    '2.16.840.1.101.3.4.2.3': 'sha512',
    '2.16.840.1.101.3.4.2.4': 'sha224',
    '2.16.840.1.101.3.4.2.5': 'sha512-224',
    '2.16.840.1.101.3.4.2.6': 'sha512-256',
    '2.16.840.1.101.3.4.2.7': 'sha3-224',
    '2.16.840.1.101.3.4.2.8': 'sha3-256',
    '2.16.840.1.101.3.4.2.9': 'sha3-384',
    '2.16.840.1.101.3.4.2.10': 'sha3-512',
    '2.16.840.1.101.3.4.2.11': 'shake128',
    '2.16.840.1.101.3.4.2.12': 'shake256',

    # joint-iso-itu-t(2) international-organizations(23) ca-browser-forum(140) certificate-policies(1) baseline-requirements(2)
    '2.23.140.1.2.1': 'domain-validated',
    '2.23.140.1.2.2': 'subject-identity-validated',
    '2.23.140.1.2.3': 'individual-validated',
}


