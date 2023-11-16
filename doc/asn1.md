# ASN.1 Implementation

ASN.1 has  been implemented only  partially (so far). However,  the most
important types can be used. The goal  was to be able to read and create
openssl files

| ID | Name              | P/C  |  Imp. |
| -: | :---------------- | :--- | :---: |
| 1  | Boolean           | P    |   ✅  |
| 2  | INTEGER           | P    |   ✅  |
| 3  | BIT STRING        | P, C |   ✅  |
| 4  | OCTET STRING      | P, C |   ✅  |
| 5  | NULL              | P    |   ✅  |
| 6  | OBJECT IDENTIFIER | P    |   ✅  |
| 7  | Object Descriptor | P, C |   ❌  |
| 8  | EXTERNAL          | C    |   ✅  |
| 9  | REAL              | P    |   ❌  |
| 10 | ENUMERATED        | P    |   ❌  |
| 11 | EMBEDDED PDV      | C    |   ❌  |
| 12 | UTF8String        | P, C |   ✅  |
| 13 | RELATIVE OID      | P    |   ❌  |
| 14 | TIME              | P    |   ❌  |
| 15 | -                 | -    | -     |
| 16 | SEQUENCE (OF)     | C    |   ✅  |
| 17 | SET (OF)          | C    |   ✅  |
| 18 | NumericString     | P, C |   ❌  |
| 19 | PrintableString   | P, C |   ✅  |
| 20 | T61String         | P, C |   ❌  |
| 21 | VideotexString    | P, C |   ❌  |
| 22 | IA5String         | P, C |   ✅  |
| 23 | UTCTime           | P, C |   ✅  |
| 24 | GeneralizedTime   | P, C |   ❌  |
| 25 | GraphicString     | P, C |   ❌  |
| 26 | VisibleString     | P, C |   ❌  |
| 27 | GeneralString     | P, C |   ❌  |
| 28 | UniversalString   | P, C |   ❌  |
| 29 | CHARACTER STRING  | C    |   ❌  |
| 30 | BMPString         | P, C |   ❌  |
| 31 | DATE              | P    |   ❌  |
| 32 | TIME OF DAY       | P    |   ❌  |
| 33 | DATE TIME         | P    |   ❌  |
| 34 | DURATION          | P    |   ❌  |
| 35 | OID IRI           | P    |   ❌  |
| 36 | RELATIVE OID IRI  | P    |   ❌  |

P: Primitive  
C: Constructive

Also note, that there are no constraints in this solution, including the
basic definitions. There is no check  against usage mistakes, but if you
use this  tool correctly, the results  will be correct. E.g.  it is your
responsibility to set correct strings in a `PRINTABLE STRING` object.
TODO ✅ | ❌
