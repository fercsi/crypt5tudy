# ASN.1 Implementation

The **ASN.1** standard (_ITU-T X.680-693_) is a complex communication solution
used in  many applications. It is  basically a well-defined object  system for
which the  standard provides among  other features a number  of representation
forms. One  of the  most common  ones is  the binary  **BER** format  (and its
**DER** variant,  with more strict  rules), which  s been implemented  in this
study at a certain level. It is important to note that tool accepts BER inputs
when  read  (permissive), but  the  output  is  more  strict and  follows  DER
specification.

Since BER/DER is a  binary format, it is common to store  it in **PEM** format
based on  base64 encoding,  which is  also part of  the implementation.  It is
worth noting here that not only ASN.1 BER objects can be stored in PEM format,
but also other binary content. One  example is OpenSSH's own (proprietary) key
format. This cannot currently be read and written by this tool.

## Limitations

ASN.1 has  been implemented only  partially (so  far, at least).  However, the
most important types can be used. The  goal was to be able to read, manipulate
and create OpenSSL compatible files.

Following table shows which objects has been implemented so far:

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
C: Constructed

Also  note, that  there are  no constraints  in this  solution, including  the
object types' basic definition. There is  no check against usage mistakes, but
if you  use this  tool properly,  the results will  be correct,  DER formatted
objects.  E.g.  it  is  your  responsibility  to  set  correct  strings  in  a
`PrintableString` object.
