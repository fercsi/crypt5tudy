# Crypt5tudy

_Cryptographic study and educational material in source code form_

I created this project to study in detail the opportunities and practicalities
of secure communication.

I  try  to achieve  this  by  implementing  each  algorithm according  to  the
specifications, and by doing so, I can  find out even the smallest details. To
make  this  actually  happen,  I  did  not  use  external  libraries  for  the
implementation,  not  even the  built-in  hashlib.  Also, even  though  Python
supports  modular  arithmetic at  a  fairly  high  level, I  implemented  some
algorithms there.

However, if  I have already done  these implementations, I will  share them so
that  others can  learn from  them. So,  consider it  as such  material. Don't
expect more from it.

The project does not aim to implement the procedures in a way that they can be
used  on a  daily  basis. There  is no  performance,  security or  reliability
warranty for any conditions.

I have also tried to collect the sources I have worked from, although some may
have been missed: [references.html](doc/references.md)

Currently implemented features:

- [TLS1.3](doc/tls13.md)
  - ECDH curve key exchange (secp\*, x25519, x448)
  - AES 128, 192, 256
  - GCM
  - SHA2 192, 256, 384, 512
  - TLS1.3 Handshake protocol
- Algorithms used in cryptography
  - Modular arithmetic (for GF with primes)
  - Polynomial arithmetic (for GF with 2^n)
  - Weierstrass curves (e.g. SECG curves)
  - Montgomery curves (E.g. 25519, 448)
  - RSA
- [ASN.1 objects](doc/asn1.md) (OpenSSL documents, pfx)
  - BER/DER format
  - PEM
- [Example programs](doc/examples.md)
  - **berutil**: Utility to analyse, change or create BER/DER or PEM files
  - **genkey**: Generate OpenSSL compatible private key
  - **tls13req**: A TLS1.3 client sending HTTP requests and receiving response

## Limitations, Warranty ⚠️

### Licensing

This   project   is   licensed   under  the   terms   of   **CC-BY-NC**   (see
[LICENSE.txt](LICENSE.txt)).

In addition to the above:

- **Building applications on the code found here**: Just don't do it. Read the
  code, understand it, and implement a proper one.
- **Education**: I would appreciate it if you  would email me if you use it in
  any way so that I know about it:
  [ferenc.vajda@gmail.com](mailto:ferenc.vajda@gmail.com)
- **Media (including videos, books etc.)**:  On one hand consider the licence,
  on the  other hand please email  me if you want  to use the content  of this
  repository in this way. I would appreciate it.
  [ferenc.vajda@gmail.com](mailto:ferenc.vajda@gmail.com)

### Performance and optimization

The code snippets are intentionally not  optimized. Their purpose is not to be
efficient, but to  help you/me understand the principles. In  some cases, they
can even be downright slow.

For the  same reason, the  algorithms are  written specifically in  Python. In
many areas of security, it is not  practical to use this language. However, it
is a clear and readable programming language.

### Backwards compatibility

Since the goal is  not for anyone to build a consumer  product on this system,
but to  make the  algorithms understandable,  from time to  time there  may be
changes  that make  the current  version incompatible  with earlier  ones. The
purpose of these changes is always increase clarity.

Accordingly, I do not provide the study with any versioning.

### Security, vulnerability

Although the point of the topic is  security, there is no guarantee that there
are no vulnerabilities in the solutions. This  is due to the fact that I don't
always follow the specifications perfectly: e.g. a secret must be removed from
memory  immediately  (try  this  in  python), or  many  procedures  (e.g.  key
generation) have recommendations that I  haven't implemented, and I even don't
plan  to,  etc.  On  the  other  hand,  I  don't  want  to  think  about  what
vulnerabilities might still be in the system,  because nobody will use it in a
live environment (right?).

### No PyPI module

Although some parts  are suitable for PyPI,  most of the code  is not suitable
for everyday use. For this reason, I do not plan to make it into a PyPI module
for the time being.

## Planned activities

### Educational material

I am  also planning to  put together educational  material based on  the codes
here (diagrams  - possibly  interactive, slides, etc.),  but no  concrete plan
yet, when and how I will implement them.

### Additional algorithms

- Digital signature implementations, primarily those used in TLS
  CertificateVerify
- Further hash algorithms (E.g. SHA3)
- CHACHA20/POLY-1305 AEAD (traffic encryption)
- TLS1.3 server solution implementation (DigSig investigation needed)
- More TLS features (handshake  messages, extensions, maybe 0-RTT). Note, that
  no TLS1.2 or earlier implementations are currently planned,
- OpenSSH Key PEM format: encryped + create
- New ASN.1 features: Generalizedatime (for certs), further stringa...
- SSH, SCP (maybe SFTP)

### Code improvements

The code needs refactoring at several points

- Improved exception handling
- More unit tests
- Code documentation (annotation, funtion/class documentation)
- Further documentation, references

Some system-level features would also be useful:

- Multilevel verbosity solution to be able to follow the process while running
- TLS handshake warning handling (ignore, fatal, show)
