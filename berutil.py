#!/usr/bin/python3

import argparse
import re
import sys

from util.pemasn1 import PemAsn1Object
from util.asn1 import *
from util.pem import Pem
from util.objectidref import OBJECT_ID_REFERENCE

class Tool:
    content: Asn1Object
    pem_type: str = 'NONE'
    filename: str|None = None

    def __init__(self, args) -> None:
        self.args = args
        if args.filename:
            self.load_object(args.filename)
        else:
            self.content = Asn1Sequence()

    def load_object(self, filename: str) -> None:
        try:
            with open(filename, 'rb') as f:
                pem_content = f.read()
        except Exception as exc:
            fail(exc)
        obj = PemAsn1Object()
        try:
            obj.import_pem(pem_content.decode("ascii", errors="ignore"))
            self.pem_type = obj.pem_type
            self.content = obj.content
        except Exception as exc:
            self.content = Asn1.from_ber(pem_content)
            self.pem_type = 'UNKNOWN'

    def parse_selector(self, selector: str) -> list[int]:
        parts = selector.split('.')
        if parts[0] == 'root':
            parts.pop(0)
        return [int(p) for p in parts]

    def create_output(self) -> None:
        obj = self.content
        indices = self.parse_selector(args.query)
        for index in indices:
            obj = obj.content[index]
        text = self.format_object(obj)
        if args.out == '-':
            if isinstance(text, str):
                print(text, end='')
            else:
                sys.stdout.buffer.write(text)
        else:
            if isinstance(text, str):
                mode = 'wt'
            else:
                mode = 'wb'
            with open(args.out, mode) as f:
                f.write(text)

    def format_object(self, obj: Asn1Object) -> str|bytes:
        fmt = args.format
        if fmt is None:
            if args.out == '-':
                fmt = 't'
            elif args.pem_type is None and self.pem_type == 'NONE':
                fmt = 'b'
            else:
                fmt = 'p'
        if fmt == 't': # text
            text = str(obj) + '\n'
        elif fmt == 'r': # raw content
            text = obj.to_ber()
        elif fmt == 'i': # type info
            text = str(obj.info())
        elif fmt == 'b': # ber
            text = Asn1.to_ber(obj)
        elif fmt == 'p': # pem
            text = Pem.create(args.pem_type or self.pem_type, Asn1.to_ber(obj))
#>        elif fmt == 'j': # json - Asn1.to_object() is Support, yet
#>        elif fmt == 'y': # yaml - Asn1.to_object() is Support, yet
        else:
            fail(NotImplementedError(f"format '{fmt}' not yet implemented"))
        return text

    def unpack_all(self) -> None:
        if args.unpack is None:
            return
        for e in args.unpack:
            indices = self.parse_selector(e)
            obj = self.content
            for index in indices:
                obj = obj.content[index]
            obj.process_encapsulated()

    def delete_all(self) -> None:
        if args.delete is None:
            return
        for d in args.delete:
            indices = self.parse_selector(d)
            if not indices:
                fail('Root cannot be removed.')
            item = indices.pop()
            obj = self.content
            for index in indices:
                obj = obj.content[index]
            del obj.content[item]

    def replace_all(self) -> None:
        if args.replace is None:
            return
        for r in args.replace:
            newobj = self.create_object(r[1])
            indices = self.parse_selector(r[0])
            if not indices:
                self.content = newobj
                return
            item = indices.pop()
            obj = self.content
            for index in indices:
                obj = obj.content[index]
            obj.content[item] = newobj

    def insert_all(self) -> None:
        if args.insert is None:
            return
        for i in args.insert:
            newobj = self.create_object(i[1])
            indices = self.parse_selector(i[0])
            if not indices:
                fail('Cannot insert anything before root.')
            item = indices.pop()
            obj = self.content
            for index in indices:
                obj = obj.content[index]
            obj.content.insert(item, newobj)

    def append_all(self) -> None:
        if args.append is None:
            return
        for a in args.append:
            newobj = self.create_object(a[1])
            indices = self.parse_selector(a[0])
            obj = self.content
            for index in indices:
                obj = obj.content[index]
            obj.append(newobj)

    def encapsulate_all(self) -> None:
        if args.encapsulate is None:
            return
        for e in args.encapsulate:
            newobj = self.create_object(e[1])
            indices = self.parse_selector(e[0])
            obj = self.content
            for index in indices:
                obj = obj.content[index]
            obj.append(newobj)
            obj._encapsulated = True # XXX slight hack (this might be solved later)
            obj._constructed = False

    def create_object(self, descr: str) -> Asn1Object:
        match = re.match(r'(\w+)(?:(\(.*\)))?$', descr)
        if match is None:
            fail(f"Syntax error in object descriptor: {descr}")
        parth = ''
        if descr[-1] != ')':
            parth = '()'
        try:
            obj = eval('Tool._create_' + descr + parth)
        except AttributeError:
            fail(f"Object descriptor '{match.group(1)}' is not valid")
        except IOError as exc:
            fail(exc)
        except Exception as exc:
            if str(exc) == 'PEM format error':
                fail(f"File format error: {descr}")
            fail(f"Error processing Object descriptor: {descr}")
#>            raise exc
        return obj

    @staticmethod
    def _create_null():
        return Asn1Null()

    @staticmethod
    def _create_int(value: int = 0):
        return Asn1Integer(value)

    @staticmethod
    def _create_str(value: str = ''):
        return Asn1Utf8String(value)

    @staticmethod
    def _create_objid(value: str = ''):
        value = OBJIDS.get(value, value)
        return Asn1ObjectIdentifier(value)

    @staticmethod
    def _create_seq():
        return Asn1Sequence()

    @staticmethod
    def _create_set():
        return Asn1Set()

    @staticmethod
    def _create_bitstr():
        return Asn1BitString()

    @staticmethod
    def _create_octstr():
        return Asn1OctetString()

    @staticmethod
    def _create_attr(id: str, value: str = ''):
        seq = Asn1Sequence()
        seq.append(Tool._create_objid(id))
        seq.append(Asn1Utf8String(value))
        set = Asn1Set()
        set.append(seq)
        return set

    @staticmethod
    def _create_ber(filename: str):
        with open(filename, 'rb') as f:
            content = f.read()
        return Asn1.from_ber(content)

    @staticmethod
    def _create_pem(filename: str):
        with open(filename, 'rt', encoding='ascii', errors='ignore') as f:
            content = f.read()
        obj = PemAsn1Object()
        obj.import_pem(content)
        return obj.content


    def run(self) -> None:
        self.unpack_all()
        self.delete_all()
        self.replace_all()
        self.insert_all()
        self.append_all()
        self.encapsulate_all()
        self.create_output()

# ITU-T X.520, 6.3
OBJIDS = {
    'CN': '2.5.4.3', 'C':  '2.5.4.6', 'L':  '2.5.4.7',
    'ST': '2.5.4.8', 'O':  '2.5.4.10', 'OU': '2.5.4.11',
}
for id, name in OBJECT_ID_REFERENCE.items():
    OBJIDS[name] = id


def get_args():
    global args, parser
    parser = argparse.ArgumentParser(formatter_class=ParHelpFormatter, description="""
        This tool helps analysing, creating and modifying PEM files containing
        ASN.1 objects in BER/DER format.  
          
        The processing order is the following:  
          1. unpack  
          2. delete  
          3. replace  
          4. insert  
          5. append  
          6. encapsulate  
          7. query  
          8. generate output  
          
        The order within a category is preserved.
    """, epilog="""
        SELECTOR: root, root.1 (or 1), root.3.0.4 (or 3.0.4)  
          
        FORMAT:  
          t     Readable, textual representation  
          r     Raw content of the object  
          i     Object's type info  
          b     Object in ber format  
          p     Object in pem format  
          j     json (to be implemented)  
          y     yaml (to be implemented)  
          
        OBJECT:  
          null  ASN.1 NULL object
          int(VALUE)  
                ASN.1 INTEGER object with given value  
          str(TEXT)  
                ASN.1 UTF8 TEXT with the value given in TEXT. TEXT must be given
                in double quots, and escape sequences can be used.  
          objid(OID)  
                ASN.1 OBJECT IDENTIFIER with the given OID value (e.g. 1.2.480).  
          seq   Empty ASN.1 SEQUENCE object  
          set   Empty ASN.1 SET object  
          bitstr  
                Empty ASN.1 BITSTRING object  
          octstr  
                Empty ASN.1 BITSTRING object  
          attr(ATTRID,TEXT)  
                ASN.1 SEQUENCE of an OBJECT ID and a UTF8 STRING. ATTRID can
                be a common abbreviation (e.g. OU, CN, S...) or global OID
                (e.g. 2.5.4.46). This constructed type has been created for
                OpenSSL certificate requests
          ber(FILE)  
                ASN.1 object loaded from a BER file.  
          pem(FILE)  
                ASN.1 object loaded from a PEM file.
    """)

    parser.add_argument('filename', metavar='FILENAME', nargs='?', help="""
        File must be in PEM or BER/DER format. PEM format must also contain
        BER/DER formatted ASN.1 objects (e.g. openssl generated and pfx files).
        Note, that OpenSSH PEM files contain binary data of a different format.
        If no file is defined, an empty ASN.1 SEQUENCE object is created, so
        you can create your own PEM/BER file.
    """)
    parser.add_argument('-u', '--unpack', metavar='SELECTOR', action='append', help="""
        Resolve unpackd object specified by SELECTOR.
    """)

    manip = parser.add_argument_group('manipulation options')
    manip.add_argument('-d', '--delete', metavar='SELECTOR', action='append', help="""
        Delete a object specified by SELECTOR.
    """)
    manip.add_argument('-r', '--replace', metavar=('SELECTOR','OBJECT'), action='append', nargs=2, help="""
        Replace an object at the position defined by SELECTOR.
    """)
    manip.add_argument('-i', '--insert', metavar=('SELECTOR','OBJECT'), action='append', nargs=2, help="""
        Insert an object at the position defined by SELECTOR.
    """)
    manip.add_argument('-a', '--append', metavar=('SELECTOR','OBJECT'), action='append', nargs=2, help="""
        Append an object to the end of the selected object.
    """)
    manip.add_argument('-e', '--encapsulate', metavar=('SELECTOR','OBJECT'), action='append', nargs=2, help="""
        Encapsulate an object within the selected object.
    """)

    output = parser.add_argument_group('output options')
    output.add_argument('-q', '--query', metavar='SELECTOR', default='root', help="""
        Query the main ASN.1 object or a selected part of it. If none of the
        modufication options are defined nor this one, '--output root' is the
        default.
    """)
    output.add_argument('-f', '--format', metavar='FORMAT', choices='tribpjy', help="""
        Query response Format. The default format is the same as the input file
        (`p` or `b`) if --out is defined, otherwise `t`.
    """)
    output.add_argument('-o', '--out', metavar='FILENAME', default='-', help="""
        Output file name. If not specified output is stdout.
    """)
    output.add_argument('-p', '--pem-type', metavar='PEMTYPE', help="""
        PEM type if output format is `p`.
    """)

    args = parser.parse_args()


class ParHelpFormatter(argparse.HelpFormatter):
    def _fill_text(self, text, width, indent):
        if text[0] == '\n':
            text = text[1:]
        sindent = len(text) - len(text.lstrip(' '))
        pars = text.split('  \n') # two apaces at the end of line -> line break
        for idx, par in enumerate(pars):
            pindent = indent + ' ' * (len(par) - len(par.lstrip(' ')) - sindent)
            pars[idx] = argparse.HelpFormatter._fill_text(self, par, width, pindent)
        return '\n'.join(pars)


def fail(errstr: str):
    parser.error(errstr)


def main():
    global args
    tool = Tool(args)
    tool.run()

get_args()
main()
