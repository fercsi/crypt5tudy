#!/usr/bin/python3

# storage format / access format
# Asn.1 / Python

class AlgorithmIdentifier(Asn1Object):
    algorithm: Asn1ObjectIdentifier
    parameters: Asn1Object

    def to_pyobject(self):
        return {
        }

    # 

    def to_asn1_object(self):
        seq = Asn1Sequence()
        seq.append(to_object_identifier(self.algorithm))
        seq.append

class AlgorithmIdentifier(Asn1Sequence):

    @property
    def algorithm(self):
        return self[0]

    @algorithm.setter
    def algor

    _first_optional = 3
    _optionals = {
        'field1': None,
        'field2': 3,
    }

    @property
    def field1(self):
        if 'field1' in self._optionals:
            return self[self._optionals['field1']]
        return None

    @field1.setter
    def field1(self, newobj):

what if optional?
or multiple?

aid.algorithm.

- optional items
- context-specific types
- embedded bitstring octetstring
- sets ~lists

set py object -> Asn1Object

Asn1Choice: container of a single object
Asn1Any: container of a single object ; default: Asn1Null
Asn1SequenceOf(TYPE), Asn1SetOf(TYPE)

object id const: Asn1Object derivative, which registers the constant in constructor

## Sequence ond other properties

- generate in asn/py file
- metaclass
- class decorators

## Explicit vs implicit

object may contain so version can be
version [6] EXPLICIT Version
a6 03 02 01 02  - Context-specific, contained
version [6] IMPLICIT Version
86 01 02        - Context-specific

asn1.INTEGER(explicit=(2, 6))
asn1.INTEGER(implicit=(2, 6))


## Optional

ASN.1 objects have an 'off' state(_enabled = False), si they arent included in sequence...

asn1.INTEGER(state='off')

Reading? Object.read 'off' if invalid, pos not changed
check if type matches. Note if explicit! but it is defined by the time of reading!

default: _enabled = False
Ha value v. bármi set, akkor True

__bool__ : enabled

## Choice

Select a
x.mychoice.text.value = "fgd"
mych = x.mychoice.num
if mych:
    mynum = mych.value

asn1.Object init param
choices = {...}
@value.setter
def value():
    # set value
    if self._choices: # super() ?
        for c in self._choices:
            c._disable()
        self._enable()

or: just a setter_callback: it must be called when content/value is set

def _set_content(self):
    if self._setter_callback:
        self._setter_callback()
    self._disabled = False

## ANY

x.params

legyen setter

@parameters.setter
def parameters(self, obj):
    self._components[...] = obj

## BitString, OctetString

__getter__/__setter__

if selfs._encapsulated:
    return super().__...__(*args, **kwargs)

## SET OF

## SEQUENCE OF
