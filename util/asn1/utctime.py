#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

from datetime import datetime
from .object import Asn1Object

class Asn1UtcTime(Asn1Object):
    _type_id = 23
    _type_name = 'UTC TIME'

    value: datetime

    def __init__(self, value: datetime|None = None):
        super().__init__()
        if value is None:
            self.value = datetime.now()
        else:
            self.value = value

    def to_ber(self):
        text = str(self.value)
        datetxt = ''.join(text[i:i+2] for i in range(2, 18, 3))
        return datetxt + 'Z'

    def from_ber(self, raw: bytes):
        datetxt = raw.decode()
        time_values = [int(datetxt[i:i+2]) for i in range(0,len(raw) - 1,2)]
        time_values[0] += 2000 if time_values[0] < 70 else 1900
        self.value = datetime(*time_values)

    def _repr_content(self, level: int):
        return str(self.value)
