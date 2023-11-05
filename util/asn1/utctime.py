#!/usr/bin/python3
# ASN.1 BER/DER, ITU-T X.690

import copy
from datetime import datetime
import importlib.util
from .object import Asn1Object

class Asn1UtcTime(Asn1Object):
    _type_id = 23
    _type_name = 'UTC TIME'

    _time: datetime

    def __init__(self, value: datetime|str|list|tuple|None = None):
        super().__init__()
        if importlib.util.find_spec('dateutil'):
            from dateutil.parser import parse
            Asn1UtcTime.parse = parse
        else:
            def parse(time):
                return datetime.strptime(time, '%Y-%m-%d %H:%M:%S')
            Asn1UtcTime.parse = parse
        if value is None:
            self._time = datetime.now()
        else:
            self.time = value # intentionally use property


    @property
    def time(self):
        return self._time

    @time.setter
    def time(self, time: datetime|str|list|tuple):
        if isinstance(time, datetime):
            self._time = copy.deepcopy(time)
        elif isinstance(time, str):
            self._time = Asn1UtcTime.parse(time)
        else:
            self._time = datetime(*time)

    def to_ber(self):
        text = str(self._time)
        datetxt = ''.join(text[i:i+2] for i in range(2, 18, 3))
        return (datetxt + 'Z').encode()

    def from_ber(self, raw: bytes):
        datetxt = raw.decode()
        time_values = [int(datetxt[i:i+2]) for i in range(0,len(raw) - 1,2)]
        time_values[0] += 2000 if time_values[0] < 70 else 1900
        self._time = datetime(*time_values)

    def _repr_content(self, level: int):
        return str(self._time)
