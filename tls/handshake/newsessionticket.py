#!/usr/bin/python3
# RFC8446

from util.serialize import *
from .handshake import Handshake

class NewSessionTicket(Handshake):
    def __init__(self):
        super().__init__()
        self.handshake_type = 4

    def pack_handshake_content(self):
        ticket_lifetime = pack_u32(self.ticket_lifetime)
        ticket_age_add = pack_u32(self.ticket_age_add)
        ticket_nonce = pack_bytes(self.ticket_nonce, 1)
        ticket = pack_bytes(self.ticket, 2)
        return ticket_lifetime + ticket_age_add + ticket_nonce + ticket

    def unpack_handshake_content(self, raw):
        pos = 0
        self.ticket_lifetime = unpack_u32(raw, pos)
        pos += 4
        self.ticket_age_add = unpack_u32(raw, pos)
        pos += 4
        self.ticket_nonce = unpack_bytes(raw, pos, 1)
        pos += 1 + len(self.ticket_nonce)
        self.ticket = unpack_bytes(raw, pos, 2)
        pos += 2 + len(self.ticket)
        # Note, thet the only extension which can be shared in this message is
        # early_data, which is not supported by this project
        self.unpack_extensions(raw, pos)

    def represent(self):
        m, s = divmod(self.ticket_lifetime, 60)
        h, m = divmod(m, 60)
        d, h = divmod(h, 24)
        lifetime = f'{d} days {h:0>2}:{m:0>2}:{s:0>2}'
        ext_str = ''
        for ext in self.extensions:
            ext_str += ext.represent(2)

        return "Handshake-new_session_ticket:\n" \
             + f"  TicketLifetime: {lifetime}\n" \
             + f"  TicketAgeAdd: {self.ticket_age_add:0>8x}\n" \
             + f"  TicketNonce: {self.ticket_nonce.hex()}\n" \
             + f"  Ticket: {self.ticket.hex()}\n" \
             + f"  Extensions:\n" + ext_str
