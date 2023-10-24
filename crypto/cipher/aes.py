#!/usr/bin/python3
# NIST FIPS 197

from .blockcipher import BlockCipher
from .registry import Registry
from ..polynomial import Polynomial

State = list[list[int]]
Word = tuple[int, int, int, int]

class aes(BlockCipher):
    def set_key(self, key: bytes) -> None:
        super().set_key(key)
        self._Nk = len(key) >> 2
        self._Nb = 4
        self._Nr = self._Nk + 6
        self._w = _key_expansion(key)

    def encrypt(self, plainText: bytes) -> bytes:
        Nr = self._Nr
        state = _raw_to_state(plainText)
        _add_round_key(state, self._w[0:4])
        for round in range(1, Nr):
            _sub_bytes(state)
            _shift_rows(state)
            _mix_columns(state)
            _add_round_key(state, self._w[4*round:4*round+4])
        _sub_bytes(state)
        _shift_rows(state)
        _add_round_key(state, self._w[4*Nr:4*Nr+4])
        return _state_to_raw(state)

    def decrypt(self, cipherText: bytes) -> bytes:
        Nr = self._Nr
        state = _raw_to_state(cipherText)
        _add_round_key(state, self._w[4*Nr:4*Nr+4])
        for round in range(Nr-1, 0, -1):
            _inv_shift_rows(state)
            _inv_sub_bytes(state)
            _add_round_key(state, self._w[4*round:4*round+4])
            _inv_mix_columns(state)
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, self._w[0:4])
        return _state_to_raw(state)


_GF256 = Polynomial([8, 4, 3, 1, 0])

def _raw_to_state(raw: bytes) -> State:
#>    return [list(t) for t in zip(*zip(*[iter(raw)]*4))]
    return [list(t) for t in zip(*[iter(raw)]*4)]

def _state_to_raw(state: State) -> bytes:
    return bytes(s for v in state for s in v)

# Rcon: GF[256] 1, x, x^2, x^3...
_Rcon = [None] + [(b,0,0,0) for b in
                (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)]

def _key_expansion(key: bytes) -> list[Word]:
    Nk = len(key) >> 2
    Nr = Nk + 6
    w = [None] * (4 * Nr + 4)
    for i in range(Nk):
        w[i] = tuple(key[4*i:4*i+4])
    for i in range(Nk, 4 * Nr + 4):
        temp = w[i - 1]
        if i % Nk == 0:
            temp = _add_words(_sub_word(_rot_word(temp)), _Rcon[i // Nk])
        elif Nk > 6 and i % Nk == 4:
            temp = _sub_word(temp)
        w[i] = _add_words(w[i - Nk], temp)
    return w

def _rot_word(word: Word) -> Word:
    return word[1:4] + word[0:1]

def _sub_word(word: Word) -> Word:
    return tuple(_SBOX[a] for a in word)

def _add_words(word1: Word, word2: Word) -> Word:
    return tuple(a^b for a,b in zip(word1, word2))

def _sub_bytes(state: State) -> None:
    for c in range(4):
        for r in range(4):
            state[c][r] = _SBOX[state[c][r]]

def _inv_sub_bytes(state: State) -> None:
    for c in range(4):
        for r in range(4):
            state[c][r] = _INVSBOX[state[c][r]]

def _shift_rows(s: State) -> None:
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]

def _inv_shift_rows(s: State) -> None:
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]

def _mix_columns(state: State) -> None:
    for v in state:
        v0, v1, v2, v3 = (_GF256(s) for s in v)
        v[0] = int(2 * v0 + 3 * v1 +     v2 +     v3)
        v[1] = int(    v0 + 2 * v1 + 3 * v2 +     v3)
        v[2] = int(    v0 +     v1 + 2 * v2 + 3 * v3)
        v[3] = int(3 * v0 +     v1 +     v2 + 2 * v3)
    # Note: there are really good opportunities to speed up this step:
    # 1, vi + vj = vi ^ vj
    # 2, 2 * vi (GF256)
    #    vo = vi << 1
    #    if vo & 0x100:
    #        vo = vo ^ G # G = 0x11b, generator polynom
    # 3, 3 * vi
    #    vo = 2 * vi ^ vi
    # e.g. v0_next = mulby2(v0 ^ v1) ^ v1 ^ v2 ^ v3

def _inv_mix_columns(state: State) -> None:
    for v in state:
        v0, v1, v2, v3 = (_GF256(s) for s in v)
        v[0] = int(0xe * v0 + 0xb * v1 + 0xd * v2 + 0x9 * v3)
        v[1] = int(0x9 * v0 + 0xe * v1 + 0xb * v2 + 0xd * v3)
        v[2] = int(0xd * v0 + 0x9 * v1 + 0xe * v2 + 0xb * v3)
        v[3] = int(0xb * v0 + 0xd * v1 + 0x9 * v2 + 0xe * v3)

def _add_round_key(state: State, w: list[Word]) -> None:
    for i in range(4):
        state[i] = [a^b for a,b in zip(state[i], w[i])]


########################################

def _show_state(state: State) -> None:
    print(' -------------')
    for r in range(4):
        print('| ', end='')
        for c in range(4):
            print(f'{state[c][r]:0>2x} ', end='')
        print('|')
    print(' -------------')


##############################################################################
# SBOX can be caluclated or a Look-Up-Table can be used (FIPS 197, 5.1.1)
_SBOX = bytes.fromhex('''
    63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
    ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0
    b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15
    04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75
    09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84
    53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf
    d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8
    51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2
    cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73
    60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db
    e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79
    e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08
    ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a
    70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e
    e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df
    8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16
    ''')

_INVSBOX = bytes.fromhex('''
    52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb 
    7c e3 39 82 9b 2f ff 87 34 8e 43 44 c4 de e9 cb 
    54 7b 94 32 a6 c2 23 3d ee 4c 95 0b 42 fa c3 4e 
    08 2e a1 66 28 d9 24 b2 76 5b a2 49 6d 8b d1 25 
    72 f8 f6 64 86 68 98 16 d4 a4 5c cc 5d 65 b6 92 
    6c 70 48 50 fd ed b9 da 5e 15 46 57 a7 8d 9d 84 
    90 d8 ab 00 8c bc d3 0a f7 e4 58 05 b8 b3 45 06 
    d0 2c 1e 8f ca 3f 0f 02 c1 af bd 03 01 13 8a 6b 
    3a 91 11 41 4f 67 dc ea 97 f2 cf ce f0 b4 e6 73 
    96 ac 74 22 e7 ad 35 85 e2 f9 37 e8 1c 75 df 6e 
    47 f1 1a 71 1d 29 c5 89 6f b7 62 0e aa 18 be 1b 
    fc 56 3e 4b c6 d2 79 20 9a db c0 fe 78 cd 5a f4 
    1f dd a8 33 88 07 c7 31 b1 12 10 59 27 80 ec 5f 
    60 51 7f a9 19 b5 4a 0d 2d e5 7a 9f 93 c9 9c ef 
    a0 e0 3b 4d ae 2a f5 b0 c8 eb bb 3c 83 53 99 61 
    17 2b 04 7e ba 77 d6 26 e1 69 14 63 55 21 0c 7d
    ''')

# Generating SBOX substitution table:
#
#     _SBOX = None
#
#     def _gen_SBOX() -> None:
#         global _SBOX, _INVSBOX
#         mask = 0xf8
#         _SBOX = [0] * 256
#         _INVSBOX = [0] * 256
#         for b in range(256):
#             b_inv = int(1 / _GF256(b)) if b else 0
#             b_out = 0
#             for _ in range(8):
#                 bit = _parity(b_inv & mask)
#                 b_out = b_out << 1 | bit
#                 mask = _rotr8(mask)
#             s = b_out ^ 0x63
#             _SBOX[b] = s
#             _INVSBOX[s] = b
#     
#     def _parity(value: int) -> int:
#         p = 0
#         while value:
#             p = 1 - p
#             value = value & value - 1
#         return p
#     
#     def _rotr8(value: int) -> int:
#         return (value & 0x1) << 7 | value >> 1
#     
#     _gen_SBOX()

Registry.add(aes)
