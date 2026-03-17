import itertools as it
import math
import struct
import shutil
import os
import sys
import uuid
import hashlib
import platform
import subprocess
import requests
import base64
import zlib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import PurePath, Path
from typing import List, Dict, Tuple, Optional, Any
import time
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich import print as rprint
from rich.markup import escape
import gmalg
from Crypto.Cipher import AES
from Crypto.Cipher.AES import MODE_CBC
from Crypto.Hash import SHA1
from Crypto.Util.Padding import unpad
from zstandard import ZstdDecompressor, ZstdCompressionDict, DICT_TYPE_AUTO, ZstdCompressor
from colorama import Fore, Style, init
init(autoreset=True)

from colorama import Fore, Back, Style

def pill(text, fore_color=Fore.WHITE, back_color=Back.MAGENTA):
    return f"{back_color}{fore_color} {text} {Style.RESET_ALL}"

# Initialize console for Rich with Cyberpunk theme
console = Console()

def detect_pak_files(base_path: Path) -> List[Path]:
    """Detect all .pak files in the specific Download directory"""
    base_path = Path("/storage/emulated/0/Download/GRW_BRAND OBB TOOL")
    
    pak_files = list(base_path.glob("*.pak"))
    pak_files.extend(base_path.glob("*.obb"))
    return sorted(pak_files, key=lambda x: x.name)


tool_path = Path("/storage/emulated/0/Download/GRW_BRAND OBB TOOL")
tool_path.mkdir(parents=True, exist_ok=True)

# Cyberpunk Theme Colors
class CyberpunkTheme:
    # Neon Colors
    NEON_PINK = "#FF00FF"          # Bright Pink
    NEON_BLUE = "#00FFFF"          # Cyan Blue
    NEON_PURPLE = "#9D00FF"        # Purple
    NEON_GREEN = "#00FF00"         # Lime Green
    NEON_YELLOW = "#FFFF00"        # Bright Yellow
    NEON_RED = "#FF0033"           # Red
    
    # Dark Backgrounds
    DARK_BG = "#0A0A14"            # Deep Blue-Black
    DARK_PANEL = "#121220"         # Panel Background
    DARK_ACCENT = "#1A1A2E"        # Accent Dark
    
    # UI Elements
    TEXT_PRIMARY = "#E0E0FF"       # Light Blue-White
    TEXT_SECONDARY = "#A0A0CC"     # Muted Blue
    028DDAD20FC301951E5924BE9AD62FB719DD94CC30CAB871BEC4377A8')

SIMPLE1_DECRYPT_KEY = 0x79

SIMPLE2_DECRYPT_KEY = bytes.fromhex('E55B4ED1')
SIMPLE2_BLOCK_SIZE = 16

SM4_SECRET_4 = 'eb691efea914241317a8'
SM4_SECRET_2 = 'Q0hVTKey$as*1ZFlQCiA'
SM4_SECRET_NEW = [
        'xG2qW5lP7lV2iN5fN5pG',
        'xT1cJ6dL5wC0kK1rB4dK',
        'qC4jS5bZ6fL5xE6nD4zA',
        'gD4jQ2aL3bS3lC3xT0iW',
        'xU1yQ8wE9zY3gZ3bT5aE',
        'uQ3cO2dX7xY4xU7gH7iS',
        'gW1fR0jK6wQ4oN0oK1kZ',
        'aJ4pV7iZ7pU4wP2aC2cZ',
        'cX6jT3cM2oT3vK0kJ1qN',
        'iT2vS0cS6yT6cZ1sE1lO',
        'hM1pH9iY8wM9hT4lN5uJ',
        'kG6bC8jK0fL0dE4sH4mL',
        'dB6lB3vE0eZ8wM8rI0aC'
]
EM_SIMPLE1 = 1
EM_SIMPLE2 = 16
EM_SM4_2 = 2
EM_SM4_4 = 4
EM_SM4_NEW_BASE = 31
EM_SM4_NEW_MASK = ~EM_SM4_NEW_BASE
EM_UNKNOWN_17 = 17  
CM_NONE = 0
CM_ZLIB = 1
CM_ZSTD = 6
CM_ZSTD_DICT = 8
CM_MASK = 15


# ========== SM4 IMPLEMENTATION ==========
class SM4:
    """SM4 Algorithm Implementation."""
    
    _S_BOX = bytes([
        0x34, 0x66, 0x25, 0x74, 0x89, 0x78, 0xE4, 0xA9, 0x5A, 0x41, 0xBC, 0x7A, 0xD6, 0x16, 0x21, 0x23,
        0x4D, 0x61, 0xDA, 0x94, 0x9B, 0xDF, 0x13, 0x3C, 0x69, 0x3A, 0x31, 0x0A, 0x5F, 0xD7, 0x99, 0x95,
        0xF1, 0xAE, 0x72, 0x3D, 0x07, 0x60, 0x24, 0xB6, 0x98, 0xEE, 0xC4, 0xA2, 0x2D, 0x88, 0xDD, 0x8D,
        0x04, 0xEA, 0xBB, 0x11, 0xCA, 0x3E, 0x5D, 0xA1, 0xF6, 0x3F, 0xB0, 0x97, 0x80, 0x47, 0x2B, 0xA6,
        0xE6, 0xF7, 0xD9, 0xB1, 0x59, 0xC0, 0x7C, 0xBE, 0x54, 0x28, 0xB7, 0x7E, 0x4F, 0xF8, 0x43, 0x6E,
        0xA0, 0x50, 0x0E, 0xF5, 0x90, 0xB8, 0xFB, 0xA3, 0x7B, 0x62, 0x19, 0x46, 0x03, 0x2A, 0xB9, 0x8F,
        0x9F, 0x77, 0xB4, 0x5B, 0x83, 0x87, 0x08, 0xEB, 0xE2, 0x1E, 0x42, 0xF0, 0x0F, 0xE8, 0x71, 0x6A,
        0x75, 0xAD, 0x55, 0x1F, 0xB5, 0xAB, 0x33, 0xFA, 0x7F, 0x15, 0xBD, 0x85, 0xD8, 0x06, 0x68, 0xB3,
        0x52, 0x30, 0x48, 0x0B, 0x00, 0xED, 0xEF, 0xB2, 0x57, 0x8E, 0xE7, 0x6C, 0xD5, 0xE5, 0x2E, 0x53,
        0x82, 0x05, 0xF9, 0x81, 0xF4, 0x56, 0xBF, 0x8C, 0x4B, 0xE3, 0xDB, 0x4A, 0x91, 0x4C, 0x2C, 0xD3,
        0x40, 0x29, 0x4E, 0x20, 0x14, 0x36, 0x79, 0x09, 0x6F, 0xD1, 0x37, 0xE0, 0x39, 0x0C, 0x8A, 0x92,
        0x38, 0x12, 0x35, 0x6D, 0xE1, 0xFD, 0x93, 0x9A, 0x17, 0xD4, 0xC9, 0x9C, 0x6B, 0x84, 0x26, 0x9D,
        0xAF, 0x76, 0xC1, 0x9E, 0xD0, 0x96, 0xC5, 0xCB, 0xE9, 0x73, 0x49, 0xD2, 0xCD, 0x64, 0xC3, 0xC7,
        0x01, 0x7D, 0xF3, 0xAC, 0xFC, 0xDE, 0xA4, 0x44, 0x32, 0x1B, 0xC2, 0xBA, 0x1C, 0x02, 0xC6, 0x27,
        0x45, 0x8B, 0xF2, 0x18, 0xA7, 0x10, 0x51, 0x1D, 0xC8, 0xCF, 0x63, 0xFF, 0x2F, 0x0D, 0x58, 0xCE,
        0x65, 0xA5, 0xDC, 0x1A, 0x3B, 0x86, 0xFE, 0x22, 0x5C, 0xA8, 0x5E, 0x67, 0xAA, 0xEC, 0x70, 0xCC
    ])

    _FK = [
        0x46970E9C, 0x4BC0685E, 0x59056186, 0xBCA2491E
    ]

    _CK = [
        0x000EB92B, 0x3A0AE783, 0x9E3B5C67, 0xADDBDABF, 0x7B7484CB, 0x49156C63, 0xC79AB5E7, 0x79EC9CFF,
        0x1725BEAB, 0x2FB89CA3, 0x24808AD7, 0xDDD28B1F, 0x4740DA4B, 0xBBC3EA73, 0x247B30E7, 0x91BE385F,
        0x0401248B, 0x45FCD3A3, 0x530B4CE7, 0xC68DD35F, 0xE3D16C2B, 0x4F698C13, 0x6B92C747, 0x769EFB1F,
        0x4C73BE9B, 0xC942B193, 0xAD80D827, 0x372FB33F, 0x13CB6AAB, 0x2BDC0AA3, 0x17A4A247, 0xD5E96CAF
    ]

    @staticmethod
    def ROL32(x, n):
        return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

    @staticmethod
    def _BS(X):
        return ((SM4._S_BOX[(X >> 24) & 0xff] << 24) |
                (SM4._S_BOX[(X >> 16) & 0xff] << 16) |
                (SM4._S_BOX[(X >> 8) & 0xff] << 8) |
                (SM4._S_BOX[X & 0xff]))

    @staticmethod
    def _T0(X):
        X = SM4._BS(X)
        return X ^ SM4.ROL32(X, 2) ^ SM4.ROL32(X, 10) ^ SM4.ROL32(X, 18) ^ SM4.ROL32(X, 24)

    @staticmethod
    def _T1(X):
        X = SM4._BS(X)
        return X ^ SM4.ROL32(X, 13) ^ SM4.ROL32(X, 23)

    @staticmethod
    def _key_expand(key: bytes, rkey: list):
        K0 = int.from_bytes(key[0:4], "big") ^ SM4._FK[0]
        K1 = int.from_bytes(key[4:8], "big") ^ SM4._FK[1]
        K2 = int.from_bytes(key[8:12], "big") ^ SM4._FK[2]
        K3 = int.from_bytes(key[12:16], "big") ^ SM4._FK[3]

        for i in range(0, 32, 4):
            K0 = K0 ^ SM4._T1(K1 ^ K2 ^ K3 ^ SM4._CK[i])
            rkey[i] = K0
            K1 = K1 ^ SM4._T1(K2 ^ K3 ^ K0 ^ SM4._CK[i + 1])
            rkey[i + 1] = K1
            K2 = K2 ^ SM4._T1(K3 ^ K0 ^ K1 ^ SM4._CK[i + 2])
            rkey[i + 2] = K2
            K3 = K3 ^ SM4._T1(K0 ^ K1 ^ K2 ^ SM4._CK[i + 3])
            rkey[i + 3] = K3

    @classmethod
    def key_length(cls):
        return 16

    @classmethod
    def block_length(cls):
        return 16

    def __init__(self, key: bytes):
        if len(key) != self.key_length():
            raise ValueError(f"Key must be {self.key_length()} bytes")

        self._key = key
        self._rkey = [0] * 32
        SM4._key_expand(self._key, self._rkey)
        self._block_buffer = bytearray()

    def encrypt(self, block: bytes) -> bytes:
        if len(block) != self.block_length():
            raise ValueError(f"Block must be {self.block_length()} bytes")

        RK = self._rkey
        X0 = int.from_bytes(block[0:4], "big")
        X1 = int.from_bytes(block[4:8], "big")
        X2 = int.from_bytes(block[8:12], "big")
        X3 = int.from_bytes(block[12:16], "big")

        for i in range(0, 32, 4):
            X0 = X0 ^ SM4._T0(X1 ^ X2 ^ X3 ^ RK[i])
            X1 = X1 ^ SM4._T0(X2 ^ X3 ^ X0 ^ RK[i + 1])
            X2 = X2 ^ SM4._T0(X3 ^ X0 ^ X1 ^ RK[i + 2])
            X3 = X3 ^ SM4._T0(X0 ^ X1 ^ X2 ^ RK[i + 3])

        BUFFER = self._block_buffer
        BUFFER.clear()
        BUFFER.extend(X3.to_bytes(4, "big"))
        BUFFER.extend(X2.to_bytes(4, "big"))
        BUFFER.extend(X1.to_bytes(4, "big"))
        BUFFER.extend(X0.to_bytes(4, "big"))
        return bytes(BUFFER)

    def decrypt(self, block: bytes) -> bytes:
        if len(block) != self.block_length():
            raise ValueError(f"Block must be {self.block_length()} bytes")

        RK = self._rkey
        X0 = int.from_bytes(block[0:4], "big")
        X1 = int.from_bytes(block[4:8], "big")
        X2 = int.from_bytes(block[8:12], "big")
        X3 = int.from_bytes(block[12:16], "big")

        for i in range(0, 32, 4):
            X0 = X0 ^ SM4._T0(X1 ^ X2 ^ X3 ^ RK[31 - i])
            X1 = X1 ^ SM4._T0(X2 ^ X3 ^ X0 ^ RK[30 - i])
            X2 = X2 ^ SM4._T0(X3 ^ X0 ^ X1 ^ RK[29 - i])
            X3 = X3 ^ SM4._T0(X0 ^ X1 ^ X2 ^ RK[28 - i])

        BUFFER = self._block_buffer
        BUFFER.clear()
        BUFFER.extend(X3.to_bytes(4, "big"))
        BUFFER.extend(X2.to_bytes(4, "big"))
        BUFFER.extend(X1.to_bytes(4, "big"))
        BUFFER.extend(X0.to_bytes(4, "big"))
        return bytes(BUFFER)

# ========== UTILITY CLASSES ==========
class Misc:
    @staticmethod
    def pad_to_n(data: bytes, n: int) -> bytes:
        assert n > 0
        padding = n - (len(data) % n)
        if padding == n:
            return data
        return data + b'\x00' * padding

    @staticmethod
    def align_up(x: int, n: int) -> int:
        return ((x + n - 1) // n) * n

class Reader:
    def __init__(self, buffer, cursor=0):
        self._buffer = buffer
        self._cursor = cursor

    def u1(self, move_cursor=True) -> int:
        return self.unpack('B', move_cursor=move_cursor)[0]

    def u4(self, move_cursor=True) -> int:
        return self.unpack('<I', move_cursor=move_cursor)[0]

    def u8(self, move_cursor=True) -> int:
        return self.unpack('<Q', move_cursor=move_cursor)[0]

    def i1(self, move_cursor=True) -> int:
        return self.unpack('b', move_cursor=move_cursor)[0]

    def i4(self, move_cursor=True) -> int:
        return self.unpack('<i', move_cursor=move_cursor)[0]

    def i8(self, move_cursor=True) -> int:
        return self.unpack('<q', move_cursor=move_cursor)[0]

    def s(self, n: int, move_cursor=True) -> bytes:
        return self.unpack(f'{n}s', move_cursor=move_cursor)[0]

    def unpack(self, f: str | bytes, offset=0, move_cursor=True):
        x = struct.unpack_from(f, self._buffer, self._cursor + offset)
        if move_cursor:
            self._cursor += struct.calcsize(f)
        return x

    def string(self, move_cursor=True) -> str:
        length = self.i4(move_cursor=move_cursor)
        if length == 0:
            return str()
        assert length > 0
        offset = 0 if move_cursor else 4
        return self.unpack(f'{length}s', offset=offset, move_cursor=move_cursor)[0].rstrip(b'\x00').decode()

# ========== PAK CLASSES ==========
class PakInfo:
    def __init__(self, buffer, keystream: List[int]):
        def decrypt_index_encrypted(x: int) -> int:
            MASK_8 = 0xFF
            return (x ^ keystream[3]) & MASK_8

        def decrypt_magic(x: int) -> int:
            return x ^ keystream[2]

        def decrypt_index_hash(x: bytes) -> bytes:
            key = struct.pack('<5I', *keystream[4:][:5])
            assert len(x) == len(key)
            return bytes(a ^ b for a, b in zip(x, key))

        def decrypt_index_size(x: int) -> int:
            return x ^ ((keystream[10] << 32) | keystream[11])

        def decrypt_index_offset(x: int) -> int:
            return x ^ ((keystream[0] << 32) | keystream[1])

        reader = Reader(buffer[-PakInfo._mem_size(-1):])
        self.index_encrypted: bool = decrypt_index_encrypted(reader.u1()) == 1
        self.magic: int = decrypt_magic(reader.u4())
        self.version: int = reader.u4()
        self.index_hash: bytes = decrypt_index_hash(reader.s(20)) if self.version >= 6 else bytes()
        self.index_size: int = decrypt_index_size(reader.u8())
        self.index_offset: int = decrypt_index_offset(reader.u8())
        if self.version <= 3:
            self.index_encrypted = False

    @staticmethod
    def _mem_size(_: int) -> int:
        return 1 + 4 + 4 + 20 + 8 + 8

class TencentPakInfo(PakInfo):
    def __init__(self, buffer, keystream: List[int]):
        def decrypt_unk(x: bytes) -> bytes:
            key = struct.pack('<8I', *keystream[7:][:8])
            assert len(x) == len(key)
            return bytes(a ^ b for a, b in zip(x, key))

        def decrypt_stem_hash(x: int) -> int:
            return x ^ keystream[8]

        def decrypt_unk_hash(x: int) -> int:
            return x ^ keystream[9]

        super().__init__(buffer, keystream)
        reader = Reader(buffer[-TencentPakInfo._mem_size(self.version):])
        self.unk1: bytes = decrypt_unk(reader.s(32)) if self.version >= 7 else bytes()
        self.packed_key: bytes = reader.s(256) if self.version >= 8 else bytes()
        self.packed_iv: bytes = reader.s(256) if self.version >= 8 else bytes()
        self.packed_index_hash: bytes = reader.s(256) if self.version >= 8 else bytes()
        self.stem_hash: int = decrypt_stem_hash(reader.u4()) if self.version >= 9 else 0
        self.unk2: int = decrypt_unk_hash(reader.u4()) if self.version >= 9 else 0
        self.content_org_hash: bytes = reader.s(20) if self.version >= 12 else bytes()

    @staticmethod
    def _mem_size(version: int) -> int:
        size_for_7 = 32 if version >= 7 else 0
        size_for_8 = 256 * 3 if version >= 8 else 0
        size_for_9 = 4 * 2 if version >= 9 else 0
        size_for_12 = 20 if version >= 12 else 0
        return PakInfo._mem_size(version) + size_for_7 + size_for_8 + size_for_9 + size_for_12

class PakCompressedBlock:
    def __init__(self, reader: Reader):
        self.start: int = reader.u8()
        self.end: int = reader.u8()

@dataclass
class TencentPakEntry:
    def __init__(self, reader: Reader, version: int):
        self.content_hash: bytes = reader.s(20)
        if version <= 1:
            _ = reader.u8()
        self.offset: int = reader.u8()
        self.uncompressed_size: int = reader.u8()
        self.compression_method: int = reader.u4() & CM_MASK
        self.size: int = reader.u8()
        self.unk1: int = reader.u1() if version >= 5 else 0
        self.unk2: bytes = reader.s(20) if version >= 5 else bytes()
        self.compressed_blocks: List[PakCompressedBlock] = [PakCompressedBlock(reader) for _ in range(
            reader.u4())] if self.compression_method != 0 and version >= 3 else []
        self.compression_block_size: int = reader.u4() if version >= 4 else 0
        self.encrypted: bool = reader.u1() == 1 if version >= 4 else False
        self.encryption_method: int = reader.u4() if version >= 12 else 0
        self.index_new_sep: int = reader.u4() if version >= 12 else 0

    def _mem_size(self, version: int) -> int:
        size_for_123 = 20 + 8 + 8 + 4 + 8 + (8 if version == 1 else 0)
        size_for_4 = 4 + 1 if version >= 4 else 0
        size_for_compressed_blocks = 4 + len(self.compressed_blocks) * 16 if self.compressed_blocks else 0
        size_for_5 = 1 + 20 if version >= 5 else 0
        size_for_12 = 4 if version >= 12 else 0
        return size_for_123 + size_for_4 + size_for_5 + size_for_12 + size_for_compressed_blocks

class PakCrypto:
    class _LCG:
        def __init__(self, seed: int):
            self.state = seed

        def next(self) -> int:
            MASK_32 = 0xFFFFFFFF
            MSB_1 = 1 << 31

            def wrap(x: int) -> int:
                x &= MASK_32
                if not x & MSB_1:
                    return x
                else:
                    return ((x + MSB_1) & MASK_32) - MSB_1

            x1 = wrap(0x41C64E6D * self.state)
            self.state = wrap(x1 + 12345)
            x2 = wrap(x1 + 0x13038) if self.state < 0 else self.state
            return ((x2 >> 16) & MASK_32) % 0x7FFF

    @staticmethod
    def zuc_keystream() -> List[int]:
        zuc = gmalg.ZUC(ZUC_KEY, ZUC_IV)
        return [struct.unpack('>I', zuc.generate())[0] for _ in range(16)]

    @staticmethod
    def _xorxor(buffer, x) -> bytes:
        return bytes(buffer[i] ^ x[i % len(x)] for i in range(len(buffer)))

    @staticmethod
    def _hashhash(buffer, n: int) -> bytes:
        result = bytes()
        for i in range(math.ceil(n / SHA1.digest_size)):
            result += SHA1.new(buffer).digest()
        if len(result) >= n:
            result = result[:n]
        else:
            result += b'\x00' * (n - len(result))
        return result

    @staticmethod
    def _meowmeow(buffer) -> bytes:
        def unpad(x):
            skip = 1 + next((i for i in range(len(x)) if x[i] != 0))
            return x[skip:]

        if len(buffer) < 43:
            return bytes()

        x1 = buffer[1:][:SHA1.digest_size]
        x2 = buffer[SHA1.digest_size + 1:]
        x1 = PakCrypto._xorxor(x1, PakCrypto._hashhash(x2, len(x1)))
        x2 = PakCrypto._xorxor(x2, PakCrypto._hashhash(x1, len(x2)))

        part1, m = (x2[:SHA1.digest_size], x2[SHA1.digest_size:])
        if part1 != SHA1.new(b'\x00' * SHA1.digest_size).digest():
            return bytes()

        return unpad(m)

    @staticmethod
    def rsa_extract(signature: bytes, modulus: bytes) -> bytes:
        c = int.from_bytes(signature, 'little')
        n = int.from_bytes(modulus, 'little')
        e = 0x10001
        m = pow(c, e, n).to_bytes(256, 'little').rstrip(b'\x00')
        return PakCrypto._meowmeow(Misc.pad_to_n(m, 4))

    @staticmethod
    def _decrypt_simple1(ciphertext) -> bytes:
        return bytes(x ^ SIMPLE1_DECRYPT_KEY for x in ciphertext)

    @staticmethod
    def _decrypt_simple2(ciphertext) -> bytes:
        class RollingKey:
            def __init__(self, initial_value: int):
                self._value = initial_value

            def update(self, x: int) -> int:
                self._value ^= x
                return self._value

        assert len(ciphertext) % SIMPLE2_BLOCK_SIZE == 0
        initial_key, = struct.unpack('<I', SIMPLE2_DECRYPT_KEY)
        rolling_key = RollingKey(initial_key)
        plaintext = (
            struct.pack('<I', rolling_key.update(x)) for x in struct.unpack(f'<{len(ciphertext) // 4}I', ciphertext)
        )
        return bytes(it.chain.from_iterable(plaintext))

    @staticmethod
    @lru_cache(maxsize=1)
    def _derive_sm4_key(file_path: PurePath, encryption_method: int) -> bytes:
        part1 = file_path.stem.lower()
        if encryption_method == EM_SM4_2:
            secret = SM4_SECRET_2
        elif encryption_method == EM_SM4_4:
            secret = SM4_SECRET_4
        else:
            index = (encryption_method - EM_SM4_NEW_BASE) % len(SM4_SECRET_NEW)
            secret = f'{SM4_SECRET_NEW[index]}{encryption_method}'
        return SHA1.new(str(part1 + secret).encode()).digest()[:SM4.key_length()]

    @staticmethod
    @lru_cache(maxsize=1)
    def _sm4_context_for_key(key: bytes) -> SM4:
        return SM4(key)

    @staticmethod
    def _decrypt_sm4(ciphertext, file_path: PurePath, encryption_method: int) -> bytes:
        assert len(ciphertext) % SM4.block_length() == 0
        key = PakCrypto._derive_sm4_key(file_path, encryption_method)
        sm4 = PakCrypto._sm4_context_for_key(key)
        return bytes(
            it.chain.from_iterable(
                sm4.decrypt(x) for x in it.batched(ciphertext, SM4.block_length())
            )
        )

    @staticmethod
    def decrypt_index(ciphertext, pak_info: TencentPakInfo) -> bytes:
        if pak_info.version > 7:
            key = PakCrypto.rsa_extract(pak_info.packed_key, RSA_MOD_1)
            iv = PakCrypto.rsa_extract(pak_info.packed_iv, RSA_MOD_1)
            assert len(key) == 32 and len(iv) == 32
            aes = AES.new(key, MODE_CBC, iv[:16])
            return unpad(aes.decrypt(ciphertext), AES.block_size)
        else:
            return bytes(PakCrypto._decrypt_simple1(ciphertext))

    @staticmethod
    def _is_simple1_method(encryption_method: int) -> bool:
        return encryption_method == EM_SIMPLE1

    @staticmethod
    def _is_simple2_method(encryption_method: int) -> bool:
        return encryption_method == EM_SIMPLE2 or encryption_method == 17

    @staticmethod
    def _is_sm4_method(encryption_method: int) -> bool:
        return (encryption_method == EM_SM4_2
                or encryption_method == EM_SM4_4
                or encryption_method & EM_SM4_NEW_MASK != 0)

    @staticmethod
    def align_encrypted_content_size(n: int, encryption_method: int) -> int:
        if PakCrypto._is_simple2_method(encryption_method):
            return Misc.align_up(n, SIMPLE2_BLOCK_SIZE)
        elif PakCrypto._is_sm4_method(encryption_method):
            return Misc.align_up(n, SM4.block_length())
        else:
            return n

    @staticmethod
    def decrypt_block(ciphertext, file: PurePath, encryption_method: int) -> bytes:
        if PakCrypto._is_simple1_method(encryption_method):
            return PakCrypto._decrypt_simple1(ciphertext)
        elif PakCrypto._is_simple2_method(encryption_method):
            return PakCrypto._decrypt_simple2(ciphertext)
        elif PakCrypto._is_sm4_method(encryption_method):
            return PakCrypto._decrypt_sm4(ciphertext, file, encryption_method)
        else:
            raise ValueError(f"Unknown encryption method: {encryption_method}")

    @staticmethod
    @lru_cache(maxsize=33)
    def generate_block_indices(n: int, encryption_method: int) -> List[int]:
        if not PakCrypto._is_sm4_method(encryption_method):
            return list(range(n))
        permutation = []
        lcg = PakCrypto._LCG(n)
        while len(permutation) != n:
            x = lcg.next() % n
            if x not in permutation:
                permutation.append(x)
        inverse = [0] * len(permutation)
        for i, x in enumerate(permutation):
            inverse[x] = i
        return inverse

class PakCompression:
    @staticmethod
    @lru_cache(maxsize=33)
    def _zstd_decompressor(dict: ZstdCompressionDict) -> ZstdDecompressor:
        return ZstdDecompressor(dict)

    @staticmethod
    def zstd_dictionary(dict_data) -> ZstdCompressionDict:
        return ZstdCompressionDict(dict_data, DICT_TYPE_AUTO)

    @staticmethod
    def decompress_block(block, dict: Optional[ZstdCompressionDict], compression_method: int) -> bytes:
        if compression_method == CM_ZLIB:
            try:
                return zlib.decompress(block)
            except zlib.error:
                return block
        elif compression_method == CM_ZSTD or compression_method == CM_ZSTD_DICT:
            if compression_method != CM_ZSTD_DICT:
                dict = None
            return PakCompression._zstd_decompressor(dict).decompress(block)
        else:
            raise ValueError(f"Unknown compression method: {compression_method}")

class TencentPakFile:
    def __init__(self, file_path: PurePath, is_od=False):
        self._file_path = file_path
        with open(file_path, 'rb') as file:
            self._file_content = memoryview(file.read())
        self._is_od = is_od
        self._mount_point = PurePath()
        self._is_zstd_with_dict = 'zsdic' in str(self._file_path)
        self._zstd_dict = None
        self._files: List[TencentPakEntry] = []
        self._index: Dict[PurePath, Dict[str, TencentPakEntry]] = {}
        self._pak_info = TencentPakInfo(self._file_content, PakCrypto.zuc_keystream())
        self._verify_stem_hash()
        self._tencent_load_index()

    def _verify_stem_hash(self) -> None:
        if not self._is_od and self._pak_info.version >= 9:
            assert self._pak_info.stem_hash == zlib.crc32(self._file_path.stem.encode('utf-32le'))

    def _tencent_load_index(self) -> None:
        index_data = self._file_content[self._pak_info.index_offset:][:self._pak_info.index_size]
        if self._pak_info.index_encrypted:
            index_data = PakCrypto.decrypt_index(index_data, self._pak_info)
        else:
            index_data = index_data
        self._verify_index_hash(index_data)
        self._load_index(index_data)

    def _verify_index_hash(self, index_data) -> None:
        expected_hash = self._pak_info.index_hash
        if not self._is_od and self._pak_info.version >= 8:
            assert expected_hash == PakCrypto.rsa_extract(self._pak_info.packed_index_hash, RSA_MOD_2)
        assert expected_hash == SHA1.new(index_data).digest()

    @staticmethod
    def _construct_mount_point(mount_point: str) -> PurePath:
        result = PurePath()
        for part in PurePath(mount_point).parts:
            if part != '..':
                result /= part
        return result

    def _peek_content(self, offset: int, size: int, encryption_method: int) -> memoryview:
        size = PakCrypto.align_encrypted_content_size(size, encryption_method)
        return self._file_content[offset:][:size]

    def _peek_block_content(self, block: PakCompressedBlock, encryption_method: int) -> memoryview:
        size = PakCrypto.align_encrypted_content_size(block.end - block.start, encryption_method)
        return self._file_content[block.start:][:size]

    def _construct_zstd_dict(self, dict_entry: TencentPakEntry) -> None:
        assert not self._zstd_dict
        assert not dict_entry.encrypted
        assert dict_entry.compression_method == CM_NONE
        reader = Reader(self._peek_content(dict_entry.offset, dict_entry.size, 0))
        dict_size = reader.u8()
        _ = reader.u4()
        assert dict_size == reader.u4()
        dict_data = reader.s(dict_size)
        self._zstd_dict = PakCompression.zstd_dictionary(dict_data)

    def _load_index(self, index_data) -> None:
        if self._pak_info.version <= 10:
            raise ValueError(f"Unsupported version: {self._pak_info.version}")
        reader = Reader(index_data)
        self._mount_point = self._construct_mount_point(reader.string())
        self._files = [TencentPakEntry(reader, self._pak_info.version) for _ in range(reader.u4())]
        for _ in range(reader.u8()):
            dir_path = PurePath(reader.string())
            e = {reader.string(): self._files[~reader.i4()] for _ in range(reader.u8())}
            if self._is_zstd_with_dict and dir_path.name == 'zstddic':
                assert len(e) == 1
                self._construct_zstd_dict(e[[*e.keys()][0]])
                continue
            self._index.update({PurePath(dir_path): e})

    def _write_to_disk(self, file_path: PurePath, entry: TencentPakEntry) -> None:
        encryption_method = entry.encryption_method
        compression_method = entry.compression_method
        
        console.print(f"[#00CCFF]{file_path.name}[/#00CCFF] - Encryption: {encryption_method}, Compression: {compression_method}, Blocks: {len(entry.compressed_blocks)}")
        
        with open(file_path, 'wb') as file:
            if compression_method == CM_NONE:
                data = self._peek_content(entry.offset, entry.size, encryption_method)
                if entry.encrypted:
                    data = PakCrypto.decrypt_block(data, file_path, encryption_method)
                file.write(data)
                return
            for x in PakCrypto.generate_block_indices(len(entry.compressed_blocks), encryption_method):
                data = self._peek_block_content(entry.compressed_blocks[x], encryption_method)
                if entry.encrypted:
                    data = PakCrypto.decrypt_block(data, file_path, encryption_method)
                data = PakCompression.decompress_block(data, self._zstd_dict, compression_method)
                file.write(data)

    def dump(self, out_path: PurePath) -> None:
        out_path /= self._mount_point
        for dir_path, dir in self._index.items():
            current_out_path = Path(out_path / dir_path)
            if not current_out_path.exists():
                current_out_path.mkdir(parents=True, exist_ok=True)
            for file_name, entry in dir.items():
                self._write_to_disk(current_out_path / file_name, entry)

# ========== REPACK FUNCTIONALITY ==========
def dump_unpacking_log(pak_file, output_log_path: Path):
    """
    Dump detailed unpacking log with compression, encryption, and block information
    """
    with open(output_log_path, 'w', encoding='utf-8') as log_file:
        log_file.write("=" * 80 + "\n")
        log_file.write("PAK UNPACKING DEBUG LOG\n")
        log_file.write("=" * 80 + "\n\n")
        
        log_file.write(f"PAK File: {pak_file._file_path}\n")
        log_file.write(f"PAK Info Version: {pak_file._pak_info.version}\n")
        log_file.write(f"Mount Point: {pak_file._mount_point}\n")
        log_file.write(f"Is ZSTD with Dict: {pak_file._is_zstd_with_dict}\n")
        log_file.write(f"Has ZSTD Dict: {pak_file._zstd_dict is not None}\n")
        log_file.write("-" * 80 + "\n\n")
        
        # Counters
        file_count = 0
        compression_stats = {}
        encryption_stats = {}
        block_stats = {}
        
        for dir_path, files in pak_file._index.items():
            for file_name, entry in files.items():
                file_count += 1
                full_path = str(PurePath(dir_path) / file_name).replace("\\", "/")
                
                # Update statistics
                comp_method = entry.compression_method
                compression_stats[comp_method] = compression_stats.get(comp_method, 0) + 1
                
                enc_method = entry.encryption_method
                encryption_stats[enc_method] = encryption_stats.get(enc_method, 0) + 1
                
                block_count = len(entry.compressed_blocks)
                block_stats[block_count] = block_stats.get(block_count, 0) + 1
                
                # Write file details
                log_file.write(f"\n[{file_count}] {full_path}\n")
                log_file.write(f"  {'─' * 60}\n")
                log_file.write(f"  Uncompressed Size: {entry.uncompressed_size:,} bytes\n")
                log_file.write(f"  Compressed Size:   {entry.size:,} bytes\n")
                
                # Compression details
                comp_method_name = {
                    CM_NONE: "NONE",
                    CM_ZLIB: "ZLIB",
                    CM_ZSTD: "ZSTD",
                    CM_ZSTD_DICT: "ZSTD_DICT"
                }.get(comp_method, f"UNKNOWN({comp_method})")
                
                log_file.write(f"  Compression Method: {comp_method_name} ({comp_method})\n")
                
                # Encryption details
                enc_method_name = "NONE"
                if enc_method == EM_SIMPLE1:
                    enc_method_name = "SIMPLE1"
                elif enc_method in (EM_SIMPLE2, EM_UNKNOWN_17):
                    enc_method_name = "SIMPLE2"
                elif enc_method == EM_SM4_2:
                    enc_method_name = "SM4_2"
                elif enc_method == EM_SM4_4:
                    enc_method_name = "SM4_4"
                elif enc_method & EM_SM4_NEW_MASK != 0:
                    enc_method_name = f"SM4_NEW({enc_method})"
                else:
                    enc_method_name = f"UNKNOWN({enc_method})"
                
                log_file.write(f"  Encryption Method: {enc_method_name}\n")
                log_file.write(f"  Is Encrypted: {entry.encrypted}\n")
                
                # Block information
                log_file.write(f"  Compressed Blocks: {len(entry.compressed_blocks)}\n")
                log_file.write(f"  Compression Block Size: {entry.compression_block_size:,} bytes\n")
                
                if entry.compressed_blocks:
                    total_compressed = sum(blk.end - blk.start for blk in entry.compressed_blocks)
                    total_space = sum(blk.end - blk.start for blk in entry.compressed_blocks)
                    
                    log_file.write(f"  Total Compressed Space: {total_compressed:,} bytes\n")
                    log_file.write(f"  Available for Repack: {total_space:,} bytes\n")
                    
                    # Calculate compression ratio
                    if entry.uncompressed_size > 0:
                        compression_ratio = total_compressed / entry.uncompressed_size
                        log_file.write(f"  Compression Ratio: {compression_ratio:.2%}\n")
                    
                    # Show block details (first 10 blocks)
                    log_file.write(f"  Block Details (first 10 of {len(entry.compressed_blocks)}):\n")
                    for i, blk in enumerate(entry.compressed_blocks[:10]):
                        block_size = blk.end - blk.start
                        log_file.write(f"    Block {i}: Offset={blk.start:,} Size={block_size:,} bytes\n")
                    
                    if len(entry.compressed_blocks) > 10:
                        log_file.write(f"    ... and {len(entry.compressed_blocks) - 10} more blocks\n")
                    
                    # Calculate min/max/avg block sizes
                    block_sizes = [blk.end - blk.start for blk in entry.compressed_blocks]
                    if block_sizes:
                        log_file.write(f"  Min Block Size: {min(block_sizes):,} bytes\n")
                        log_file.write(f"  Max Block Size: {max(block_sizes):,} bytes\n")
                        log_file.write(f"  Avg Block Size: {sum(block_sizes) / len(block_sizes):,.0f} bytes\n")
                
                log_file.write(f"  Available Space per Block: {'N/A' if not entry.compressed_blocks else 'See block details'}\n")
                log_file.write(f"  {'─' * 60}\n")
        
        # Write summary statistics
        log_file.write("\n" + "=" * 80 + "\n")
        log_file.write("SUMMARY STATISTICS\n")
        log_file.write("=" * 80 + "\n\n")
        
        log_file.write(f"Total Files: {file_count}\n\n")
        
        # Compression method summary
        log_file.write("Compression Methods:\n")
        for method, count in sorted(compression_stats.items()):
            method_name = {
                CM_NONE: "NONE",
                CM_ZLIB: "ZLIB",
                CM_ZSTD: "ZSTD",
                CM_ZSTD_DICT: "ZSTD_DICT"
            }.get(method, f"UNKNOWN({method})")
            log_file.write(f"  {method_name}: {count} files ({count/file_count*100:.1f}%)\n")
        
        # Encryption method summary
        log_file.write("\nEncryption Methods:\n")
        for method, count in sorted(encryption_stats.items()):
            if method == EM_SIMPLE1:
                method_name = "SIMPLE1"
            elif method == EM_SIMPLE2:
                method_name = "SIMPLE2"
            elif method == EM_SM4_2:
                method_name = "SM4_2"
            elif method == EM_SM4_4:
                method_name = "SM4_4"
            elif method & EM_SM4_NEW_MASK != 0:
                method_name = f"SM4_NEW({method})"
            else:
                method_name = f"UNKNOWN({method})"
            log_file.write(f"  {method_name}: {count} files ({count/file_count*100:.1f}%)\n")
        
        # Block count summary
        log_file.write("\nBlock Count Distribution:\n")
        for block_count, file_count_with_blocks in sorted(block_stats.items()):
            percentage = file_count_with_blocks / file_count * 100
            log_file.write(f"  {block_count:3d} blocks: {file_count_with_blocks:4d} files ({percentage:5.1f}%)\n")
        
        # Calculate compression efficiency
        log_file.write("\nCompression Efficiency Analysis:\n")
        single_block_files = block_stats.get(1, 0)
        multi_block_files = file_count - single_block_files
        log_file.write(f"  Single-block files: {single_block_files} ({single_block_files/file_count*100:.1f}%)\n")
        log_file.write(f"  Multi-block files:  {multi_block_files} ({multi_block_files/file_count*100:.1f}%)\n")
        
        log_file.write("\n" + "=" * 80 + "\n")
        log_file.write("END OF LOG\n")
        log_file.write("=" * 80 + "\n")
    
    console.print(f"[bold #00FF88]✅ Debug log saved to: {output_log_path}[/bold #00FF88]")
    
def debug_entry_info(entry):
    """Debug function to print entry details"""
    console.print(f"[bold #FFFF00]ENTRY DEBUG INFO:[/bold #FFFF00]")
    console.print(f"  • Uncompressed size: {entry.uncompressed_size}")
    console.print(f"  • Compressed size: {entry.size}")
    console.print(f"  • Compression method: {entry.compression_method}")
    console.print(f"  • Encryption method: {entry.encryption_method}")
    console.print(f"  • Encrypted: {entry.encrypted}")
    console.print(f"  • Blocks: {len(entry.compressed_blocks)}")
    console.print(f"  • Block size: {entry.compression_block_size}")
    
    if entry.compressed_blocks:
        console.print(f"  • Block ranges:")
        for i, blk in enumerate(entry.compressed_blocks[:5]):  # Show first 5
            console.print(f"    Block {i}: {blk.start} - {blk.end} (size: {blk.end - blk.start})")
        if len(entry.compressed_blocks) > 5:
            console.print(f"    ... and {len(entry.compressed_blocks) - 5} more blocks")

def _zstd_add_skippable_padding(data: bytes, pad_len: int) -> bytes:
    if pad_len <= 0:
        return data

    out = bytearray(data)
    while pad_len > 0:
        frame_len = min(max(pad_len - 8, 0), 1024 * 1024)
        out += b"\x50\x2A\x4D\x18"
        out += struct.pack("<I", frame_len)
        out += b"\x00" * frame_len
        pad_len -= (8 + frame_len)
    return bytes(out)

def _compress_to_target(
    plaintext: bytes,
    method: int,
    zstd_dict,
    target_size: int,
    encryption_method: int
) -> bytes:

    align = PakCrypto.align_encrypted_content_size

    if method in (CM_ZSTD, CM_ZSTD_DICT):
        for lvl in (22, 19, 16, 13, 10, 7, 4, 1):
            try:
                c = ZstdCompressor(
                    level=lvl,
                    dict_data=zstd_dict if method == CM_ZSTD_DICT else None,
                    threads=1
                )
                comp = c.compress(plaintext)
                a = align(len(comp), encryption_method)
                if a <= target_size:
                    if a < target_size:
                        comp = _zstd_add_skippable_padding(comp, target_size - a)
                    return comp
            except Exception:
                pass

        c = ZstdCompressor(
            dict_data=zstd_dict if method == CM_ZSTD_DICT else None,
            threads=1
        )
        return c.compress(plaintext)[:target_size]

def _encrypt_plaintext(
    plaintext: bytes,
    pak_relative_path: PurePath,
    encryption_method: int
) -> bytes:

    if PakCrypto._is_simple1_method(encryption_method):
        return bytes(b ^ SIMPLE1_DECRYPT_KEY for b in plaintext)

    if PakCrypto._is_simple2_method(encryption_method):
        pad = (-len(plaintext)) % SIMPLE2_BLOCK_SIZE
        plaintext += b"\x00" * pad

        key, = struct.unpack("<I", SIMPLE2_DECRYPT_KEY)
        rolling = key
        out = []

        for x, in struct.iter_unpack("<I", plaintext):
            c = rolling ^ x
            out.append(c)
            rolling ^= c

        return struct.pack(f"<{len(out)}I", *out)

    if PakCrypto._is_sm4_method(encryption_method):
        # Derive SM4 key for this specific encryption method
        key = PakCrypto._derive_sm4_key(pak_relative_path, encryption_method)
        sm4 = PakCrypto._sm4_context_for_key(key)

        # Ensure plaintext is 16-byte aligned for SM4
        pad_len = (-len(plaintext)) % 16
        if pad_len > 0:
            plaintext = plaintext + b'\x00' * pad_len

        # Encrypt in 16-byte blocks
        out = bytearray()
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            if len(block) < 16:
                block = block.ljust(16, b'\x00')
            out.extend(sm4.encrypt(block))
        
        return bytes(out)

    return plaintext

def _repack_uncompressed(
    outfh,
    pak_file,
    entry,
    pak_relative_path: PurePath,
    new_data: bytes
):

    enc_method = entry.encryption_method
    target_size = entry.size

    enc_region = (
        PakCrypto.align_encrypted_content_size(target_size, enc_method)
        if entry.encrypted else target_size
    )

    plaintext = new_data[:enc_region]

    if entry.encrypted:
        a = PakCrypto.align_encrypted_content_size(len(plaintext), enc_method)
        plaintext += b"\x00" * (a - len(plaintext))
        cipher = _encrypt_plaintext(plaintext, pak_relative_path, enc_method)

        outfh.seek(entry.offset)
        outfh.write(cipher)

        with open(pak_file._file_path, "rb") as src:
            src.seek(entry.offset + len(cipher))
            outfh.write(src.read(enc_region - len(cipher)))
    else:
        outfh.seek(entry.offset)
        outfh.write(plaintext)

        with open(pak_file._file_path, "rb") as src:
            src.seek(entry.offset + len(plaintext))
            outfh.write(src.read(target_size - len(plaintext)))

def _repack_compressed(
    outfh,
    pak_file,
    entry,
    pak_relative_path,
    new_data,
    repack_dir
):
    blocks = entry.compressed_blocks
    enc_method = entry.encryption_method
    comp_method = entry.compression_method
    
    order = PakCrypto.generate_block_indices(len(blocks), enc_method)
    
    console.print(f"[#FFFF00]REPACK DEBUG:[/#FFFF00]")
    console.print(f"  Original uncompressed: {entry.uncompressed_size:,} bytes")
    console.print(f"  New data size: {len(new_data):,} bytes")
    console.print(f"  Blocks: {len(blocks)}")
    console.print(f"  Total compressed space: {sum(b.end-b.start for b in blocks):,} bytes")
    
    if len(new_data) != entry.uncompressed_size:
        console.print(f"[#FF0055]❌ CRITICAL: New data size mismatch![/#FF0055]")
        if len(new_data) < entry.uncompressed_size:
            new_data = new_data.ljust(entry.uncompressed_size, b'\x00')
        else:
            new_data = new_data[:entry.uncompressed_size]
    
    # ================= MULTI BLOCK =================
    if len(blocks) > 1:
        block_sizes = [blk.end - blk.start for blk in blocks]
        total_block_size = sum(block_sizes)
        
        if entry.compression_block_size > 0:
            chunk_size = entry.compression_block_size
        else:
            avg_block_size = sum(block_sizes) / len(block_sizes)
            avg_compression_ratio = total_block_size / entry.uncompressed_size
            chunk_size = int(avg_block_size / avg_compression_ratio) if avg_compression_ratio > 0 else 65536
        
        ptr = 0
        processed_blocks = 0
        skipped_blocks = 0
        
        for logical_i, phys_i in enumerate(order):
            blk = blocks[phys_i]
            target_size = blk.end - blk.start
            
            chunk_len = min(chunk_size, len(new_data) - ptr)
            if chunk_len <= 0:
                break
            
            chunk = new_data[ptr:ptr + chunk_len]
            ptr += chunk_len
            
            with open(pak_file._file_path, "rb") as src:
                src.seek(blk.start)
                original_compressed = src.read(target_size)
            
            compressed_ok = False
            new_compressed = None
            
            # ---------- FIXED PART (ZSDic + Mini safe) ----------
            if comp_method == CM_ZSTD:
                zstd_dict = None
            elif comp_method == CM_ZSTD_DICT:
                zstd_dict = pak_file._zstd_dict
            else:
                zstd_dict = None
            
            if comp_method in (CM_ZSTD, CM_ZSTD_DICT):
                for level in [22, 19, 16, 13, 10, 7, 4, 1]:
                    try:
                        c = ZstdCompressor(level=level, dict_data=zstd_dict, threads=1)
                        new_compressed = c.compress(chunk)
                        if len(new_compressed) <= target_size:
                            compressed_ok = True
                            break
                    except:
                        continue
            
            elif comp_method == CM_ZLIB:
                new_compressed = zlib.compress(chunk, zlib.Z_BEST_COMPRESSION)
                if len(new_compressed) <= target_size:
                    compressed_ok = True
            # -------------------------------
            
            if not compressed_ok:
                outfh.seek(blk.start)
                outfh.write(original_compressed)
                skipped_blocks += 1
                continue
            
            if entry.encrypted:
                if PakCrypto._is_sm4_method(enc_method):
                    pad_len = (-len(new_compressed)) % 16
                    if pad_len > 0:
                        new_compressed += b'\x00' * pad_len
                new_compressed = _encrypt_plaintext(new_compressed, pak_relative_path, enc_method)
            
            if len(new_compressed) > target_size:
                outfh.seek(blk.start)
                outfh.write(original_compressed)
                skipped_blocks += 1
                continue
            
            outfh.seek(blk.start)
            outfh.write(new_compressed)
            if len(new_compressed) < target_size:
                outfh.write(b'\x00' * (target_size - len(new_compressed)))
            
            processed_blocks += 1
        
        if ptr < len(new_data):
            console.print("[#FF0055]❌ Data alignment error, stopping[/#FF0055]")
            return False
    
    # ================= SINGLE BLOCK =================
    else:
        blk = blocks[0]
        target_size = blk.end - blk.start
        
        with open(pak_file._file_path, "rb") as src:
            src.seek(blk.start)
            original_compressed = src.read(target_size)
        
        compressed_ok = False
        new_compressed = None
        
        # ---------- FIXED PART (ZSDic + Mini safe) ----------
        if comp_method == CM_ZSTD:
            zstd_dict = None
        elif comp_method == CM_ZSTD_DICT:
            zstd_dict = pak_file._zstd_dict
        else:
            zstd_dict = None
        
        if comp_method in (CM_ZSTD, CM_ZSTD_DICT):
            for level in [22, 19, 16, 13, 10, 7, 4, 1]:
                try:
                    c = ZstdCompressor(level=level, dict_data=zstd_dict, threads=1)
                    new_compressed = c.compress(new_data)
                    if len(new_compressed) <= target_size:
                        compressed_ok = True
                        break
                except:
                    continue
        
        elif comp_method == CM_ZLIB:
            new_compressed = zlib.compress(new_data, zlib.Z_BEST_COMPRESSION)
            if len(new_compressed) <= target_size:
                compressed_ok = True
        # -------------------------------
        
        if not compressed_ok:
            outfh.seek(blk.start)
            outfh.write(original_compressed)
            return True
        
        if entry.encrypted:
            if PakCrypto._is_sm4_method(enc_method):
                pad_len = (-len(new_compressed)) % 16
                if pad_len > 0:
                    new_compressed += b'\x00' * pad_len
            new_compressed = _encrypt_plaintext(new_compressed, pak_relative_path, enc_method)
        
        if len(new_compressed) > target_size:
            outfh.seek(blk.start)
            outfh.write(original_compressed)
            return True
        
        outfh.seek(blk.start)
        outfh.write(new_compressed)
        if len(new_compressed) < target_size:
            outfh.write(b'\x00' * (target_size - len(new_compressed)))
    
    return True
    # ===== END ZSTD_DICT MULTI-BLOCK CHUNK MODE =====


def _build_pak_filename_map(pak_file):
    """
    Build safe filename → full pak path map
    """
    name_map = {}

    for dir_path, files in pak_file._index.items():
        for name in files.keys():
            full = str(PurePath(dir_path) / name).replace("\\", "/")
            stem = Path(name).stem.lower()
            ext = Path(name).suffix.lower()

            key1 = name.lower()                 # exact filename
            key2 = f"{stem}{ext}"               # normalized
            key3 = stem                          # stem only

            for k in (key1, key2, key3):
                name_map.setdefault(k, []).append(full)

    return name_map
    
def detect_repack_mode(pak_path: Path) -> str:
    name = pak_path.name.lower()

    if name == "mini_obb.pak":
        return "MINI_OBB"

    if "zsdic" in name:
        return "OBBZSDIC"

    # Fix: "game" ya "patch" dono check karo
    if "game" in name or "patch" in name:
        return "GAMEPATCH"

    return "OBBZSDIC"

def smart_resolve_by_fingerprint(
    filename: str,
    repack_file: Path,
    candidates: list
):
    """
    Resolve ambiguous pak entries using structural fingerprint matching.
    Returns (full_path, entry) or None.
    """

    repack_size = repack_file.stat().st_size

    # ---- Level 1: uncompressed size ----
    size_matches = [
        (path, entry)
        for path, entry in candidates
        if entry.uncompressed_size == repack_size
    ]

    if len(size_matches) == 1:
        return size_matches[0]

    if not size_matches:
        return None

    # ---- Level 2: structural fingerprint ----
    def fingerprint(e):
        return (
            e.uncompressed_size,
            e.compression_method,
            e.encryption_method,
            len(e.compressed_blocks),
            e.compression_block_size
        )

    base_fp = fingerprint(size_matches[0][1])

    final_matches = [
        (path, entry)
        for path, entry in size_matches
        if fingerprint(entry) == base_fp
    ]

    if len(final_matches) == 1:
        return final_matches[0]

    return None

def repack_pak_file_fileA_style(
    pak_file,
    edited_root: Path,
    output_path: Path
):
    """
    SAFE FILE-A REPACK (FIXED VERSION)
    • NO FORCE matching
    • Exact extension matching for .uasset/.uexp
    • Strict validation
    """

    shutil.copy2(pak_file._file_path, output_path)
    
    # Build filename map (like version 4.1)
    pak_name_map = {}
    for dir_path, files in pak_file._index.items():
        for name, entry in files.items():
            full_path = str(PurePath(dir_path) / name).replace("\\", "/")
            # Use lowercase filename as key (extension included)
            key = name.lower()
            pak_name_map.setdefault(key, []).append((full_path, entry))
    
    edited = {}
    skipped_files = []
    
    console.print(f"[#00CCFF]🔍 Matching files from {edited_root}...[/#00CCFF]")
    
    # First pass: Exact filename matches (case-insensitive)
    for p in edited_root.rglob("*"):
        if not p.is_file():
            continue
        
        fname_lower = p.name.lower()
        
        if fname_lower in pak_name_map:
            candidates = pak_name_map[fname_lower]
            
            if len(candidates) == 1:
                # Perfect match
                full_path, entry = candidates[0]
                edited[full_path] = (p, entry)
                console.print(f"[#00FF88]✓ Match: {p.name} → {full_path}[/#00FF88]")
            else:
                # Try SMART fingerprint resolution
                resolved = smart_resolve_by_fingerprint(
                    filename=p.name,
                    repack_file=p,
                    candidates=candidates
                )

                if resolved:
                    full_path, entry = resolved
                    edited[full_path] = (p, entry)
                    console.print(
                        f"[#00FF88]✓ Smart-matched: {p.name} → {full_path}[/#00FF88]"
                    )
                else:
                    console.print(f"[#FFAA00]⚠ Multiple matches for {p.name}:[/#FFAA00]")
                    for cand_path, _ in candidates:
                        console.print(f"    - {cand_path}")
                    skipped_files.append(p.name)
        else:
            # Check for .uasset/.uexp pairs with same stem
            stem = p.stem.lower()
            ext = p.suffix.lower()
            
            # Look for files with same stem AND same extension
            potential_matches = []
            for dir_path, files in pak_file._index.items():
                for name, entry in files.items():
                    if (Path(name).stem.lower() == stem and 
                        Path(name).suffix.lower() == ext):
                        full_path = str(PurePath(dir_path) / name).replace("\\", "/")
                        potential_matches.append((full_path, entry))
            
            if len(potential_matches) == 1:
                full_path, entry = potential_matches[0]
                edited[full_path] = (p, entry)
                console.print(f"[#00FF88]✓ Stem+Ext Match: {p.name} → {full_path}[/#00FF88]")
            elif len(potential_matches) > 1:
                console.print(f"[#FF0055]✗ Multiple stem matches for {p.name}:[/#FF0055]")
                for cand_path, _ in potential_matches:
                    console.print(f"    - {cand_path}")
                skipped_files.append(p.name)
            else:
                console.print(f"[#FF0055]✗ No match found for {p.name}[/#FF0055]")
                skipped_files.append(p.name)
    
    # Show summary
    console.print("\n[bold #00FFFF]📊 Matching Summary:[/bold #00FFFF]")
    console.print(f"[#00FF88]✓ Files matched: {len(edited)}[/#00FF88]")
    if skipped_files:
        console.print(f"[#FFAA00]⚠ Files skipped: {len(skipped_files)}[/#FFAA00]")
        for fname in skipped_files[:10]:  # Show first 10
            console.print(f"    - {fname}")
        if len(skipped_files) > 10:
            console.print(f"    ... and {len(skipped_files) - 10} more")
    
    if not edited:
        console.print("[bold #FF0055]❌ No files to repack![/bold #FF0055]")
        return
    
    # Confirm with user
    confirm = 'y'
    if confirm != 'y':
        console.print("[#FFAA00]Repack cancelled by user.[/#FFAA00]")
        return
    
    # Proceed with repacking
    with open(output_path, "r+b") as outfh:
        for full_path, (p, entry) in edited.items():
            console.print(
                f"[#FFFF00][REPACK][/#FFFF00] {full_path} | "
                f"Compression: {entry.compression_method} | "
                f"Encryption: {entry.encryption_method} | "
                f"Blocks: {len(entry.compressed_blocks)}"
            )
            debug_entry_info(entry)
            new_data = p.read_bytes()
            pak_rel = PurePath(full_path)
            
            if entry.compression_method == CM_NONE:
                _repack_uncompressed(outfh, pak_file, entry, pak_rel, new_data)
            else:
                success = _repack_compressed(outfh, pak_file, entry, pak_rel, new_data, edited_root)
                if not success:
                    console.print(f"[#FF0055]❌ FAILED to repack {full_path}. File may be corrupted![/#FF0055]")
                    # Optionally: restore original file and abort
                
    console.print(f"[bold #00FF88]✅ Repack completed! {len(edited)} file(s) replaced.[/bold #00FF88]")

# ========== REPACK MODE WRAPPERS ==========
def repack_mini_obb(pak, repack_dir, output_pak):
    console.print("[bold #00FFFF]🧩 Repack Mode: MINI_OBB[/bold #00FFFF]")

    # Safety: ensure no dict logic
    pak._is_zstd_with_dict = False
    pak._zstd_dict = None

    repack_pak_file_fileA_style(
        pak_file=pak,
        edited_root=repack_dir,
        output_path=output_pak
    )

def repack_obbzsdic(pak, repack_dir, output_pak):
    console.print("[bold #00FFFF]🧩 Repack Mode: OBBZSDIC[/bold #00FFFF]")

    repack_pak_file_fileA_style(
        pak_file=pak,
        edited_root=repack_dir,
        output_path=output_pak
    )

def repack_gamepatch(pak, repack_dir, output_pak):
    console.print("[bold #00FFFF]🧩 Repack Mode: GAMEPATCH[/bold #00FFFF]")

    pak._is_zstd_with_dict = False
    pak._zstd_dict = None

    repack_pak_file_fileA_style(
        pak_file=pak,
        edited_root=repack_dir,
        output_path=output_pak
    )
# ========== UTILITY FUNCTIONS ==========
def print_banner():
    """Print Cyberpunk styled banner"""
    os.system('cls' if os.name == 'nt' else 'clear')
    banner = r"""
def print_banner():

░██████╗░█████╗░███╗░░░███╗███████╗███████╗██████╗░
██╔════╝██╔══██╗████╗░████║██╔════╝██╔════╝██╔══██╗
╚█████╗░███████║██╔████╔██║█████╗░░███████╗██████╔╝
░╚═══██╗██╔══██║██║╚██╔╝██║██╔══╝░░██╔══╝░░██╔══██╗
██████╔╝██║░░██║██║░╚═╝░██║███████╗███████╗██║░░██║
╚═════╝░╚═╝░░╚═╝╚═╝░░░░░╚═╝╚══════╝╚══════╝╚═╝░░╚═╝
  ✦ ────────────────────────────────────────── ✦
  • Update-By     : GRW official (@GRW_XD)  │
  • Platform       : BGMI|PUBG|KR|TW|JP|VNG    │
  • Tool Version  : [bold #FF00FF]4.3[/bold #FF00FF]                        │
  ✦ ────────────────────────────────────────── ✦
    """
    console.print(banner, style="#00FFFF")
    print()
from typing import List

def detect_pak_files(base_path: Path) -> List[Path]:
    """Detect all .pak files in the specific Download directory"""
    base_path = Path("/storage/emulated/0/Download/GRW_BRAND OBB TOOL")
    
    pak_files = list(base_path.glob("*.pak"))
    pak_files.extend(base_path.glob("*.obb"))
    return sorted(pak_files, key=lambda x: x.name)


tool_path = Path("/storage/emulated/0/Download/GRW_BRAND OBB TOOL")
tool_path.mkdir(parents=True, exist_ok=True)

def safe_input(prompt: str = "") -> str:
    """Safe input function that works with redirected stdin"""
    try:
        return input(prompt)
    except (EOFError, RuntimeError):
        try:
            if sys.platform != "win32":
                with open("/dev/tty", "r") as tty:
                    sys.stderr.write(prompt)
                    sys.stderr.flush()
                    return tty.readline().rstrip("\n")
            else:
                with open("CON", "r") as con:
                    sys.stderr.write(prompt)
                    sys.stderr.flush()
                    return con.readline().rstrip("\r\n")
        except Exception:
            return ""

def human_size(size: int) -> str:
    """Convert bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"

def clear_folders(base_path: Path) -> None:
    """Clear all unpack/repack folders"""
    with Progress() as progress:
        task = progress.add_task("[#00CCFF]Cleaning folders...", total=1)
        
        count = 0
        for item in base_path.iterdir():
            if item.is_dir() and (item.name.startswith("GRW_BRANDxUnpack_") or item.name.startswith("GRW_BRANDxRepack_")):
                try:
                    shutil.rmtree(item)
                    console.print(f"[#00FF88]✓ Cleared: {item.name}[/#00FF88]")
                    count += 1
                except Exception as e:
                    console.print(f"[#FF0055]✗ Error clearing {item.name}: {escape(str(e))}[/#FF0055]")
        
        progress.update(task, completed=1)
        
        if count > 0:
            console.print(f"[#00FF88]✓ Successfully cleared {count} folder(s)[/#00FF88]")
        else:
            console.print("[#FFAA00]⚠ No folders to clear[/#FFAA00]")

# ========== MAIN MENU ==========
def main_menu():
    """Main menu interface with Cyberpunk theme"""
    if getattr(sys, 'frozen', False):
        base_path = Path(sys.executable).parent
    else:
        base_path = Path(__file__).parent

    while True:
        print_banner()
        
        # Detect .pak files
        pak_files = detect_pak_files(base_path)
        
        if not pak_files:
            console.print("[bold #FF0055]⚠  No .pak/.obb files found in the current directory![/bold #FF0055]")
            console.print("[#FFAA00]Please place .pak/.obb files in the same directory as this tool.[/#FFAA00]")
            safe_input("\nPress Enter to continue...")
            continue
            
        console.print(f"[bold #00FFFF]📁 Found {len(pak_files)} .pak/.obb file(s):[/bold #00FFFF]")
        console.print("─" * 60, style="#666699")
        
        for i, pak_file in enumerate(pak_files, 1):
            file_size = pak_file.stat().st_size
            size_mb = file_size / (1024 * 1024)
            console.print(f"[#00CCFF]{i:2}. {pak_file.name}[/#00CCFF] [#FFFF00]({size_mb:.2f} MB)[/#FFFF00]")
        
        console.print("─" * 60, style="#666699")
        console.print("\n[bold #00FF88]OPTIONS:[/bold #00FF88]")
        console.print("[#00FF00]1. 📂 UNPAK - Extract .pak file[/#00FF00]")
        console.print("[#00FFFF]2. 🔧 REPAK - Rebuild .pak file[/#00FFFF]") 
        console.print("[#00FF00]3. 🤖 Auto Tool - Menu file[/#00FF00]") 
        console.print("[#FF0055]4. 🗑️  CLEAR - Remove all Unpack/Repack folders[/#FF0055]")
        console.print("[#FFFF00]0. 🚪 EXIT - Close the tool[/#FFFF00]")
        console.print("─" * 60, style="#666699")
        
        choice = safe_input(f"Enter your choice (0-3):").strip()
        
        if choice == '1':
            # Unpack selected .pak file
            if len(pak_files) == 1:
                selected_pak = pak_files[0]
            else:
                file_choice = safe_input(f"Select .pak file (1-{len(pak_files)}): ").strip()
                try:
                    index = int(file_choice) - 1
                    if 0 <= index < len(pak_files):
                        selected_pak = pak_files[index]
                    else:
                        console.print("[bold #FF0055]❌ Invalid selection![/bold #FF0055]")
                        time.sleep(2)
                        continue
                except ValueError:
                    console.print("[bold #FF0055]❌ Invalid input! Please enter a number.[/bold #FF0055]")
                    time.sleep(2)
                    continue
            base_path = Path("/storage/emulated/0/Download/GRW_BRAND OBB TOOL")
            pak_name = selected_pak.stem
            unpack_path = base_path / f"GRW_BRANDxUnpack_{pak_name}"
            repack_path = base_path / f"GRW_BRANDxRepack_{pak_name}"
            
            with Progress() as progress:
                task = progress.add_task(f"[#00CCFF]Creating directories...", total=1)
                unpack_path.mkdir(exist_ok=True)
                repack_path.mkdir(exist_ok=True)
                progress.update(task, completed=1)
            
            try:
                console.print(f"[bold #00FFFF]🚀 Unpacking {selected_pak.name}...[/bold #00FFFF]")
                
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    console=console
                ) as progress:
                    task = progress.add_task(f"Processing {selected_pak.name}", total=100)
                    
                    pak = TencentPakFile(selected_pak)
                    progress.update(task, advance=30)
                    
                    pak.dump(unpack_path)
                    progress.update(task, advance=40)
                    
                    # ✅ SAVE LOG IN UNPACK DIRECTORY
                    log_path = unpack_path / f"GRW_BRANDxDebug_{pak_name}.log"
                    dump_unpacking_log(pak, log_path)
                    progress.update(task, advance=20)
                    
                    progress.update(task, completed=100)
                
                console.print("[bold #00FF88]✅ UNPACK COMPLETED![/bold #00FF88]")
                console.print(f"[#00CCFF]📁 Unpacked to: {unpack_path}[/#00CCFF]")
                console.print(f"[#00CCFF]🔧 Repack folder: {repack_path}[/#00CCFF]")
                console.print(f"[#00CCFF]📝 Debug log saved in unpack folder[/#00CCFF]")
                
                # Show file count
                file_count = sum(len(files) for _, files in pak._index.items())
                console.print(f"[#FFFF00]📄 Total files extracted: {file_count}[/#FFFF00]")
                
            except Exception as e:
                console.print(f"[bold #FF0055]❌ Error unpacking:[/bold #FF0055] {escape(str(e))}")
                import traceback
                traceback.print_exc()
                
            safe_input("\nPress Enter to continue...")
        elif choice == '2':
            # Repack selected .pak file
            if len(pak_files) == 1:
                selected_pak = pak_files[0]
            else:
                file_choice = safe_input(f"Select .pak file (1-{len(pak_files)}): ").strip()
                try:
                    index = int(file_choice) - 1
                    if 0 <= index < len(pak_files):
                        selected_pak = pak_files[index]
                    else:
                        console.print("[bold #FF0055]❌ Invalid selection![/bold #FF0055]")
                        time.sleep(2)
                        continue
                except ValueError:
                    console.print("[bold #FF0055]❌ Invalid input! Please enter a number.[/bold #FF0055]")
                    time.sleep(2)
                    continue
            base_path = Path("/storage/emulated/0/Download/GRW_BRAND OBB TOOL")
            pak_name = selected_pak.stem
            repack_dir = base_path / f"GRW_BRANDxRepack_{pak_name}"
            
            if not repack_dir.exists():
                console.print(f"[bold #FF0055]❌ ERROR: {repack_dir} not found.[/bold #FF0055]")
                console.print("[#FFAA00]⚠  Please unpack the .pak file first using option 1.[/#FFAA00]")
                safe_input("\nPress Enter to continue...")
                continue
                
            try:
                console.print(f"[bold #00FFFF]🚀 Repacking {selected_pak.name}...[/bold #00FFFF]")
                
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    console=console
                ) as progress:
                    task = progress.add_task(f"Repacking {selected_pak.name}", total=100)
                    
                    pak = TencentPakFile(selected_pak)
                    progress.update(task, advance=20)

                    output_pak = selected_pak.with_suffix(".repacked")

                    mode = detect_repack_mode(selected_pak)

                    if mode == "MINI_OBB":
                          repack_mini_obb(pak, repack_dir, output_pak)
                    elif mode == "GAMEPATCH": 
                          repack_gamepatch(pak, repack_dir, output_pak)
                    else:  
                          repack_obbzsdic(pak, repack_dir, output_pak)

                    progress.update(task, advance=50)
    
                    # Safety check
                    if output_pak.stat().st_size != selected_pak.stat().st_size:
                        raise ValueError("Repack size mismatch! Aborting to prevent corruption.")
                    
                    selected_pak.unlink()
                    output_pak.rename(selected_pak)
                    progress.update(task, completed=100)
                
                console.print("[bold #00FF88]✅ REPACK COMPLETED SUCCESSFULLY![/bold #00FF88]")
                console.print(f"[#00CCFF]📦 Original file replaced with repacked version[/#00CCFF]")
                
                # Show file count
                file_count = sum(len(files) for _, files in pak._index.items())
                console.print(f"[#FFFF00]📄 Total files in pak: {file_count}[/#FFFF00]")
                
            except Exception as e:
                console.print(f"[bold #FF0055]❌ Repack failed:[/bold #FF0055] {e}")
                import traceback
                traceback.print_exc()
                
            safe_input("\nPress Enter to continue...")
        elif choice == '3':
            MainMenu()
            safe_input("\nPress Enter to continue...")
        elif choice == '4':
            # Clear all unpack/repack folders
            console.print("[bold #FFFF00]⚠  WARNING: This will delete all GRW_BRANDxUnpack_* and GRW_BRANDxRepack_* folders[/bold #FFFF00]")
            confirm = safe_input("Are you sure? (y/N): ").strip().lower()
            
            if confirm == 'y':
                clear_folders(base_path)
            else:
                console.print("[#FFAA00]Operation cancelled.[/#FFAA00]")
            
            safe_input("\nPress Enter to continue...")
            
        elif choice == '0':
            console.print("[bold #FFFF00]\n👋 Allah Hafiz... Thanks for Using This Tool![/bold #FFFF00]")
            time.sleep(2)
            break
            
        else:
            console.print("[bold #FF0055]❌ Invalid choice! Please enter 0, 1, 2, or 3.[/bold #FF0055]")
            time.sleep(2)

LOG_FILE = "log.txt"
FOLDER = Path("/storage/emulated/0/Download/GRW_BRAND OBB TOOL/GRW_BRAND AUTO")
FOLDER.mkdir(parents=True, exist_ok=True)

def log(msg):
    print(msg)
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")

def replace_anchor_itself(content, anchor_val, replace_val):
    anchor_bytes = struct.pack('f', anchor_val)
    replace_bytes = struct.pack('f', replace_val)

    pos = content.find(anchor_bytes)
    if pos == -1:
        return False

    content[pos:pos+4] = replace_bytes
    return True


def replace_after_all_anchors(content, anchor_val, search_val, replace_val, name):
    anchor_bytes = struct.pack('f', anchor_val)
    search_bytes = struct.pack('f', search_val)
    replace_bytes = struct.pack('f', replace_val)

    start = 0
    count = 0

    while True:
        anchor_pos = content.find(anchor_bytes, start)
        if anchor_pos == -1:
            break

        val_pos = content.find(search_bytes, anchor_pos + 4)
        if val_pos != -1:
            content[val_pos:val_pos+4] = replace_bytes
            log(f"{name} replaced after SPEED {anchor_val} at 0x{val_pos:x}")
            count += 1

        start = anchor_pos + 4

    if count == 0:
        log(f"{name} NOT replaced (no anchors)")
    return count > 0


def search_file_in_directory(file_name, directory="/storage/emulated/0/Download/GRW_BRAND OBB TOOL/GRW_BRAND AUTO"):
    if not os.path.exists(directory):
        return None
    for root, _, files in os.walk(directory):
        if file_name in files:
            return os.path.join(root, file_name)
    return None

# ---------------- INPUT ----------------

def aim_bot_modification():
    speed = float(input("Please write your Speed value (Inner + Outer): "))
    values = [
        float(input("RangeRate: ")),
        float(input("SpeedRate: ")),
        float(input("RangeRateSight: ")),
        float(input("SpeedRateSight: ")),
        float(input("CrouchRate: ")),
        float(input("ProneRate: "))
    ]
    return speed, values

# ---------------- MAIN ----------------

def AimMenu():
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)

    target = search_file_in_directory("BP_ShootWeaponBase.uexp")
    if not target:
        print("Target file not found")
        return

    with open(target, "rb") as f:
        content = bytearray(f.read())

    speed, values = aim_bot_modification()

    # ✅ SPEED LOCK
    replace_anchor_itself(content, 3.5, speed)
    replace_anchor_itself(content, 2.5, speed)

    log(f"SPEED_LOCKED = {speed}")

    # ✅ use SPEED as anchor now
    defaults = [1.0, 1.0, 1.0, 1.0, 0.5, 0.1]
    names = [
        "RangeRate",
        "SpeedRate",
        "RangeRateSight",
        "SpeedRateSight",
        "CrouchRate",
        "ProneRate"
    ]

    for i in range(6):
        replace_after_all_anchors(
            content,
            speed,
            defaults[i],
            values[i],
            names[i]
        )

    with open(target, "wb") as f:
        f.write(content)

    print("\nDONE. log.txt check karo.")

def SmallCross():

    if not os.path.exists(FOLDER):
        print("❌ FOLDER GRW_MOD not found!")
        return

    target_values = [3.36, 1.09375]
    target_bytes = [struct.pack("<f", v) for v in target_values]

    # Sirf ek file assume kar raha hoon FOLDER me
    files = os.listdir(FOLDER)

    if len(files) == 0:
        print("❌ GRW_MOD FOLDER empty!")
        return

    file_path = os.path.join(FOLDER, files[0])

    with open(file_path, "rb") as f:
        data = f.read()

    found = False
    for tb in target_bytes:
        if tb in data:
            found = True

    if not found:
        print("❌ Values not found in file.")
        return

    try:
        new_val = float(input("Please Write Your Value Under (1.0) : "))
    except:
        print("❌ Invalid number.")
        return

    if not (0 < new_val < 1.0):
        print("❌ Value must be between 0 and 1.")
        return

    new_bytes = struct.pack("<f", new_val)

    for tb in target_bytes:
        data = data.replace(tb, new_bytes)

    with open(file_path, "wb") as f:
        f.write(data)

    print(f"Small Crosshair Done.. ✅")


def LessR():

    if not os.path.exists(FOLDER):
        print("❌ FOLDER GRW_MOD not found!")
        return

    target_values = [0.52, 0.65, 0.9]
    target_bytes = [struct.pack("<f", v) for v in target_values]

    # Sirf ek file assume kar raha hoon FOLDER me
    files = os.listdir(FOLDER)

    if len(files) == 0:
        print("❌ GRW_MOD FOLDER empty!")
        return

    file_path = os.path.join(FOLDER, files[0])

    with open(file_path, "rb") as f:
        data = f.read()

    found = False
    for tb in target_bytes:
        if tb in data:
            found = True

    if not found:
        print("❌ Values not found in file.")
        return

    try:
        new_val = float(input("Please Write Your Value Under (1.0) : "))
    except:
        print("❌ Invalid number.")
        return

    if not (0 < new_val < 1.0):
        print("❌ Value must be between 0 and 1.")
        return

    new_bytes = struct.pack("<f", new_val)

    for tb in target_bytes:
        data = data.replace(tb, new_bytes)

    with open(file_path, "wb") as f:
        f.write(data)

    print(f"Less Recoil Done.. ✅")

def FastS():
    if not os.path.exists(FOLDER):
        print("❌ FOLDER GRW_MOD not found!")
        return

    target_values = [0.65, 0.7]
    target_bytes = [struct.pack("<f", v) for v in target_values]

    # Sirf ek file assume kar raha hoon FOLDER me
    files = os.listdir(FOLDER)

    if len(files) == 0:
        print("❌ GRW_MOD FOLDER empty!")
        return

    file_path = os.path.join(FOLDER, files[0])

    with open(file_path, "rb") as f:
        data = f.read()

    found = False
    for tb in target_bytes:
        if tb in data:
            found = True

    if not found:
        print("❌ Values not found in file.")
        return

    try:
        new_val = float(input("Please Write Your Value Under (1.0) : "))
    except:
        print("❌ Invalid number.")
        return

    if not (0 < new_val < 1.0):
        print("❌ Value must be between 0 and 1.")
        return

    new_bytes = struct.pack("<f", new_val)

    for tb in target_bytes:
        data = data.replace(tb, new_bytes)

    with open(file_path, "wb") as f:
        f.write(data)

    print(f"Fast Switch Done.. ✅")

import os
import struct
import shutil

# Given values (order matters – search next)
TARGET_VALUES = [
    (35.0, 33.0, 69.5),   # 16th
    (23.0, 25.0, 30.5),   # 17th
    (15.0, 30.0, 30.0),   # 21th
    (15.0, 30.0, 30.0),   # 22th
    (40.0, 33.0, 69.5),   # 24th
]

def f2b(val):
    return struct.pack("<f", val)


def find_file(directory):
    MAGIC_TEXT = "5Bѿ8".encode("utf-8")  # STRING → bytes (TEXT search)

    for root, _, files in os.walk(directory):
        for f in files:
            path = os.path.join(root, f)
            with open(path, "rb") as fp:
                data = fp.read()

                # TEXT string check (MANDATORY)
                if MAGIC_TEXT not in data:
                    continue

                # Phir X float values check (single precision)
                for x, _, _ in TARGET_VALUES:
                    if f2b(x) in data:
                        return path
    return None


def apply_modification(file_path, new_x, new_yz):
    with open(file_path, "rb") as f:
        data = bytearray(f.read())

    offset = 0
    for x, y, z in TARGET_VALUES:
        # X (search next)
        x_bytes = f2b(x)
        pos = data.find(x_bytes, offset)
        if pos == -1:
            print("❌ X value not found:", x)
            return

        data[pos:pos+4] = f2b(new_x)
        offset = pos + 4

        # Y
        y_pos = data.find(f2b(y), offset)
        if y_pos != -1:
            data[y_pos:y_pos+4] = f2b(new_yz)

        # Z
        z_pos = data.find(f2b(z), y_pos + 4)
        if z_pos != -1:
            data[z_pos:z_pos+4] = f2b(new_yz)

    with open(file_path, "wb") as f:
        f.write(data)

    print("✅ Modification applied successfully")


def magic():
    target_file = find_file(FOLDER)

    if not target_file:
        print("ℹ️ File not found in FOLDER, searching FOLDER...")
        unpack_file = find_file(FOLDER)

        if not unpack_file:
            print("❌ Target file not found anywhere")
            return

        os.makedirs(FOLDER, exist_ok=True)
        target_file = os.path.join(FOLDER, os.path.basename(unpack_file))
        shutil.copy(unpack_file, target_file)
        print("📁 File copied to FOLDER")

    print("🎯 Target file:", target_file)

    new_x = float(input("Please type your X value : "))
    new_yz = float(input("Please type your Y-Z value: "))

    apply_modification(target_file, new_x, new_yz)

def find_any_file():
    for file in os.listdir(FOLDER):
        path = os.path.join(FOLDER, file)
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                if "SM-S928W" in content:
                    return path
    return None

def get_model_from_line(line, target_len):
    for part in re.findall(r"[A-Za-z0-9\- ]+", line):
        if len(part) == target_len:
            return part
    return None

def replace_model(file_path, user_model):

    user_bytes = user_model.encode("utf-8")
    user_len = len(user_bytes)

    with open(file_path, "rb") as f:
        data = f.read()

    replaced_model = None
    found_index = -1

    # file میں same-length text ڈھونڈیں
    import re
    for match in re.finditer(rb"[A-Za-z0-9\- ]+", data):
        token = match.group(0)

        if len(token) == user_len:
            replaced_model = token.decode("utf-8", errors="ignore")
            found_index = match.start()
            break   # صرف پہلا match

    if found_index == -1:
        return None

    # 🔥 PURE OVERWRITE (insert نہیں)
    new_data = (
        data[:found_index]
        + user_bytes
        + data[found_index + user_len :]
    )

    with open(file_path, "wb") as f:
        f.write(new_data)

    return replaced_model


def FPS():
    print("Searching any file inside FOLDER...")
    src_file = find_any_file()
    if not src_file:
        print("❌ No file found inside FOLDER!")
        return
    file_name = os.path.basename(src_file)
    dst_file = os.path.join(FOLDER, file_name)

    
    user_model = input("Please write your model number: ").strip()
    replaced = replace_model(dst_file, user_model)
    if replaced:
        print("\n-------------------------------------")
        print("✔ Modification Done!")
        print("Original Model Found :", replaced)
        print("New Model Placed     :", user_model)
        print("-------------------------------------\n")
    else:
        print("❌ No matching-length model found to replace!")
        
def FPS1():
    print("Please paste here your all user name :-")
    raw_input_data = input().strip()

    # Split multiple user models by comma
    all_models = [m.strip() for m in raw_input_data.split(",") if m.strip()]

    if not all_models:
        print("❌ No valid model names provided!")
        return

    for user_model in all_models:
        print(f"\n----- Processing Model: {user_model} -----")

        # STEP 1: Find file in FOLDER
        src_file = find_any_file()
        if not src_file:
            print("❌ No file found inside FOLDER!")
            return

        # Prepare FOLDER copy destination
        file_name = os.path.basename(src_file)
        dst_file = os.path.join(FOLDER, file_name)

        # Copy file again for each model
        shutil.copy2(src_file, dst_file)
        print("✔ File copied to FOLDER:", dst_file)

        # Perform replacement on copied file
        replaced = replace_model(dst_file, user_model)

        if replaced:
            print("----------------------------------------")
            print("✔ Replacement Done!")
            print("Original Model Found :", replaced)
            print("New Model Placed     :", user_model)
            print("----------------------------------------")
        else:
            print("❌ No matching-length model found for:", user_model)

def headshot_auto_make():
    print("Wait HeadShot Making in Progress......")

    all_files = sorted(os.listdir(FOLDER))
    os.makedirs(FOLDER, exist_ok=True)

    i = 0
    while i < len(all_files):
        file_name = all_files[i]
        source_file = os.path.join(FOLDER, file_name)

        if not os.path.isfile(source_file):
            i += 1
            continue

        size = os.path.getsize(source_file)

        # ✅ Only start merging when 64KB block with target strings is found
        if size == 64 * 1024:
            with open(source_file, "rb") as f:
                data = f.read()

            if b"BigBody" in data and b"/Game/Arts/PhysicalMaterial/PhysicalMaterial_Flesh" in data:
                # Merge continuous 64KB + next non-64KB
                merge_files = [file_name]
                j = i + 1
                while j < len(all_files):
                    next_file = os.path.join(FOLDER, all_files[j])
                    if not os.path.isfile(next_file):
                        break
                    next_size = os.path.getsize(next_file)
                    merge_files.append(all_files[j])
                    j += 1
                    if next_size != 64 * 1024:
                        break

                # Read + merge
                merged_data = bytearray()
                sizes = []
                for fname in merge_files:
                    with open(os.path.join(FOLDER, fname), "rb") as f:
                        chunk = f.read()
                    sizes.append(len(chunk))
                    merged_data.extend(chunk)

                # ✅ Apply patch on merged data
                replacement_map = {
                    b"EAvatarDamagePosition::BigBody": b"EAvatarDamagePosition::BigHead",
                    b"EAvatarDamagePosition::BigFoot": b"EAvatarDamagePosition::BigHead",
                    b"EAvatarDamagePosition::BigHand": b"EAvatarDamagePosition::BigHead",
                    b"EAvatarDamagePosition::BigLimbs": b"EAvatarDamagePosition::BigHead",
                    b"spine_01": b"spine_03",
                    b"spine_02": b"spine_03"
                }

                modified = False
                for target, replacement in replacement_map.items():
                    start = 0
                    while True:
                        idx = merged_data.find(target, start)
                        if idx == -1:
                            break
                        modified = True
                        if len(replacement) < len(target):
                            padded = replacement + b'\x00' * (len(target) - len(replacement))
                        elif len(replacement) > len(target):
                            padded = replacement[:len(target)]
                        else:
                            padded = replacement
                        merged_data[idx:idx + len(target)] = padded
                        if target == b"EAvatarDamagePosition::BigLimbs":
                            pos_s = idx + len(target) - 1
                            merged_data[pos_s] = 0x00
                        start = idx + len(target)

                # ✅ Only write if actual modification happened
                if modified:
                    offset = 0
                    for fname, fsize in zip(merge_files, sizes):
                        part = merged_data[offset:offset + fsize]
                        offset += fsize
                        # Only write the file that originally triggered the patch
                        if fname == file_name:
                            dest_file = os.path.join(FOLDER, fname)
                            with open(dest_file, "wb") as f:
                                f.write(part)
                            print(f"[✔] Patched & Saved: {fname}")
                        else:
                            # Skip other merged parts completely
                            pass
                else:
                    print(f"[–] No modification found, skipping all.")

                i = j
                continue

        i += 1

    print("Auto HeadShot Done.....")
    
#uexp Headshot 💀
def patch_bones_from_head():
  

    bones = [
        "upperarm_l","lowerarm_l","hand_l","hand_r",
        "thigh_l","calf_l","thigh_r","calf_r",
        "foot_l","spine_03","foot_r","lowerarm_r",
        "upperarm_r","pelvis"
    ]

    head_file = None

    # 1️⃣ Check FOLDER first
    for f in FOLDER.rglob("*"):
        if f.is_file():
            try:
                data = f.read_bytes()
                if b"TemperatureLow_Phase0" in data:
                    head_file = f
                    print(f"✅ Found in FOLDER: {f.name}")
                    break
            except:
                continue

    # 2️⃣ If not found, search FOLDER
    if head_file is None:
        for f in FOLDER.rglob("*"):
            if f.is_file():
                try:
                    data = f.read_bytes()
                    if b"TemperatureLow_Phase0" in data:
                        target_file = FOLDER / f.name
                        shutil.copy(f, target_file)
                        head_file = target_file
                        print(f"✅ Found in FOLDER and copied to FOLDER: {f.name}")
                        break
                except:
                    continue

    if head_file is None:
        print("❌ No file with 'TemperatureLow_Phase0' found in either directory.")
        return

    # Continue processing same as before
    data = head_file.read_bytes()
    pos = data.find(b"head")
    if pos == -1:
        print("❌ 'head' text not found.")
        return

    val_pos = pos + len(b"head") + 1
    if val_pos + 2 > len(data):
        print("❌ Not enough bytes after 'head'.")
        return

    value_bytes = data[val_pos:val_pos+2]
    print(f"🧠 Extracted 2 bytes after 'head': {value_bytes.hex().upper()}")

    # Patch all bones in FOLDER
    patched = 0
    for f in FOLDER.rglob("*"):
        if not f.is_file():
            continue
        file_data = f.read_bytes()
        modified = False
        for bone in bones:
            b = bone.encode()
            idx = 0
            while True:
                pos = file_data.find(b, idx)
                if pos == -1:
                    break
                after = pos + len(b)
                if after < len(file_data) and file_data[after] == 0x00:
                    after += 1
                if after + 2 <= len(file_data):
                    ba = bytearray(file_data)
                    ba[after:after+2] = value_bytes
                    file_data = bytes(ba)
                    modified = True
                    patched += 1
                idx = pos + 1
        if modified:
            f.write_bytes(file_data)
            print(f"✏️ Patched {f.name}")

    print(f"\n✅ Done. Total patched: {patched}")

#  ipad method

FLOAT_TARGET = 1300.0
TARGET_LE = struct.pack('<f', FLOAT_TARGET)
PATTERN_FULL = bytes.fromhex('ddffff')  

def float32_bytes(value):
    return struct.pack('<f', float(value))

def find_all(data: bytes, sub: bytes):
    i = data.find(sub)
    while i != -1:
        yield i
        i = data.find(sub, i + 1)



def IPadV():
    files = list(FOLDER.glob("*"))
    if not files:
        print("No files found in GRW__Unpack")
        return

    new_val = None
    while new_val is None:
        new_val_raw = input("What value do you want (300–400): ").strip()
        try:
            new_val = float(new_val_raw)
        except ValueError:
            print("Invalid input")

    new_bytes = float32_bytes(new_val)

    for p in files:
        data = bytearray(p.read_bytes())
        occurrences = list(find_all(data, TARGET_LE))
        if not occurrences:
            continue

        modified = False

        for cur_idx in occurrences:
            cut_start = cur_idx - 25
            cut_end = cur_idx + 4
            if cut_start < 0:
                continue

            cut_bytes = bytes(data[cut_start:cut_end])
            del data[cut_start:cut_end]

            pat_idx = data.find(PATTERN_FULL)
            if pat_idx == -1 or pat_idx < 33:
                continue
            insert_pos = pat_idx - 33
            data[insert_pos:insert_pos] = cut_bytes
            modified = True

            new_idx = data.find(TARGET_LE)
            if new_idx == -1:
                continue

            data[new_idx:new_idx + 4] = new_bytes

        if modified:
            out_path = FOLDER / p.name
            out_path.write_bytes(data)
            print(f"Done. Saved modified file to {out_path.name} — Go and Check")

# Ipad view Scope

import struct
from pathlib import Path

TARGET_FLOAT = struct.pack("<f", 5.0)

def float_to_bytes(f):
    return struct.pack("<f", f)

def find_all(data, sub):
    start = 0
    while True:
        idx = data.find(sub, start)
        if idx == -1:
            break
        yield idx
        start = idx + len(sub)

def modify_file(path, new_val):
    data = bytearray(path.read_bytes())
    matches = list(find_all(data, TARGET_FLOAT))
    if len(matches) == 24: 
        pos22 = matches[21]        # <-- sirf yeh line change/add hui
        new_bytes = float_to_bytes(new_val)
        data[pos22:pos22+4] = new_bytes
        out_path = FOLDER / path.name
        out_path.write_bytes(data)
        print(f"Modified 6th 5.0 in {path.name} to {new_val}")
        return True
    return False

def IPadS():
    files = list(FOLDER.glob("*"))
    if not files:
        print("No files found in GRW__Modification")
        return

    new_val = None
    while new_val is None:
        try:
            new_val = float(input("What value you want under (20): ").strip())
        except ValueError:
            print("Invalid input")

    modified = False
    for f in files:
        if modify_file(f, new_val):
            modified = True

    if not modified:
        print("No files with exactly {path.name} times {new_val} found.")


SEARCH_STRING = b"BodyDuability"  
HEX_TO_FIND = b"\xcd\xcc"        
OCCURRENCE = 17                   
OFFSET_BEHIND = 49               
NUM_BYTES = 2           

# Step 2 constants
FLOAT_TO_FIND = -88.0
OFFSET_BEHIND_2 = 61
NUM_BYTES_2 = 2

def find_body_duability_file():
    for file in FOLDER.iterdir():
        if file.is_file():
            with open(file, "rb") as f:
                content = f.read()
                if SEARCH_STRING in content:
                    return file
    return None

def extract_and_overwrite(file_path):
    with open(file_path, "rb") as f:
        data = bytearray(f.read()) 

    # ---------------- Step 1: cd cc ----------------
    step1_bytes = None
    indices = []
    start = 0
    while True:
        idx = data.find(HEX_TO_FIND, start)
        if idx == -1:
            break
        indices.append(idx)
        start = idx + 1

    if len(indices) < OCCURRENCE:
        print(f"❌ {OCCURRENCE} occurrences nahi mili.")
    else:
        target_idx = indices[OCCURRENCE - 1]
        hex_pos1 = target_idx - OFFSET_BEHIND
        if 0 <= hex_pos1 <= len(data) - NUM_BYTES:
            step1_bytes = data[hex_pos1:hex_pos1 + NUM_BYTES]
            hex_str1 = " ".join(f"{b:02x}" for b in step1_bytes)
            #print(f"✔ Step 1 Extracted hex: {hex_str1}")

    # ---------------- Step 2: float -88 ----------------
    float_bytes = struct.pack('<f', FLOAT_TO_FIND)
    indices2 = []
    start = 0
    while True:
        idx = data.find(float_bytes, start)
        if idx == -1:
            break
        indices2.append(idx)
        start = idx + 1

    step2_positions = []
    for i, idx in enumerate(indices2, 1):
        hex_pos2 = idx + 4 - OFFSET_BEHIND_2
        if 0 <= hex_pos2 <= len(data) - NUM_BYTES_2:
            extracted2 = data[hex_pos2:hex_pos2 + NUM_BYTES_2]
            hex_str2 = " ".join(f"{b:02x}" for b in extracted2)
            #print(f"✔ Step 2 Occurrence {i} Extracted hex: {hex_str2}")
            step2_positions.append(hex_pos2)

    # ---------------- Step 3: overwrite Step 2 with Step 1 ----------------
    if step1_bytes and step2_positions:
        for pos in step2_positions:
            data[pos:pos + NUM_BYTES] = step1_bytes
        with open(file_path, "wb") as f:
            f.write(data)
        #print(f"✔ Step 3: Step 1 bytes overwritten on all Step 2 occurrences.")

    # ---------------- Step 4: user value overwrite ----------------
    user_val = None
    while True:
        try:
            user_val = float(input("Please Write Your Value into (0/3): "))
            if 0 <= user_val <= 3:
                break
            else:
                print("❌ Value must be between 0 and 3.")
        except:
            print("❌ Invalid input. Try again.")

    # single precision little-endian bytes
    user_bytes = struct.pack('<f', user_val)

    # overwrite each -88 occurrence
    for idx in indices2:
        # original -88 position
        float_pos = idx
        # 1st overwrite -88
        data[float_pos:float_pos + 4] = user_bytes
        # 2nd overwrite - 1st picha 4 bytes
        data[float_pos - 4:float_pos] = user_bytes
        # 3rd overwrite - 2nd picha 4 bytes
        data[float_pos - 8:float_pos - 4] = user_bytes

    with open(file_path, "wb") as f:
        f.write(data)
    print(f"✔ User value {user_val} pasted. Enjoy Your Character 🙂.")

def bigC():
    file_path = find_body_duability_file()
    if not file_path:
        print("❌ No file with BodyDuability found in FOLDER!")
        return
    print(f"✔ File found: {file_path.name}")
    extract_and_overwrite(file_path)

def MainMenu():
    while True:
        os.system("clear")
        print_banner()
        print()
        print(Fore.CYAN + "Select Option.." + Style.RESET_ALL)
        menu_items = [
            ("1.", "AimBot Manual (Uexp - Method)"),
            ("2.", "Crosshair (Uexp - Method)"),
            ("3.", "Recoil (Risky) (Uexp - Method)"),
            ("4.", "Fast Switch (Uexp - Method)"),
            ("5.", "Magic Bullet (Uexp - Method)"),
            ("6.", "Auto FPS (Uexp - Method)"),
            ("7.", "Headshot (Uasset - method)"),
            ("8.", "Headshot (Uexp - method)"),
            ("9.", "Ipad View (Uexp - Method)"),
            ("10.", "Ipad View ( Scope ) (Uexp - Method)"),
            ("11.", "Big Character (Uexp - Method)"),
            ("0.", "Exit"),
        ]
        color_sets = [
            (Fore.MAGENTA, Fore.YELLOW),
            (Fore.GREEN, Fore.MAGENTA),
            (Fore.BLUE, Fore.CYAN),
            (Fore.YELLOW, Fore.GREEN),
            (Fore.CYAN, Fore.BLUE),
            (Fore.MAGENTA, Fore.CYAN),
            (Fore.RED, Fore.YELLOW),
        ]
        max_name = max(len(name) for _, name in menu_items)
        border_len = max_name + 8
        print(Fore.CYAN + "╔" + "═" * border_len + "╗" + Style.RESET_ALL)
        for idx, (num, name) in enumerate(menu_items):
            num_col, name_col = color_sets[idx % len(color_sets)]
            line = (
                Fore.CYAN + "║ " +
                num_col + Style.BRIGHT + f"{num}" +
                Fore.CYAN + "│" +
                name_col + f"{name.ljust(max_name)} " +
                Fore.CYAN + "║" + Style.RESET_ALL
            )
            print(line)
            if idx != len(menu_items) - 1:
                print(Fore.CYAN + "╟" + "─" * border_len + "╢" + Style.RESET_ALL)
        print(Fore.CYAN + "╚" + "═" * border_len + "╝" + Style.RESET_ALL)
        choice = input(Fore.MAGENTA + "Select an option (1-5): " + Style.RESET_ALL).strip()
        time.sleep(1)
        if choice == "1":
            AimMenu()
            input("Press Enter to Return To Menu")
        elif choice == "2":
            SmallCross()
            input("Press Enter to Return To Menu")
        elif choice == "3":
            LessR()
            input("Press Enter to Return To Menu")
        elif choice == "4":
            FastS()
            input("Press Enter to Return To Menu")
        elif choice == "5":
            magic()
            input("Press Enter to Return To Menu")
        elif choice == "6":
            FPSM()
            input("Press Enter to Return To Menu")
        elif choice == "7":
            headshot_auto_make()
            input("Press Enter to Return To Menu")
        elif choice == "8":
            patch_bones_from_head()
            input("Press Enter to Return To Menu")
        elif choice == "9":
            IPadV()
            input("Press Enter to Return To Menu")
        elif choice == "10":
            IPadS()
            input("Press Enter to Return To Menu")
        elif choice == "11":
            bigC()
            input("Press Enter to Return To Menu")
        elif choice == "0":
            print(Fore.YELLOW + "Allah Hafiz... Thanks For Using GRW_BRAND VIP Tool!" + Style.RESET_ALL)
            break
        else:
            print(Fore.RED + "Invalid choice. Please try again." + Style.RESET_ALL)

def FPSM():
    print_banner()
    while True:
        print(Fore.MAGENTA + "─" * 52)
        print(pill("MENU", Fore.WHITE, Back.MAGENTA), "Select an option:\n")
        print(Fore.GREEN + "1. Single Mode")
        print(Fore.GREEN + "2. Multiple Mode")
        print(Fore.RED + "0. EXIT")
        choice = input(Fore.YELLOW + "Select Option : ")
        if choice == "1":
            FPS()
            input("Press Enter to Return To Menu")
        elif choice == "2":
            FPS1()
            input("Press Enter to Return To Menu")
        elif choice == "0":
            print(Fore.YELLOW + "Return To The Main Menu" + Style.RESET_ALL)
            break
        else:
            print(Fore.RED + "Invalid choice. Please try again." + Style.RESET_ALL)


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        console.print("\n[bold #FFFF00]⚠  Interrupted by user. Exiting...[/bold #FFFF00]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[bold #FF0055]💥 UNEXPECTED ERROR:[/bold #FF0055] {escape(str(e))}")
        import traceback
        traceback.print_exc()
        safe_input("\nPress Enter to exit...")
        sys.exit(1)
