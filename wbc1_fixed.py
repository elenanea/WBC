"""
WBC1 — исправленная версия (6 багов устранены)
=============================================
БАГ 1: flat[0] не XOR-ился с ключом         → flat ^= xor_bytes[:cube_bytes]
БАГ 2: key_crypt из KDF не использовался    → tmp_cipher = WBC1(key_crypt)
БАГ 3: swap/diagflip не реализованы         → реализованы
БАГ 4: вложенный dynamic → identity          → рекурсивная обработка
БАГ 5: x/y/z в строках алгоритмов игнор.   → добавлена ветка cube-rotation
БАГ 6: padding corrupt для block > 255 байт → 2-байтовый length-prefix padding
"""

import numpy as np
import os
import random
import math
import time
import hashlib
import hmac
import json
from collections import Counter
from typing import Dict, Tuple, Union

MAGIC      = b'WBC1'
VERSION    = b'\x01'
NONCE_SIZE = 12
MAC_SIZE   = 32   # HMAC-SHA256
PAD_HDR    = 2    # байта на хранение длины паддинга (FIX #6)

# ─────────────────────────── вспомогательные функции ────────────────────────

def rotate_right(byte: int, n: int) -> int:
    return ((byte >> n) | (byte << (8 - n))) & 0xFF

def rotate_left(byte: int, n: int) -> int:
    return ((byte << n) | (byte >> (8 - n))) & 0xFF

def _bitwise_rotate_cube(cube: np.ndarray, n: int, direction: str) -> np.ndarray:
    flat = cube.flatten()
    if direction == 'right':
        rotated = np.array([rotate_right(b, n % 8) for b in flat], dtype=np.uint8)
    else:
        rotated = np.array([rotate_left(b, n % 8)  for b in flat], dtype=np.uint8)
    return rotated.reshape(cube.shape)

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq  = Counter(data)
    probs = [v / len(data) for v in freq.values()]
    return -sum(p * math.log2(p) for p in probs)

def chi_square_uniform(data: bytes) -> float:
    freq     = Counter(data)
    expected = len(data) / 256
    return sum((freq.get(x, 0) - expected) ** 2 / expected for x in range(256))

def byte_histogram(data: bytes):
    freq = Counter(data)
    return [freq.get(i, 0) for i in range(256)]

def correlation(x: bytes, y: bytes) -> float:
    if len(x) != len(y) or not x:
        return float('nan')
    mean_x = sum(x) / len(x)
    mean_y = sum(y) / len(y)
    cov  = sum((a - mean_x) * (b - mean_y) for a, b in zip(x, y))
    varx = sum((a - mean_x) ** 2 for a in x)
    vary = sum((b - mean_y) ** 2 for b in y)
    if varx == 0 or vary == 0:
        return float('nan')
    return cov / (varx ** 0.5 * vary ** 0.5)

def repetition_test(data: bytes, block_size: int = 8) -> Tuple[int, int]:
    reps       = sum(1 for i in range(1, len(data)) if data[i] == data[i - 1])
    blocks     = [bytes(data[i:i + block_size]) for i in range(0, len(data), block_size)]
    block_reps = len(blocks) - len(set(blocks))
    return reps, block_reps

def _parse_alg_string(alg: str):
    return alg.replace(",", " ").split()

# ──────────────────────── таблица 127 операций ─────────────────────────────

def build_127_ascii_operations(key: bytes) -> list:
    faces      = ['U', 'D', 'L', 'R', 'F', 'B']
    directions = ['', "'", '2', '3']
    slices     = ['M', 'E', 'S']
    wide_moves = ['u', 'd', 'l', 'r', 'f', 'b']
    cube_rot   = ['x', 'y', 'z']

    algs = [
        ("T-Perm", "R U R' U' R' F R2 U' R' U' R U R' F'"),
        ("Y-Perm", "F R U' R' U' R U R' F' R U R' U' R' F R F'"),
        ("J-Perm", "R U R' F' R U R' U' R' F R2 U' R' U'"),
        ("F-Perm", "R' U' F' R U R' U' R' F R2 U' R' U' R U R' U R"),
        ("A-Perm", "x' R2 D2 R' U' R D2 R' U R' x"),
        ("E-Perm", "x' R U' R' D R U R' D' R U R' D R U' R' D' x"),
        ("R-Perm", "R U' R' U' R U R D R' U' R D' R' U2 R'"),
        ("U-Perm", "R U' R U R U R U' R' U' R2"),
        ("V-Perm", "R' U R' U' y R' F' R2 U' R' U R' F R F"),
        ("N-Perm", "R U R' U R U R' F' R U R' U' R' F R2 U' R' U2 R U' R'"),
        ("Z-Perm", "M2 U M2 U M' U2 M2 U2 M' U2"),
        ("H-Perm", "M2 U M2 U2 M2 U M2"),
    ]
    patterns = [
        ("Checkerboard", "M2 E2 S2"),
        ("Cube-in-Cube", "F L F U' R U F2 L2 U' L' B D' B' L2 U"),
        ("Superflip",    "U R2 F B R B2 R U2 L B2 R U' D' R2 F R' L B2 U2 F2"),
        ("Six-Spot",     "U D' R L' F B' U D'"),
        ("Tetris",       "L R F B U' D' L' R'"),
        ("Anaconda",     "L U B' U' R L' B R' F B' D R D' F'"),
        ("Python",       "F2 R' B' U R' L F' L F' B D' R B L2"),
        ("Black Mamba",  "R D L F' R U' R' F L' D' R' U"),
    ]

    base_ops = []
    for face in faces:
        for d in directions:
            base_ops.append(('face',    face,  d, f"Rotate {face} face {d}"))
    for sl in slices:
        for d in directions:
            base_ops.append(('slice',   sl,    d, f"Rotate {sl} slice {d}"))
    for move in wide_moves:
        for d in directions:
            base_ops.append(('wide',    move,  d, f"Wide move {move}{d}"))
    for rot in cube_rot:
        for d in directions:
            base_ops.append(('cube',    rot,   d, f"Cube rotation {rot}{d}"))
    for name, alg in algs:
        base_ops.append(('alg',     name,  alg, f"Algorithm: {name}"))
    for name, patt in patterns:
        base_ops.append(('pattern', name,  patt, f"Pattern: {name}"))
    for axis in range(3):
        for k in range(4):
            base_ops.append(('swap',    axis,  k,  f"Swap axis={axis}, offset={k}"))
    for axis in range(3):
        base_ops.append(('diagflip', axis, '', f"Diagonal flip axis={axis}"))

    # 20 dynamic base patterns
    for i in range(20):
        seed = int(hashlib.sha256(key + i.to_bytes(2, "little")).hexdigest(), 16)
        rnd  = random.Random(seed)
        ops  = [rnd.choice(base_ops) for _ in range(rnd.randint(4, 7))]
        base_ops.append(('dynamic', i, ops, f"Dynamic pattern {i}"))

    # 127 guaranteed-unique final ops
    op_list = []
    seen    = set()
    for i in range(127):
        attempt = 0
        while True:
            seed  = int(hashlib.sha256(
                key + b"WBC1_OP" + i.to_bytes(2, 'little') + attempt.to_bytes(2, 'little')
            ).hexdigest(), 16)
            rnd   = random.Random(seed)
            chain = tuple(rnd.choice(base_ops) for _ in range(rnd.randint(3, 6)))
            key_s = str(chain)
            if key_s not in seen:
                seen.add(key_s)
                op_list.append(('dynamic', i, list(chain), f"Dynamic ASCII op {i + 1}"))
                break
            attempt += 1
    return op_list


# ═══════════════════════════ класс WBC1 ═════════════════════════════════════

class WBC1:
    SUPPORTED_SIZES = {
        8: (2, 2, 2), 27: (3, 3, 3), 64: (4, 4, 4), 125: (5, 5, 5),
        216: (6, 6, 6), 343: (7, 7, 7), 512: (8, 8, 8), 1000: (10, 10, 10),
        1331: (11, 11, 11), 1728: (12, 12, 12), 2197: (13, 13, 13),
        2744: (14, 14, 14), 3375: (15, 15, 15), 4096: (16, 16, 16),
    }

    def __init__(self, key: Union[str, bytes, bytearray, None] = None,
                 rounds: int = None, block_size: int = None):
        if key is None:
            self.key = os.urandom(32)
        elif isinstance(key, str):
            self.key = key.encode('utf-8', errors='replace')[:32].ljust(32, b'\0')
        else:
            self.key = bytes(key[:32]).ljust(32, b'\0')
        if len(self.key) != 32:
            raise ValueError("Key must be exactly 256 bits (32 bytes)")
        self.rounds     = rounds
        self.block_size = block_size
        self._base_operations = build_127_ascii_operations(self.key)
        self.operations       = self._individualize_operations()

    # ── вспомогательные ─────────────────────────────────────────────────────

    def _auto_block_size(self, data_len: int) -> int:
        for size in sorted(self.SUPPORTED_SIZES):
            if data_len <= size:
                return size
        return max(self.SUPPORTED_SIZES)

    def _form_cube(self, data: bytes, block_size: int) -> np.ndarray:
        dim           = self.SUPPORTED_SIZES[block_size]
        required_size = dim[0] * dim[1] * dim[2]
        if len(data) < required_size:
            data = data + bytes(required_size - len(data))
        elif len(data) > required_size:
            data = data[:required_size]
        return np.frombuffer(data, dtype=np.uint8).copy().reshape(dim)

    def _individualize_operations(self) -> Dict[int, tuple]:
        ops      = self._base_operations[:]
        key_hash = int(hashlib.sha256(self.key).hexdigest(), 16)
        rnd      = random.Random(key_hash)
        rnd.shuffle(ops)
        return {i: op for i, op in enumerate(ops)}

    def _set_slice(self, cube: np.ndarray, axis: int, idx: int, value):
        idx = idx % cube.shape[axis]
        if axis == 0:   cube[idx, :, :]  = value
        elif axis == 1: cube[:, idx, :]  = value
        elif axis == 2: cube[:, :, idx]  = value

    # ── применение операций ─────────────────────────────────────────────────

    def _apply_operation(self, cube: np.ndarray, op_id: int, inverse=False) -> np.ndarray:
        op      = self.operations[op_id % len(self.operations)]
        op_type = op[0]
        if op_type == 'dynamic':
            chain = list(reversed(op[2])) if inverse else op[2]
            for subop in chain:
                cube = self._apply_operation_type(cube, subop, inverse)
            return cube
        return self._apply_operation_type(cube, op, inverse)

    def _apply_operation_type(self, cube: np.ndarray, op, inverse: bool) -> np.ndarray:
        op_type   = op[0]
        name      = op[1]
        direction = op[2]

        def dir2k(d):
            if d == "'": return -1
            if d == '2': return 2
            if d == '3': return 3
            return 1

        # ── грани ────────────────────────────────────────────────────────────
        if op_type == 'face':
            face_map = {'U': (0, 0), 'D': (0, -1), 'L': (1, 0),
                        'R': (1, -1), 'F': (2, 0),  'B': (2, -1)}
            axis, idx = face_map[name]
            k = dir2k(direction)
            if inverse: k = -k
            sl = np.take(cube, idx, axis=axis).copy()
            self._set_slice(cube, axis, idx, np.rot90(sl, k))
            return cube

        # ── срезы ────────────────────────────────────────────────────────────
        elif op_type == 'slice':
            slice_map = {'M': (1, 1), 'E': (0, 1), 'S': (2, 1)}
            axis, idx = slice_map[name]
            k = dir2k(direction)
            if inverse: k = -k
            sl = np.take(cube, idx, axis=axis).copy()
            self._set_slice(cube, axis, idx, np.rot90(sl, k))
            return cube

        # ── широкие ходы ─────────────────────────────────────────────────────
        elif op_type == 'wide':
            wide_map = {'u': (0, [0, 1]),  'd': (0, [-1, -2]),
                        'l': (1, [0, 1]),  'r': (1, [-1, -2]),
                        'f': (2, [0, 1]),  'b': (2, [-1, -2])}
            axis, idxs = wide_map[name]
            k = dir2k(direction)
            if inverse: k = -k
            for idx in idxs:
                sl = np.take(cube, idx, axis=axis).copy()
                self._set_slice(cube, axis, idx, np.rot90(sl, k))
            return cube

        # ── поворот куба целиком ──────────────────────────────────────────────
        elif op_type == 'cube':
            axis_map = {'x': 0, 'y': 1, 'z': 2}
            axis = axis_map[name]
            k = dir2k(direction)
            if inverse: k = -k
            return np.rot90(cube, k, axes=(axis, (axis + 1) % 3)).copy()

        # ── алгоритмы и паттерны ─────────────────────────────────────────────
        elif op_type in ('alg', 'pattern'):
            moves = _parse_alg_string(op[2])
            if inverse:
                moves = list(reversed(moves))
            for m in moves:
                if m and m[-1] in ["'", '2', '3']:
                    base, d = m[:-1], m[-1]
                else:
                    base, d = m, ''
                k = dir2k(d)
                if inverse: k = -k
                if base in ('U', 'D', 'L', 'R', 'F', 'B'):
                    face_map = {'U': (0, 0), 'D': (0, -1), 'L': (1, 0),
                                'R': (1, -1), 'F': (2, 0), 'B': (2, -1)}
                    axis, idx = face_map[base]
                    sl = np.take(cube, idx, axis=axis).copy()
                    self._set_slice(cube, axis, idx, np.rot90(sl, k))
                elif base in ('M', 'E', 'S'):
                    slice_map = {'M': (1, 1), 'E': (0, 1), 'S': (2, 1)}
                    axis, idx = slice_map[base]
                    sl = np.take(cube, idx, axis=axis).copy()
                    self._set_slice(cube, axis, idx, np.rot90(sl, k))
                # ▼ FIX #5: x/y/z в строках алгоритмов ─────────────────────
                elif base in ('x', 'y', 'z'):
                    axis_map = {'x': 0, 'y': 1, 'z': 2}
                    axis = axis_map[base]
                    cube = np.rot90(cube, k, axes=(axis, (axis + 1) % 3)).copy()
            return cube

        # ▼ FIX #3: swap ──────────────────────────────────────────────────────
        elif op_type == 'swap':
            axis   = int(name)
            offset = int(direction) if direction != '' else 0
            d      = cube.shape[axis]
            idx1   = offset % d
            idx2   = (offset + 1) % d
            cube   = cube.copy()
            if axis == 0:
                cube[[idx1, idx2], :, :] = cube[[idx2, idx1], :, :]
            elif axis == 1:
                cube[:, [idx1, idx2], :] = cube[:, [idx2, idx1], :]
            else:
                cube[:, :, [idx1, idx2]] = cube[:, :, [idx2, idx1]]
            return cube   # swap — самообратима (swap^2 = id), inverse не нужен

        # ▼ FIX #3: diagflip ──────────────────────────────────────────────────
        elif op_type == 'diagflip':
            axis = int(name)
            cube = cube.copy()
            if axis == 0:
                cube = np.transpose(cube, (0, 2, 1)).copy()
            elif axis == 1:
                cube = np.transpose(cube, (2, 1, 0)).copy()
            else:
                cube = np.transpose(cube, (1, 0, 2)).copy()
            return cube   # diagflip — самообратима

        # ▼ FIX #4: вложенный dynamic в _apply_operation_type ────────────────
        elif op_type == 'dynamic':
            chain = list(reversed(op[2])) if inverse else op[2]
            for subop in chain:
                cube = self._apply_operation_type(cube, subop, inverse)
            return cube

        return cube  # неизвестный тип — identity (fallback)

    # ── раундовые ключи ──────────────────────────────────────────────────────

    def _get_round_key(self, key_material: bytes, round_number: int, cube_size: int) -> bytes:
        base   = key_material + round_number.to_bytes(4, "little")
        h      = hashlib.sha256(base).digest()
        buf, c = h, 1
        while len(buf) < cube_size:
            buf += hashlib.sha256(base + c.to_bytes(2, "little")).digest()
            c   += 1
        return buf[:cube_size]

    # ── блочное шифрование / расшифровка ─────────────────────────────────────

    def _encrypt_block(self, block: bytes, block_size: int,
                       key_material: bytes = None) -> Tuple[bytes, int]:
        if key_material is None:
            key_material = self.key
        cube       = self._form_cube(block, block_size)
        cube_bytes = cube.size
        rounds     = self.rounds or 32
        for r in range(rounds):
            rk     = self._get_round_key(key_material, r, cube_bytes)
            op_id  = rk[0] % len(self.operations)
            cube   = self._apply_operation(cube, op_id, inverse=False)
            # ▼ FIX #1: XOR ВСЕ байты (включая flat[0]) ─────────────────────
            flat   = cube.flatten()
            flat  ^= np.frombuffer(rk, dtype=np.uint8)[:cube_bytes]
            cube   = flat.reshape(cube.shape)
            cube   = _bitwise_rotate_cube(cube, op_id, 'right')
        return cube.tobytes(), block_size

    def _decrypt_block(self, block: bytes, block_size: int,
                       key_material: bytes = None) -> bytes:
        if key_material is None:
            key_material = self.key
        cube       = self._form_cube(block, block_size)
        cube_bytes = cube.size
        rounds     = self.rounds or 32
        for r in reversed(range(rounds)):
            rk     = self._get_round_key(key_material, r, cube_bytes)
            op_id  = rk[0] % len(self.operations)
            cube   = _bitwise_rotate_cube(cube, op_id, 'left')
            # ▼ FIX #1: XOR ВСЕ байты (включая flat[0]) ─────────────────────
            flat   = cube.flatten()
            flat  ^= np.frombuffer(rk, dtype=np.uint8)[:cube_bytes]
            cube   = flat.reshape(cube.shape)
            cube   = self._apply_operation(cube, op_id, inverse=True)
        return cube.tobytes()

    # ── паддинг ──────────────────────────────────────────────────────────────
    # Формат:
    #   [данные] [нули выравнивания fill_len байт] [блок паддинга: fill_len (PAD_HDR байт LE) + нули]
    # Последний блок всегда целиком паддинг; в первых PAD_HDR байтах — fill_len.
    # _unpad читает fill_len из data[-block_bytes:-block_bytes+PAD_HDR] (начало последнего блока).

    def _pad(self, data: bytes, block_bytes: int) -> bytes:
        remainder = len(data) % block_bytes
        fill_len  = (block_bytes - remainder) % block_bytes   # байт выравнивания
        data_aligned = data + bytes(fill_len)
        pad_block = fill_len.to_bytes(PAD_HDR, 'little') + bytes(block_bytes - PAD_HDR)
        return data_aligned + pad_block

    def _unpad(self, data: bytes, block_bytes: int) -> bytes:
        fill_len = int.from_bytes(data[-block_bytes: -block_bytes + PAD_HDR], 'little')
        strip    = block_bytes + fill_len   # последний блок паддинга + байты выравнивания
        return data[:-strip]

    # ── режимы шифрования ────────────────────────────────────────────────────

    def encrypt(self, data: bytes, mode: str = 'ECB',
                iv: bytes = None) -> Tuple[bytes, int, bytes]:
        block_size  = self.block_size or self._auto_block_size(len(data))
        dim         = self.SUPPORTED_SIZES[block_size]
        block_bytes = dim[0] * dim[1] * dim[2]

        data_padded = self._pad(data, block_bytes)
        blocks      = [data_padded[i:i + block_bytes] for i in range(0, len(data_padded), block_bytes)]

        if mode != 'ECB':
            if iv is None:
                iv = os.urandom(block_bytes)
            prev = iv
        else:
            iv = b''

        encrypted = bytearray()
        for block in blocks:
            if mode == 'ECB':
                enc_block, _ = self._encrypt_block(block, block_size)
            elif mode == 'CBC':
                to_enc       = bytes(b ^ p for b, p in zip(block, prev))
                enc_block, _ = self._encrypt_block(to_enc, block_size)
                prev         = enc_block
            elif mode == 'CFB':
                prev_enc, _  = self._encrypt_block(prev, block_size)
                enc_block    = bytes(b ^ pe for b, pe in zip(block, prev_enc))
                prev         = enc_block
            elif mode == 'OFB':
                prev, _      = self._encrypt_block(prev, block_size)
                enc_block    = bytes(b ^ p  for b, p  in zip(block, prev))
            elif mode == 'CTR':
                prev_enc, _  = self._encrypt_block(prev, block_size)
                enc_block    = bytes(b ^ pe for b, pe in zip(block, prev_enc))
                prev         = (int.from_bytes(prev, 'big') + 1).to_bytes(block_bytes, 'big')
            else:
                raise ValueError(f"Unknown mode: {mode}")
            encrypted.extend(enc_block)

        return bytes(encrypted), block_size, iv

    def decrypt(self, data: bytes, block_size: int,
                mode: str = 'ECB', iv: bytes = None) -> bytes:
        dim         = self.SUPPORTED_SIZES[block_size]
        block_bytes = dim[0] * dim[1] * dim[2]
        blocks      = [data[i:i + block_bytes] for i in range(0, len(data), block_bytes)]

        if mode != 'ECB' and iv is None:
            raise ValueError("IV required for this mode")
        if mode != 'ECB':
            prev = iv

        decrypted = bytearray()
        for block in blocks:
            if mode == 'ECB':
                dec_block = self._decrypt_block(block, block_size)
            elif mode == 'CBC':
                dec_block = self._decrypt_block(block, block_size)
                dec_block = bytes(d ^ p for d, p in zip(dec_block, prev))
                prev      = block
            elif mode == 'CFB':
                prev_enc, _ = self._encrypt_block(prev, block_size)
                dec_block   = bytes(b ^ pe for b, pe in zip(block, prev_enc))
                prev        = block
            elif mode == 'OFB':
                prev, _   = self._encrypt_block(prev, block_size)
                dec_block = bytes(b ^ p for b, p in zip(block, prev))
            elif mode == 'CTR':
                prev_enc, _ = self._encrypt_block(prev, block_size)
                dec_block   = bytes(b ^ pe for b, pe in zip(block, prev_enc))
                prev        = (int.from_bytes(prev, 'big') + 1).to_bytes(block_bytes, 'big')
            else:
                raise ValueError(f"Unknown mode: {mode}")
            decrypted.extend(dec_block)

        return self._unpad(bytes(decrypted), block_bytes)

    # ── KDF ─────────────────────────────────────────────────────────────────

    def kdf(self, nonce: bytes) -> Tuple[bytes, bytes]:
        h = hashlib.sha512(self.key + nonce).digest()
        return h[:32], h[32:64]

    # ── WBC-CTR-HMAC ─────────────────────────────────────────────────────────

    def encrypt_wbc_ctr_hmac(self, data: bytes, nonce: bytes = None) -> bytes:
        block_size  = self.block_size or self._auto_block_size(len(data))
        dim         = self.SUPPORTED_SIZES[block_size]
        block_bytes = dim[0] * dim[1] * dim[2]
        if nonce is None:
            nonce = os.urandom(NONCE_SIZE)
        assert len(nonce) == NONCE_SIZE

        # ▼ FIX #2: используем key_crypt для шифрования ──────────────────────
        key_crypt, key_mac = self.kdf(nonce)

        data_padded  = self._pad(data, block_bytes)
        encrypted    = bytearray()
        counter      = 0
        ctr_tail_sz  = max(1, block_bytes - NONCE_SIZE)

        for block in [data_padded[i:i + block_bytes] for i in range(0, len(data_padded), block_bytes)]:
            ctr_bytes = counter.to_bytes(ctr_tail_sz, 'big')
            ctr       = (nonce + ctr_bytes)[:block_bytes].ljust(block_bytes, b'\0')
            # FIX #2: передаём key_crypt как key_material
            enc_ctr, _ = self._encrypt_block(ctr, block_size, key_material=key_crypt)
            encrypted.extend(b ^ pe for b, pe in zip(block, enc_ctr))
            counter += 1

        ciphertext = bytes(encrypted)
        header     = MAGIC + VERSION + block_size.to_bytes(2, 'big') + nonce
        mac        = hmac.new(key_mac, header + ciphertext, hashlib.sha256).digest()
        return header + ciphertext + mac

    def decrypt_wbc_ctr_hmac(self, file_bytes: bytes) -> bytes:
        if file_bytes[:4] != MAGIC:
            raise ValueError("Invalid magic bytes")
        if file_bytes[4:5] != VERSION:
            raise ValueError("Unsupported version")
        block_size  = int.from_bytes(file_bytes[5:7], 'big')
        nonce       = file_bytes[7:7 + NONCE_SIZE]
        mac_actual  = file_bytes[-MAC_SIZE:]
        ciphertext  = file_bytes[7 + NONCE_SIZE:-MAC_SIZE]

        # ▼ FIX #2: используем key_crypt для расшифровки ─────────────────────
        key_crypt, key_mac = self.kdf(nonce)

        header       = file_bytes[:7 + NONCE_SIZE]
        mac_expected = hmac.new(key_mac, header + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(mac_actual, mac_expected):
            raise ValueError("MAC verification failed")

        dim         = self.SUPPORTED_SIZES[block_size]
        block_bytes = dim[0] * dim[1] * dim[2]
        decrypted   = bytearray()
        counter     = 0
        ctr_tail_sz = max(1, block_bytes - NONCE_SIZE)

        for block in [ciphertext[i:i + block_bytes] for i in range(0, len(ciphertext), block_bytes)]:
            ctr_bytes = counter.to_bytes(ctr_tail_sz, 'big')
            ctr       = (nonce + ctr_bytes)[:block_bytes].ljust(block_bytes, b'\0')
            enc_ctr, _ = self._encrypt_block(ctr, block_size, key_material=key_crypt)
            decrypted.extend(b ^ pe for b, pe in zip(block, enc_ctr))
            counter += 1

        return self._unpad(bytes(decrypted), block_bytes)

    # ── таблица операций ─────────────────────────────────────────────────────

    def show_rotation_operations_table(self):
        print(f"\n{'ID':>4}  {'ASCII':>5}  {'Hex':>4}  {'Operation':<50} {'Description'}")
        print("-" * 110)
        for op_id in sorted(self.operations):
            op     = self.operations[op_id]
            ascii_ = chr(op_id) if 32 <= op_id <= 126 else 'N/A'
            desc   = op[3] if len(op) > 3 else str(op)
            print(f"{op_id:>4}  {ascii_:>5}  0x{op_id:02X}  {desc[:50]:<50}")

    # ── self-tests ───────────────────────────────────────────────────────────

    def run_self_tests(self, mode: str = 'ECB', nonce: bytes = None):
        print(f"\n{'─'*60}")
        print(f"  Self-tests  |  mode = {mode}")
        print(f"{'─'*60}")
        tests = [
            (b"Hello World!",      "Short text"),
            (b"A" * 64,            "Exactly one block (64 B)"),
            (b"B" * 300,           "Multi-block text (300 B)"),
            (os.urandom(100),      "Binary data (100 B)"),
            (b"",                  "Empty input"),
            (bytes(range(256)),    "All byte values (256 B)"),
            (b"X" * 1,             "Single byte"),
        ]
        passed = 0
        for data, label in tests:
            try:
                if mode == 'WBC-CTR-HMAC':
                    enc = self.encrypt_wbc_ctr_hmac(data, nonce=nonce)
                    dec = self.decrypt_wbc_ctr_hmac(enc)
                else:
                    enc, bs, iv = self.encrypt(data, mode=mode)
                    dec         = self.decrypt(enc, bs, mode=mode, iv=iv)
                ok = (dec == data)
            except Exception as e:
                ok = False
                print(f"  {label:<35} EXCEPTION: {e}")
            status = "PASS ✓" if ok else "FAIL ✗"
            print(f"  {label:<35} {status}")
            if ok:
                passed += 1
        print(f"{'─'*60}")
        print(f"  Results: {passed}/{len(tests)} passed")
        print(f"{'─'*60}\n")
        return passed == len(tests)

    # ── бенчмарк ─────────────────────────────────────────────────────────────

    def benchmark(self, sizes=(1, 10, 100, 1000, 10000, 100000, 1000000),
                  mode: str = 'ECB', repeats: int = 3, nonce: bytes = None):
        print(f"\n  Benchmark  |  mode = {mode}")
        print(f"  {'Size (KB)':>10}  {'Time (s)':>10}  {'Speed (KB/s)':>14}  Integrity")
        print("  " + "-" * 52)
        results = []
        for size in sizes:
            times, oks = [], []
            for _ in range(repeats):
                data = os.urandom(size)
                try:
                    if mode == 'WBC-CTR-HMAC':
                        t0  = time.time()
                        enc = self.encrypt_wbc_ctr_hmac(data, nonce=nonce)
                        t1  = time.time()
                        dec = self.decrypt_wbc_ctr_hmac(enc)
                        t2  = time.time()
                    else:
                        bs  = self._auto_block_size(size)
                        t0  = time.time()
                        enc, bs, iv = self.encrypt(data, mode=mode)
                        t1  = time.time()
                        dec = self.decrypt(enc, bs, mode=mode, iv=iv)
                        t2  = time.time()
                    times.append(t2 - t0)
                    oks.append(dec == data)
                except Exception as e:
                    times.append(999)
                    oks.append(False)
            avg   = sum(times) / len(times)
            speed = (size / 1024) / avg if avg > 0 else 0
            ok    = all(oks)
            results.append((size, avg, speed, ok))
            print(f"  {size/1024:>10.2f}  {avg:>10.5f}  {speed:>14.2f}  {'OK' if ok else 'FAIL'}")
        return results

    # ── лавинный эффект ──────────────────────────────────────────────────────

    def avalanche_test(self, data: bytes, mode: str = 'ECB',
                       nonce: bytes = None) -> float:
        if mode == 'WBC-CTR-HMAC':
            enc0       = self.encrypt_wbc_ctr_hmac(data, nonce=nonce)
            hdr        = 7 + NONCE_SIZE
            ref        = enc0[hdr:-MAC_SIZE]
        else:
            enc0, bs, iv = self.encrypt(data, mode=mode)
            ref          = enc0

        total = len(ref) * 8
        flips = 0
        for i in range(len(data) * 8):
            mod        = bytearray(data)
            mod[i // 8] ^= 1 << (i % 8)
            if mode == 'WBC-CTR-HMAC':
                enc1 = self.encrypt_wbc_ctr_hmac(bytes(mod), nonce=nonce)
                cmp  = enc1[hdr:-MAC_SIZE]
            else:
                enc1, _, _ = self.encrypt(bytes(mod), mode=mode, iv=iv)
                cmp        = enc1
            if len(ref) == len(cmp):
                diff   = int.from_bytes(ref, 'big') ^ int.from_bytes(cmp, 'big')
                flips += bin(diff).count('1')

        ratio = flips / (len(data) * 8 * total) if total else 0
        print(f"  Avalanche effect:    {ratio * 100:.2f}%  (ideal ≈ 50%)")
        return ratio

    # ── дифференциальный тест ────────────────────────────────────────────────

    def differential_test(self, data: bytes, mode: str = 'ECB',
                          nonce: bytes = None) -> float:
        if mode == 'WBC-CTR-HMAC':
            enc0  = self.encrypt_wbc_ctr_hmac(data, nonce=nonce)
            hdr   = 7 + NONCE_SIZE
            ref   = enc0[hdr:-MAC_SIZE]
        else:
            enc0, bs, iv = self.encrypt(data, mode=mode)
            ref          = enc0

        total = len(ref) * 8
        flips = 0
        for i in range(32 * 8):
            mod_key       = bytearray(self.key)
            mod_key[i // 8] ^= 1 << (i % 8)
            c2 = WBC1(bytes(mod_key))
            if mode == 'WBC-CTR-HMAC':
                enc1 = c2.encrypt_wbc_ctr_hmac(data, nonce=nonce)
                cmp  = enc1[hdr:-MAC_SIZE]
            else:
                enc1, _, _ = c2.encrypt(data, mode=mode, iv=iv)
                cmp        = enc1
            if len(ref) == len(cmp):
                diff   = int.from_bytes(ref, 'big') ^ int.from_bytes(cmp, 'big')
                flips += bin(diff).count('1')

        ratio = flips / (32 * 8 * total) if total else 0
        print(f"  Differential test:   {ratio * 100:.2f}%  (ideal ≈ 50%)")
        return ratio

    # ── статистические тесты ─────────────────────────────────────────────────

    def statistics_tests(self, data: bytes, ciphertext: bytes):
        print("\n  === STATISTICAL TESTS ===")
        print(f"  Shannon entropy (plain):   {shannon_entropy(data):.4f} bits/byte")
        print(f"  Shannon entropy (cipher):  {shannon_entropy(ciphertext):.4f} bits/byte  (ideal 8.0)")
        print(f"  Chi-square (ciphertext):   {chi_square_uniform(ciphertext):.2f}         (ideal ≈ 256)")
        corr = correlation(data[:len(ciphertext)], ciphertext[:len(data)])
        print(f"  Correlation plain↔cipher:  {corr:.4f}             (ideal ≈ 0)")
        reps, breps = repetition_test(ciphertext, 8)
        print(f"  Adjacent byte repeats:     {reps}")
        print(f"  Repeated 8-byte blocks:    {breps}")


# ═══════════════════════════ main / меню ════════════════════════════════════

def select_mode() -> str:
    print("  Выберите режим:")
    modes = {'1': 'ECB', '2': 'CBC', '3': 'CFB', '4': 'OFB', '5': 'CTR', '6': 'WBC-CTR-HMAC'}
    for k, v in modes.items():
        print(f"    {k}. {v}")
    while True:
        m = input("  Mode [1-6, default=1]: ").strip()
        if not m:
            return 'ECB'
        if m in modes:
            return modes[m]
        print("  Некорректный ввод.")


if __name__ == "__main__":
    c = WBC1()
    while True:
        print("""
=== WBC1 CIPHER (исправленная версия) ===
1. Encrypt / decrypt text
2. Show rotation operations table
3. Run self-tests
4. Benchmark performance
5. Avalanche + differential + statistics
6. Exit
""", end="")
        choice = input("Select (1-6): ").strip()
        if choice == '1':
            text  = input("Text to encrypt: ")
            mode  = select_mode()
            auto  = input("Generate key? (y/n): ").strip().lower()
            key   = os.urandom(32) if auto == 'y' else bytes.fromhex(input("Key (hex 32B): "))
            if auto == 'y':
                print(f"  Generated key: {key.hex()}")
            c2 = WBC1(key)
            text_bytes = text.encode()
            print(f"  Input HEX:     {text_bytes.hex()}")
            if mode == 'WBC-CTR-HMAC':
                enc = c2.encrypt_wbc_ctr_hmac(text_bytes)
                print(f"  Encrypted HEX: {enc.hex()}")
                dec = c2.decrypt_wbc_ctr_hmac(enc)
                print(f"  Decrypted HEX: {dec.hex()}")
                print(f"  Decrypted:     {dec.decode('utf-8', errors='replace')}")
            else:
                enc, bs, iv = c2.encrypt(text_bytes, mode=mode)
                print(f"  Encrypted HEX: {enc.hex()}")
                dec = c2.decrypt(enc, bs, mode=mode, iv=iv)
                print(f"  Decrypted HEX: {dec.hex()}")
                print(f"  Decrypted:     {dec.decode('utf-8', errors='replace')}")
        elif choice == '2':
            c.show_rotation_operations_table()
        elif choice == '3':
            mode = select_mode()
            c.run_self_tests(mode=mode)
        elif choice == '4':
            mode = select_mode()
            c.benchmark(mode=mode)
        elif choice == '5':
            text = input("Test text (Enter = random 64B): ").encode() or os.urandom(64)
            mode = select_mode()
            enc, bs, iv = c.encrypt(text, mode=mode)
            c.avalanche_test(text, mode=mode)
            c.differential_test(text, mode=mode)
            c.statistics_tests(text, enc)
        else:
            print("Bye!")
            break
