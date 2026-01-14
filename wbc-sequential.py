import numpy as np
import os
import math
import time
import hashlib
import hmac
import json
from collections import Counter
from typing import Dict, Tuple, Union
import matplotlib.pyplot as plt

MAGIC = b'WBC1'
VERSION = b'\x01'
NONCE_SIZE = 12
MAC_SIZE = 32  # HMAC-SHA256

def rotate_right(byte: int, n: int) -> int:
    return ((byte >> n) | (byte << (8 - n))) & 0xFF

def rotate_left(byte: int, n: int) -> int:
    return ((byte << n) | (byte >> (8 - n))) & 0xFF

def _bitwise_rotate_cube(cube: np.ndarray, n: int, direction: str) -> np.ndarray:
    flat = cube.flatten()
    if direction == 'right':
        rotated = np.array([rotate_right(b, n % 8) for b in flat], dtype=np.uint8)
    else:
        rotated = np.array([rotate_left(b, n % 8) for b in flat], dtype=np.uint8)
    return rotated.reshape(cube.shape)

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    probs = [v / len(data) for v in freq.values()]
    return -sum(p * math.log2(p) for p in probs)

def chi_square_uniform(data: bytes) -> float:
    freq = Counter(data)
    expected = len(data) / 256
    return sum((freq.get(x, 0) - expected) ** 2 / expected for x in range(256))

def byte_histogram(data: bytes):
    freq = Counter(data)
    hist = [freq.get(i, 0) for i in range(256)]
    return hist

def plot_histogram(data: bytes, title="Byte Histogram"):
    plt.figure(figsize=(10, 4))
    hist = byte_histogram(data)
    plt.bar(range(256), hist, color='steelblue', width=1)
    plt.title(title)
    plt.xlabel('Byte value')
    plt.ylabel('Frequency')
    plt.tight_layout()
    plt.show()

def plot_bit_distribution(data: bytes, title="Bit Distribution"):
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    plt.figure(figsize=(8, 2))
    plt.hist(bits, bins=[-0.5, 0.5, 1.5], rwidth=0.8, color='green')
    plt.xticks([0, 1])
    plt.title(title)
    plt.xlabel('Bit value')
    plt.ylabel('Count')
    plt.tight_layout()
    plt.show()

def correlation(x: bytes, y: bytes) -> float:
    if len(x) != len(y) or not x:
        return float('nan')
    mean_x = sum(x) / len(x)
    mean_y = sum(y) / len(y)
    cov = sum((a - mean_x) * (b - mean_y) for a, b in zip(x, y))
    varx = sum((a - mean_x) ** 2 for a in x)
    vary = sum((b - mean_y) ** 2 for b in y)
    if varx == 0 or vary == 0:
        return float('nan')
    return cov / (varx ** 0.5 * vary ** 0.5)

def repetition_test(data: bytes, block_size: int = 8) -> Tuple[int, int]:
    reps = sum(1 for i in range(1, len(data)) if data[i] == data[i - 1])
    blocks = [bytes(data[i:i+block_size]) for i in range(0, len(data), block_size)]
    block_reps = len(blocks) - len(set(blocks))
    return reps, block_reps

def key_sensitivity_test(cipher_class, data: bytes, key: bytes) -> float:
    encrypted_ref, block_size, _ = cipher_class(key).encrypt(data)
    total_bits = len(encrypted_ref) * 8
    flips = 0
    for i in range(32 * 8):
        mod_key = bytearray(key)
        mod_key[i // 8] ^= 1 << (i % 8)
        encrypted_mod, _, _ = cipher_class(bytes(mod_key)).encrypt(data)
        diff = int.from_bytes(encrypted_ref, 'big') ^ int.from_bytes(encrypted_mod, 'big')
        flips += bin(diff).count("1")
    return flips / (32 * 8 * total_bits)

def _parse_alg_string(alg: str):
    tokens = alg.replace(",", " ").split()
    return tokens

def build_127_ascii_operations(key: bytes) -> list:
    import numpy as np  # импорт здесь гарантирует, что используется всегда numpy

    faces = ['U', 'D', 'L', 'R', 'F', 'B']
    directions = ['', "'", '2', '3']
    slices = ['M', 'E', 'S']
    wide_moves = ['u', 'd', 'l', 'r', 'f', 'b']
    cube_rot = ['x', 'y', 'z']
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
        ("H-Perm", "M2 U M2 U2 M2 U M2")
    ]
    patterns = [
        ("Checkerboard", "M2 E2 S2"),
        ("Cube-in-Cube", "F L F U' R U F2 L2 U' L' B D' B' L2 U"),
        ("Superflip", "U R2 F B R B2 R U2 L B2 R U' D' R2 F R' L B2 U2 F2"),
        ("Six-Spot", "U D' R L' F B' U D'"),
        ("Tetris", "L R F B U' D' L' R'"),
        ("Anaconda", "L U B' U' R L' B R' F B' D R D' F'"),
        ("Python", "F2 R' B' U R' L F' L F' B D' R B L2"),
        ("Black Mamba", "R D L F' R U' R' F L' D' R' U")
    ]
    base_ops = []
    for face in faces:
        for dir in directions:
            base_ops.append(('face', face, dir, f"Rotate {face} face {dir}"))
    for sl in slices:
        for dir in directions:
            base_ops.append(('slice', sl, dir, f"Rotate {sl} slice {dir}"))
    for move in wide_moves:
        for dir in directions:
            base_ops.append(('wide', move, dir, f"Wide move {move}{dir}"))
    for rot in cube_rot:
        for dir in directions:
            base_ops.append(('cube', rot, dir, f"Cube rotation {rot}{dir}"))
    for name, alg in algs:
        base_ops.append(('alg', name, alg, f"Algorithm: {name}"))
    for name, pattern in patterns:
        base_ops.append(('pattern', name, pattern, f"Pattern: {name}"))
    for axis in range(3):
        for k in range(4):
            base_ops.append(('swap', axis, k, f"Swap axis={axis}, offset={k}"))
    for axis in range(3):
        base_ops.append(('diagflip', axis, '', f"Diagonal flip axis={axis}"))

    static_ops = base_ops[:]

    # Динамические паттерны только из static_ops
    dynamic_ops = []
    for i in range(20):
        seed = int(hashlib.sha256(key + i.to_bytes(2, "little")).hexdigest(), 16) & 0xFFFFFFFF
        rng = np.random.RandomState(seed)
        ops = []
        n_ops = rng.randint(4, 8)  # 4,5,6,7
        for _ in range(n_ops):
            op = static_ops[rng.randint(0, len(static_ops))]
            ops.append(op)
        dynamic_ops.append(('dynamic', i, ops, f"Dynamic pattern {i}"))

    all_ops = static_ops + dynamic_ops

    op_list = []
    seen = set()
    for i in range(127):
        attempt = 0
        while True:
            seed = int(hashlib.sha256(key + b"WBC1_OP" + i.to_bytes(2, 'little') + attempt.to_bytes(2, 'little')).hexdigest(), 16) & 0xFFFFFFFF
            rng = np.random.RandomState(seed)
            chain = tuple(all_ops[rng.randint(0, len(all_ops))] for _ in range(rng.randint(3, 7)))  # 3,4,5,6
            chain_serialized = str(chain)
            if chain_serialized not in seen:
                seen.add(chain_serialized)
                op_list.append(('dynamic', i, list(chain), f"Dynamic ASCII op {i+1}"))
                break
            attempt += 1
    return op_list

# ----- Класс WBC1 и остальной код (без изменений, как у вас) -----

class WBC1:
    SUPPORTED_SIZES = {
        8: (2, 2, 2), 27: (3, 3, 3), 64: (4, 4, 4), 125: (5, 5, 5), 216: (6, 6, 6), 343: (7, 7, 7),
        512: (8, 8, 8), 1000: (10, 10, 10), 1331: (11, 11, 11), 1728: (12, 12, 12), 2197: (13, 13, 13),
        2744: (14, 14, 14), 3375: (15, 15, 15), 4096: (16, 16, 16)
    }

    def __init__(self, key: Union[str, bytes, bytearray, None] = None, rounds: int = None, block_size: int = None):
        if key is None:
            self.key = os.urandom(32)
        elif isinstance(key, str):
            self.key = key.encode('utf-8', errors='replace')[:32].ljust(32, b'\0')
        else:
            self.key = bytes(key[:32]).ljust(32, b'\0')
        if len(self.key) != 32:
            raise ValueError("Key must be exactly 256 bits (32 bytes)")
        self.rounds = rounds
        self._base_operations = build_127_ascii_operations(self.key)
        self.operations = self._individualize_operations()  # Только здесь!
        self.block_size = block_size
        seed = int.from_bytes(hashlib.sha256(self.key).digest()[:4], 'big')
        rng = np.random.RandomState(seed)
        self.sbox = rng.permutation(256).astype(np.uint8)
        self.sbox_inv = np.argsort(self.sbox)

    def _auto_block_size(self, data_len: int) -> int:
        for size in sorted(self.SUPPORTED_SIZES):
            if data_len <= size:
                return size
        return max(self.SUPPORTED_SIZES)

    def _form_cube(self, data: bytes, block_size: int) -> np.ndarray:
        dim = self.SUPPORTED_SIZES[block_size]
        required_size = dim[0] * dim[1] * dim[2]
        if len(data) < required_size:
            data = data + bytes([0] * (required_size - len(data)))
        elif len(data) > required_size:
            data = data[:required_size]
        arr = np.frombuffer(data, dtype=np.uint8).copy()
        return arr.reshape(dim)



    def _individualize_operations(self) -> Dict[int, Tuple]:
        ops = self._base_operations[:]
        # Сортируем по хешу json-сериализации операции + ключ
        def op_sort_key(op):
            # Преобразуем кортеж в сериализуемую структуру
            serializable = [str(x) for x in op]
            h = hashlib.sha256(json.dumps(serializable, sort_keys=True).encode() + self.key).digest()
            return h
        ops.sort(key=op_sort_key)
        return {i: op for i, op in enumerate(ops)}

    def _set_slice(self, cube, axis, idx, value):
        idx = idx % cube.shape[axis]
        if axis == 0:
            cube[idx, :, :] = value
        elif axis == 1:
            cube[:, idx, :] = value
        elif axis == 2:
            cube[:, :, idx] = value

    def _apply_operation(self, cube: np.ndarray, op_id: int, inverse=False) -> np.ndarray:
        op = self.operations[op_id % len(self.operations)]
        op_type = op[0]
        if op_type == 'dynamic':
            for subop in (reversed(op[2]) if inverse else op[2]):
                cube = self._apply_operation_type(cube, subop, inverse)
            return cube
        return self._apply_operation_type(cube, op, inverse)

    def _apply_operation_type(self, cube, op, inverse):
        op_type = op[0]
        name = op[1]
        direction = op[2]
        def dir2k(d):
            if d == "'": return -1
            if d == "2": return 2
            if d == "3": return 3
            return 1
        if op_type == 'face':
            face_map = {'U': (0, 0), 'D': (0, -1), 'L': (1, 0), 'R': (1, -1), 'F': (2, 0), 'B': (2, -1)}
            axis, idx = face_map[name]
            k = dir2k(direction)
            if inverse: k = -k
            rotated = np.rot90(np.take(cube, idx, axis=axis).copy(), k)
            self._set_slice(cube, axis, idx, rotated)
            return cube
        elif op_type == 'slice':
            slice_map = {'M': (1, 1), 'E': (0, 1), 'S': (2, 1)}
            axis, idx = slice_map[name]
            k = dir2k(direction)
            if inverse: k = -k
            rotated = np.rot90(np.take(cube, idx, axis=axis).copy(), k)
            self._set_slice(cube, axis, idx, rotated)
            return cube
        elif op_type == 'wide':
            wide_map = {'u': (0, [0, 1]), 'd': (0, [-1, -2]), 'l': (1, [0, 1]), 'r': (1, [-1, -2]), 'f': (2, [0, 1]), 'b': (2, [-1, -2])}
            axis, idxs = wide_map[name]
            k = dir2k(direction)
            if inverse: k = -k
            for idx in idxs:
                rotated = np.rot90(np.take(cube, idx, axis=axis).copy(), k)
                self._set_slice(cube, axis, idx, rotated)
            return cube
        elif op_type == 'cube':
            axis_map = {'x': 0, 'y': 1, 'z': 2}
            axis = axis_map[name]
            k = dir2k(direction)
            if inverse: k = -k
            cube = np.rot90(cube, k, axes=(axis, (axis+1)%3)).copy()
            return cube
        elif op_type in ('alg', 'pattern'):
            moves = _parse_alg_string(op[2])
            for move in (reversed(moves) if inverse else moves):
                m = move
                if m[-1] in ["'", "2", "3"]:
                    base, d = m[:-1], m[-1]
                else:
                    base, d = m, ''
                if base in ['U', 'D', 'L', 'R', 'F', 'B']:
                    face_map = {'U': (0, 0), 'D': (0, -1), 'L': (1, 0), 'R': (1, -1), 'F': (2, 0), 'B': (2, -1)}
                    axis, idx = face_map[base]
                    k = dir2k(d)
                    if inverse: k = -k
                    rotated = np.rot90(np.take(cube, idx, axis=axis).copy(), k)
                    self._set_slice(cube, axis, idx, rotated)
                elif base in ['M', 'E', 'S']:
                    slice_map = {'M': (1, 1), 'E': (0, 1), 'S': (2, 1)}
                    axis, idx = slice_map[base]
                    k = dir2k(d)
                    if inverse: k = -k
                    rotated = np.rot90(np.take(cube, idx, axis=axis).copy(), k)
                    self._set_slice(cube, axis, idx, rotated)
            return cube
        return cube

    def _get_round_key(self, round_number: int, cube_size: int) -> bytes:
        base = self.key + round_number.to_bytes(4, "little")
        h = hashlib.sha256(base).digest()
        needed = cube_size
        buf = h
        c = 1
        while len(buf) < needed:
            buf += hashlib.sha256(base + c.to_bytes(2, "little")).digest()
            c += 1
        return buf[:needed]

    def _encrypt_block(self, block: bytes, block_size: int):
        cube = self._form_cube(block, block_size)
        cube_bytes = cube.size
        rounds = self.rounds or 32
        for round_number in range(rounds):
            round_key = self._get_round_key(round_number, cube_bytes)
            op_id = round_key[0] % len(self.operations)
            cube = self._apply_operation(cube, op_id, inverse=False)
            xor_bytes = np.frombuffer(round_key, np.uint8)
            flat = cube.flatten()
            flat = (flat ^ xor_bytes).astype(np.uint8)
            flat = self.sbox[flat]
            # Диффузия: накопительный XOR (forward)
            for i in range(1, len(flat)):
                flat[i] ^= flat[i-1]
            cube = flat.reshape(cube.shape)
            cube = _bitwise_rotate_cube(cube, op_id, 'right')
        return cube.tobytes(), block_size

    def _decrypt_block(self, block: bytes, block_size: int):
        cube = self._form_cube(block, block_size)
        cube_bytes = cube.size
        rounds = self.rounds or 32
        for round_number in reversed(range(rounds)):
            round_key = self._get_round_key(round_number, cube_bytes)
            op_id = round_key[0] % len(self.operations)
            cube = _bitwise_rotate_cube(cube, op_id, 'left')
            flat = cube.flatten()
            # Обратная диффузия: накопительный XOR (backward)
            for i in range(len(flat)-1, 0, -1):
                flat[i] ^= flat[i-1]
            flat = self.sbox_inv[flat]
            xor_bytes = np.frombuffer(round_key, np.uint8)
            flat = (flat ^ xor_bytes).astype(np.uint8)
            cube = flat.reshape(cube.shape)
            cube = self._apply_operation(cube, op_id, inverse=True)
        return cube.tobytes()

    def encrypt(self, data: bytes, mode='ECB', iv: bytes = None) -> Tuple[bytes, int, bytes]:
        block_size = self.block_size or self._auto_block_size(len(data))
        dim = self.SUPPORTED_SIZES[block_size]
        block_bytes = dim[0] * dim[1] * dim[2]
        pad_len = block_bytes - (len(data) % block_bytes)
        pad_byte = pad_len if pad_len < 256 else pad_len % 256 or 1
        if pad_len == 0:
            pad_len = block_bytes
            pad_byte = pad_len if pad_len < 256 else pad_len % 256 or 1
        data_padded = data + bytes([pad_byte] * pad_len)
        encrypted = bytearray()
        blocks = [data_padded[i:i+block_bytes] for i in range(0, len(data_padded), block_bytes)]
        if mode != 'ECB':
            if iv is None:
                iv = os.urandom(block_bytes)
            prev = iv
        else:
            iv = b''
        for block in blocks:
            if mode == 'ECB':
                to_encrypt = block
                enc_block, _ = self._encrypt_block(to_encrypt, block_size)
            elif mode == 'CBC':
                to_encrypt = bytes([b ^ p for b, p in zip(block, prev)])
                enc_block, _ = self._encrypt_block(to_encrypt, block_size)
                prev = enc_block
            elif mode == 'CFB':
                prev_enc, _ = self._encrypt_block(prev, block_size)
                enc_block = bytes([b ^ pe for b, pe in zip(block, prev_enc)])
                prev = enc_block
            elif mode == 'OFB':
                prev, _ = self._encrypt_block(prev, block_size)
                enc_block = bytes([b ^ p for b, p in zip(block, prev)])
            elif mode == 'CTR':
                prev_enc, _ = self._encrypt_block(prev, block_size)
                enc_block = bytes([b ^ pe for b, pe in zip(block, prev_enc)])
                prev = (int.from_bytes(prev, 'big') + 1).to_bytes(block_bytes, 'big')
            else:
                raise ValueError(f"Unknown mode: {mode}")
            encrypted.extend(enc_block)
        return bytes(encrypted), block_size, iv

    def decrypt(self, data: bytes, block_size: int, mode='ECB', iv: bytes = None) -> bytes:
        dim = self.SUPPORTED_SIZES[block_size]
        block_bytes = dim[0] * dim[1] * dim[2]
        decrypted = bytearray()
        blocks = [data[i:i+block_bytes] for i in range(0, len(data), block_bytes)]
        if mode != 'ECB':
            if iv is None:
                raise ValueError("IV is required for this mode")
            prev = iv
        for block in blocks:
            if mode == 'ECB':
                dec_block = self._decrypt_block(block, block_size)
                decrypted_block = dec_block
            elif mode == 'CBC':
                dec_block = self._decrypt_block(block, block_size)
                decrypted_block = bytes([d ^ p for d, p in zip(dec_block, prev)])
                prev = block
            elif mode == 'CFB':
                prev_enc, _ = self._encrypt_block(prev, block_size)
                decrypted_block = bytes([b ^ pe for b, pe in zip(block, prev_enc)])
                prev = block
            elif mode == 'OFB':
                prev, _ = self._encrypt_block(prev, block_size)
                decrypted_block = bytes([b ^ p for b, p in zip(block, prev)])
            elif mode == 'CTR':
                prev_enc, _ = self._encrypt_block(prev, block_size)
                decrypted_block = bytes([b ^ pe for b, pe in zip(block, prev_enc)])
                prev = (int.from_bytes(prev, 'big') + 1).to_bytes(block_bytes, 'big')
            else:
                raise ValueError(f"Unknown mode: {mode}")
            decrypted.extend(decrypted_block)
        pad_len = decrypted[-1]
        if pad_len > 0 and pad_len <= block_bytes and all(b == pad_len for b in decrypted[-pad_len:]):
            decrypted = decrypted[:-pad_len]
        return bytes(decrypted)

    # ... остальные методы (kdf, encrypt_wbc_ctr_hmac, и т.п.) идут без изменений ...
    # Их можно оставить как в вашем последнем рабочем варианте

    # --- Для краткости, остальные методы опущены, копируйте их из вашей последней версии ---


    # ... остальные методы как в вашем предыдущем коде, без изменений ...

    def kdf(self, nonce: bytes) -> Tuple[bytes, bytes]:
        h = hashlib.sha512(self.key + nonce).digest()
        return h[:32], h[32:64]

    def encrypt_wbc_ctr_hmac(self, data: bytes, nonce: bytes = None) -> bytes:
        block_size = self.block_size or self._auto_block_size(len(data))
        dim = self.SUPPORTED_SIZES[block_size]
        block_bytes = dim[0] * dim[1] * dim[2]
        if nonce is None:
            nonce = os.urandom(NONCE_SIZE)
        assert len(nonce) == NONCE_SIZE
        key_crypt, key_mac = self.kdf(nonce)
        # self.operations = self._individualize_operations()  # УДАЛЕНО!
        pad_len = block_bytes - (len(data) % block_bytes)
        if pad_len == 0:
            pad_len = block_bytes
        pad_byte = pad_len if pad_len < 256 else pad_len % 256 or 1
        data_padded = data + bytes([pad_byte] * pad_len)
        encrypted = bytearray()
        counter = 0
        blocks = [data_padded[i:i+block_bytes] for i in range(0, len(data_padded), block_bytes)]
        counter_bytes_size = max(1, block_bytes - NONCE_SIZE)
        for block in blocks:
            counter_bytes = counter.to_bytes(counter_bytes_size, 'big')
            ctr = nonce + counter_bytes
            if len(ctr) < block_bytes:
                ctr += b'\x00' * (block_bytes - len(ctr))
            enc_ctr, _ = self._encrypt_block(ctr, block_size)
            enc_block = bytes([b ^ pe for b, pe in zip(block, enc_ctr)])
            encrypted.extend(enc_block)
            counter += 1
        ciphertext = bytes(encrypted)
        mac_data = MAGIC + VERSION + block_size.to_bytes(2, 'big') + nonce + ciphertext
        mac = hmac.new(key_mac, mac_data, hashlib.sha256).digest()
        output = MAGIC + VERSION + block_size.to_bytes(2, 'big') + nonce + ciphertext + mac
        return output

    def decrypt_wbc_ctr_hmac(self, file_bytes: bytes) -> bytes:
        if file_bytes[:4] != MAGIC:
            raise ValueError("Invalid file format: missing magic bytes.")
        if file_bytes[4:5] != VERSION:
            raise ValueError("Unsupported version.")
        block_size = int.from_bytes(file_bytes[5:7], 'big')
        nonce = file_bytes[7:7+NONCE_SIZE]
        mac_actual = file_bytes[-MAC_SIZE:]
        ciphertext = file_bytes[7+NONCE_SIZE:-MAC_SIZE]
        key_crypt, key_mac = self.kdf(nonce)
        # self.operations = self._individualize_operations()  # УДАЛЕНО!
        mac_data = file_bytes[:7+NONCE_SIZE] + ciphertext
        mac_expected = hmac.new(key_mac, mac_data, hashlib.sha256).digest()
        if not hmac.compare_digest(mac_actual, mac_expected):
            raise ValueError("MAC verification failed! Data is corrupted or wrong key.")
        dim = self.SUPPORTED_SIZES[block_size]
        block_bytes = dim[0] * dim[1] * dim[2]
        decrypted = bytearray()
        counter = 0
        blocks = [ciphertext[i:i+block_bytes] for i in range(0, len(ciphertext), block_bytes)]
        counter_bytes_size = max(1, block_bytes - NONCE_SIZE)
        for block in blocks:
            counter_bytes = counter.to_bytes(counter_bytes_size, 'big')
            ctr = nonce + counter_bytes
            if len(ctr) < block_bytes:
                ctr += b'\x00' * (block_bytes - len(ctr))
            enc_ctr, _ = self._encrypt_block(ctr, block_size)
            decrypted_block = bytes([b ^ pe for b, pe in zip(block, enc_ctr)])
            decrypted.extend(decrypted_block)
            counter += 1
        pad_len = decrypted[-1]
        if pad_len > 0 and pad_len <= block_bytes and all(b == pad_len for b in decrypted[-pad_len:]):
            decrypted = decrypted[:-pad_len]
        return bytes(decrypted)

    def generate_nist_test_data(self, size_kb: int = 1, num_samples: int = 10, mode='ECB', nonce=None) -> Dict[str, bytes]:
        test_sets = {}
        zero_data = bytes([0] * (size_kb * 1024))
        one_data = bytes([255] * (size_kb * 1024))
        alt_data = bytes([0b10101010] * (size_kb * 1024))
        counter_data = bytes([i % 256 for i in range(size_kb * 1024)])
        text = "The quick brown fox jumps over the lazy dog. " * ((size_kb * 1024) // 45)
        random_data = [os.urandom(size_kb * 1024) for _ in range(num_samples)]
        if mode == 'WBC-CTR-HMAC':
            test_sets['zero'] = self.encrypt_wbc_ctr_hmac(zero_data, nonce=nonce)
            test_sets['ones'] = self.encrypt_wbc_ctr_hmac(one_data, nonce=nonce)
            test_sets['alternating'] = self.encrypt_wbc_ctr_hmac(alt_data, nonce=nonce)
            test_sets['counter'] = self.encrypt_wbc_ctr_hmac(counter_data, nonce=nonce)
            test_sets['text'] = self.encrypt_wbc_ctr_hmac(text.encode('utf-8'), nonce=nonce)
            test_sets['random'] = b''.join(self.encrypt_wbc_ctr_hmac(d, nonce=nonce) for d in random_data)
        else:
            test_sets['zero'] = self.encrypt(zero_data, mode=mode)[0]
            test_sets['ones'] = self.encrypt(one_data, mode=mode)[0]
            test_sets['alternating'] = self.encrypt(alt_data, mode=mode)[0]
            test_sets['counter'] = self.encrypt(counter_data, mode=mode)[0]
            test_sets['text'] = self.encrypt(text.encode('utf-8'), mode=mode)[0]
            test_sets['random'] = b''.join(self.encrypt(d, mode=mode)[0] for d in random_data)
        return test_sets

    def save_nist_test_files(self, size_kb=1, num_samples=10, mode='ECB', nonce=None):
        test_sets = self.generate_nist_test_data(size_kb, num_samples, mode=mode, nonce=nonce)
        folder = f"nist_tests/{mode.lower()}"
        os.makedirs(folder, exist_ok=True)
        metadata = []
        for name, data in test_sets.items():
            filename = f"{folder}/wbc1_{name}_{size_kb}kb.bin"
            with open(filename, 'wb') as f:
                f.write(data)
            sha256 = hashlib.sha256(data).hexdigest()
            metadata.append({
                'name': name,
                'filename': filename,
                'size': len(data),
                'sha256': sha256,
                'description': self._get_test_description(name, num_samples)
            })
        with open(f"{folder}/metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2)
        print(f"\nNIST test files saved in '{folder}/' folder.")
        return metadata

    def _get_test_description(self, test_name: str, num_samples: int) -> str:
        descriptions = {
            'zero': "Zero-filled input data (all bytes 0x00)",
            'ones': "One-filled input data (all bytes 0xFF)",
            'alternating': "Alternating bit pattern (0xAA repeating)",
            'random': f"Random data samples ({num_samples} samples)",
            'counter': "Incrementing counter pattern (0x00 to 0xFF repeating)",
            'text': "English text data repeating 'The quick brown fox...'"
        }
        return descriptions.get(test_name, "Unknown test pattern")

    def show_rotation_operations_table(self):
        print("Rotation operations table (id, ascii, hex, type, args, description):")
        for op_id in sorted(self.operations):
            ascii_sym = chr(op_id) if 32 <= op_id <= 126 else '.'
            print(f"{op_id:3d}: {ascii_sym:2s} 0x{op_id:02x} {self.operations[op_id]}")

    def run_self_tests(self, mode='ECB', nonce=None):
        print("Running self-tests...\n")
        tests = [
            (b"Hello World!", "Short text"),
            (b"A"*64, "Exactly one block"),
            (b"B"*130, "Multi-block text"),
            (os.urandom(100), "Binary data"),
        ]
        passed = 0
        for data, label in tests:
            if mode == "WBC-CTR-HMAC":
                encrypted = self.encrypt_wbc_ctr_hmac(data, nonce=nonce)
                decrypted = self.decrypt_wbc_ctr_hmac(encrypted)
            else:
                encrypted, block_size, iv = self.encrypt(data, mode=mode)
                decrypted = self.decrypt(encrypted, block_size, mode=mode, iv=iv)
            ok = decrypted == data
            print(f"Test: {label}")
            print(f"  Result:     {'PASS' if ok else 'FAIL'}")
            if ok:
                passed += 1
        print(f"Test results: {passed}/{len(tests)} passed\n")

    def benchmark(self, sizes=(1, 10, 100, 1000, 10000, 100000, 1000000), mode='ECB', repeats=3, nonce=None):
        results = []
        for size in sizes:
            enc_times, oks = [], []
            for _ in range(repeats):
                data = os.urandom(size)
                if mode == "WBC-CTR-HMAC":
                    start = time.time()
                    encrypted = self.encrypt_wbc_ctr_hmac(data, nonce=nonce)
                    enc_time = time.time() - start
                    start = time.time()
                    decrypted = self.decrypt_wbc_ctr_hmac(encrypted)
                    dec_time = time.time() - start
                    ok = decrypted == data
                else:
                    block_size = self._auto_block_size(size)
                    start = time.time()
                    encrypted, block_size, iv = self.encrypt(data, mode=mode)
                    enc_time = time.time() - start
                    start = time.time()
                    decrypted = self.decrypt(encrypted, block_size, mode=mode, iv=iv)
                    dec_time = time.time() - start
                    ok = decrypted[:size] == data
                enc_times.append(enc_time + dec_time)
                oks.append(ok)
            avg_time = sum(enc_times)/len(enc_times)
            speed = (size/1024) / avg_time if avg_time > 0 else 0
            results.append((size, avg_time, speed, all(oks)))
        print(f"\nBenchmark results (mode={mode}):")
        print(f"{'Size (KB)':>10} {'Time (s)':>10} {'Speed (KB/s)':>14} {'Integrity'}")
        print("-" * 44)
        for size, t, speed, ok in results:
            print(f"{size/1024:10.2f} {t:10.5f} {speed:14.2f} {'OK' if ok else 'FAIL'}")

    def avalanche_test(self, data: bytes, mode='ECB', verbose=True, nonce=None) -> float:
        if mode == "WBC-CTR-HMAC":
            encrypted = self.encrypt_wbc_ctr_hmac(data, nonce=nonce)
            ciphertext = encrypted[7+NONCE_SIZE:-MAC_SIZE]
            encrypted_orig = ciphertext
            iv = None
            if nonce is None:
                print("Внимание: лавинный эффект для WBC-CTR-HMAC не интерпретируем из-за рандомного nonce.")
        else:
            encrypted_orig, block_size, iv = self.encrypt(data, mode=mode)
        total_bits = len(encrypted_orig) * 8
        flips = 0
        for i in range(len(data) * 8):
            flipped = bytearray(data)
            flipped[i // 8] ^= 1 << (i % 8)
            if mode == "WBC-CTR-HMAC":
                enc = self.encrypt_wbc_ctr_hmac(bytes(flipped), nonce=nonce)
                ciphertext_flipped = enc[7+NONCE_SIZE:-MAC_SIZE]
                if len(encrypted_orig) != len(ciphertext_flipped):
                    continue
                diff = int.from_bytes(encrypted_orig, 'big') ^ int.from_bytes(ciphertext_flipped, 'big')
            else:
                encrypted_flipped, _, _ = self.encrypt(bytes(flipped), mode=mode, iv=iv)
                diff = int.from_bytes(encrypted_orig, 'big') ^ int.from_bytes(encrypted_flipped, 'big')
            flips += bin(diff).count("1")
        avalanche = flips / (len(data)*8*total_bits)
        if verbose:
            print(f"Avalanche effect: {avalanche*100:.2f}% of output bits change on single input bit flip.")
        return avalanche

    def differential_test(self, data: bytes, mode='ECB', verbose=True, nonce=None) -> float:
        if mode == "WBC-CTR-HMAC":
            encrypted = self.encrypt_wbc_ctr_hmac(data, nonce=nonce)
            ciphertext_ref = encrypted[7+NONCE_SIZE:-MAC_SIZE]
            total_bits = len(ciphertext_ref) * 8
            flips = 0
            for i in range(32*8):
                mod_key = bytearray(self.key)
                mod_key[i // 8] ^= 1 << (i % 8)
                cipher = WBC1(bytes(mod_key))
                enc = cipher.encrypt_wbc_ctr_hmac(data, nonce=nonce)
                ciphertext_mod = enc[7+NONCE_SIZE:-MAC_SIZE]
                if len(ciphertext_ref) != len(ciphertext_mod):
                    continue
                diff = int.from_bytes(ciphertext_ref, 'big') ^ int.from_bytes(ciphertext_mod, 'big')
                flips += bin(diff).count("1")
            diff_effect = flips / (32*8*total_bits)
            if verbose:
                if nonce is None:
                    print("Внимание: differential_test для WBC-CTR-HMAC не интерпретируем из-за рандомного nonce.")
                print(f"Differential test: {diff_effect*100:.2f}% of output bits change on key bit flip.")
            return diff_effect
        else:
            encrypted_ref, block_size, iv = self.encrypt(data, mode=mode)
            total_bits = len(encrypted_ref) * 8
            flips = 0
            for i in range(32*8):
                mod_key = bytearray(self.key)
                mod_key[i // 8] ^= 1 << (i % 8)
                cipher = WBC1(bytes(mod_key))
                encrypted_mod, _, _ = cipher.encrypt(data, mode=mode, iv=iv)
                diff = int.from_bytes(encrypted_ref, 'big') ^ int.from_bytes(encrypted_mod, 'big')
                flips += bin(diff).count("1")
            diff_effect = flips / (32*8*total_bits)
            if verbose:
                print(f"Differential test: {diff_effect*100:.2f}% of output bits change on key bit flip.")
            return diff_effect

    def statistics_tests(self, data: bytes, ciphertext: bytes, plot_graphs=True):
        print("\n=== STATISTICAL TESTS ===")
        print(f"Shannon entropy (plain):  {shannon_entropy(data):.4f} bits/byte")
        print(f"Shannon entropy (cipher): {shannon_entropy(ciphertext):.4f} bits/byte")
        print(f"Chi-square (ciphertext):  {chi_square_uniform(ciphertext):.2f}")
        print(f"Correlation (plain↔cipher): {correlation(data, ciphertext):.4f}")
        reps, block_reps = repetition_test(ciphertext, 8)
        print(f"Repetition in cipher:     {reps} adjacent bytes repeated")
        print(f"Repeated 8-byte blocks:   {block_reps}")
        key_sens = key_sensitivity_test(WBC1, data, self.key)
        print(f"Key sensitivity:          {key_sens*100:.2f}% of output bits change on key bit flip.")
        if plot_graphs:
            plot_histogram(data, "Plaintext Byte Histogram")
            plot_histogram(ciphertext, "Ciphertext Byte Histogram")
            plot_bit_distribution(data, "Plaintext Bit Distribution")
            plot_bit_distribution(ciphertext, "Ciphertext Bit Distribution")



def select_mode():
    print("Выберите режим работы шифра:")
    print("1. ECB (Electronic Codebook)")
    print("2. CBC (Cipher Block Chaining)")
    print("3. CFB (Cipher Feedback)")
    print("4. OFB (Output Feedback)")
    print("5. CTR (Counter Mode)")
    print("6. WBC-CTR-HMAC (author special mode)")
    mode_map = {'1': 'ECB', '2': 'CBC', '3': 'CFB', '4': 'OFB', '5': 'CTR', '6': 'WBC-CTR-HMAC'}
    while True:
        m = input("Mode [1-6, по умолчанию 1]: ").strip()
        if not m:
            return 'ECB'
        if m in mode_map:
            return mode_map[m]
        print("Некорректный ввод.")

if __name__ == "__main__":
    while True:
        print("""
=== RUBIK'S CUBE CIPHER WBC1 (режимы) ===
1. Encrypt/decrypt text
2. Show rotation operations table
3. Run self-tests
4. Benchmark performance
5. Generate NIST test data
6. Дифференциальный и лавинный тест + статистика/графики
7. Exit

Select mode (1-7): """, end="")
        mode = input().strip()
        if mode == "1":
            text = input("Enter text to encrypt: ")
            chosen_mode = select_mode()
            auto = input("Generate key automatically? (y/n): ").strip().lower()
            if auto == "y":
                key = os.urandom(32)
                print(f"\nGenerated key: {key.hex()} (save this for decryption)\n")
            else:
                key = bytes.fromhex(input("Enter 32-byte key (in hex): "))
            rounds_input = input("Введите число раундов (по умолчанию 32): ").strip()
            rounds = int(rounds_input) if rounds_input else 32
            c = WBC1(key, rounds=rounds)
            if chosen_mode == 'WBC-CTR-HMAC':
                nonce_input = input("Введите nonce (12 байт, hex) или Enter для случайного: ").strip()
                if nonce_input:
                    nonce = bytes.fromhex(nonce_input)
                    if len(nonce) != NONCE_SIZE:
                        print(f"Неверная длина nonce! Использую случайный.")
                        nonce = None
                else:
                    nonce = None
                encrypted = c.encrypt_wbc_ctr_hmac(text.encode('utf-8'), nonce=nonce)
                print(f"\nEncrypted data (HEX): {encrypted.hex()}\n")
                decrypted = c.decrypt_wbc_ctr_hmac(encrypted)
                print(f"Decrypted text: {decrypted.decode('utf-8', errors='replace')}\n")
            else:
                iv = None
                if chosen_mode != 'ECB':
                    generate_iv = input("Generate IV automatically? (y/n): ").strip().lower()
                    if generate_iv == "y" or generate_iv == "":
                        iv = None
                    else:
                        iv = bytes.fromhex(input(f"Enter IV ({c._auto_block_size(len(text.encode('utf-8')))} bytes, hex): "))
                encrypted, block_size, actual_iv = c.encrypt(text.encode('utf-8'), mode=chosen_mode, iv=iv)
                print(f"\nEncrypted data (HEX): {encrypted.hex()}\n")
                if actual_iv:
                    print(f"IV (HEX): {actual_iv.hex()} (save this for decryption)\n")
                decrypted = c.decrypt(encrypted, block_size, mode=chosen_mode, iv=actual_iv)
                print(f"Decrypted text: {decrypted.decode('utf-8', errors='replace')}\n")
        elif mode == "2":
            key = os.urandom(32)
            c = WBC1(key)
            c.show_rotation_operations_table()
        elif mode == "3":
            chosen_mode = select_mode()
            auto = input("Generate key automatically? (y/n): ").strip().lower()
            if auto == "y":
                key = os.urandom(32)
                print(f"\nGenerated key: {key.hex()} (save this for decryption)\n")
            else:
                key = bytes.fromhex(input("Enter 32-byte key (in hex): "))
            rounds_input = input("Введите число раундов (по умолчанию 32): ").strip()
            rounds = int(rounds_input) if rounds_input else 32
            c = WBC1(key, rounds=rounds)
            nonce = None
            if chosen_mode == 'WBC-CTR-HMAC':
                nonce_input = input("Введите nonce (12 байт, hex) или Enter для случайного: ").strip()
                if nonce_input:
                    nonce = bytes.fromhex(nonce_input)
                    if len(nonce) != NONCE_SIZE:
                        print(f"Неверная длина nonce! Использую случайный.")
                        nonce = None
                else:
                    nonce = None
            c.run_self_tests(mode=chosen_mode, nonce=nonce)
        elif mode == "4":
            chosen_mode = select_mode()
            auto = input("Generate key automatically? (y/n): ").strip().lower()
            if auto == "y":
                key = os.urandom(32)
                print(f"\nGenerated key: {key.hex()} (save this for decryption)\n")
            else:
                key = bytes.fromhex(input("Enter 32-byte key (in hex): "))
            rounds_input = input("Введите число раундов (по умолчанию 32): ").strip()
            rounds = int(rounds_input) if rounds_input else 32
            c = WBC1(key, rounds=rounds)
            nonce = None
            if chosen_mode == 'WBC-CTR-HMAC':
                nonce_input = input("Введите nonce (12 байт, hex) или Enter для случайного: ").strip()
                if nonce_input:
                    nonce = bytes.fromhex(nonce_input)
                    if len(nonce) != NONCE_SIZE:
                        print(f"Неверная длина nonce! Использую случайный.")
                        nonce = None
                else:
                    nonce = None
            c.benchmark(mode=chosen_mode, nonce=nonce)
        elif mode == "5":
            print("=== Генерация тестовых данных для NIST STS / dieharder ===")
            nist_mode = select_mode()
            size_kb = int(input("Размер одного паттерна (в KB, например 128): ").strip() or "128")
            num_samples = int(input("Число random samples (например 10): ").strip() or "10")
            auto = input("Generate key automatically? (y/n): ").strip().lower()
            if auto == "y":
                key = os.urandom(32)
                print(f"\nGenerated key: {key.hex()} (save this for decryption)\n")
            else:
                key = bytes.fromhex(input("Enter 32-byte key (in hex): "))
            rounds_input = input("Введите число раундов (по умолчанию 32): ").strip()
            rounds = int(rounds_input) if rounds_input else 32
            nonce = None
            c = WBC1(key, rounds=rounds)
            if nist_mode == 'WBC-CTR-HMAC':
                nonce_input = input("Введите nonce (12 байт, hex) или Enter для случайного: ").strip()
                if nonce_input:
                    nonce = bytes.fromhex(nonce_input)
                    if len(nonce) != NONCE_SIZE:
                        print("Неверная длина nonce! Использую случайный.")
                        nonce = None
                else:
                    nonce = None
            c.save_nist_test_files(size_kb, num_samples, mode=nist_mode, nonce=nonce)
        elif mode == "6":
            print("=== Дифференциальный и лавинный тест + статистика/графики ===")
            text = input("Введите тестовый текст (по умолчанию случайные данные): ")
            chosen_mode = select_mode()
            if not text:
                data = os.urandom(64)
            else:
                data = text.encode("utf-8")
            auto = input("Generate key automatically? (y/n): ").strip().lower()
            if auto == "y":
                key = os.urandom(32)
                print(f"\nGenerated key: {key.hex()} (save this for decryption)\n")
            else:
                key = bytes.fromhex(input("Enter 32-byte key (in hex): "))
            rounds_input = input("Введите число раундов (по умолчанию 32): ").strip()
            rounds = int(rounds_input) if rounds_input else 32
            nonce = None
            if chosen_mode == 'WBC-CTR-HMAC':
                nonce_input = input("Введите nonce (12 байт, hex) или Enter для случайного: ").strip()
                if nonce_input:
                    nonce = bytes.fromhex(nonce_input)
                    if len(nonce) != NONCE_SIZE:
                        print(f"Неверная длина nonce! Использую случайный.")
                        nonce = None
                else:
                    nonce = None
                c = WBC1(key, rounds=rounds)
                encrypted = c.encrypt_wbc_ctr_hmac(data, nonce=nonce)
                ciphertext = encrypted[7+NONCE_SIZE:-MAC_SIZE]
            else:
                c = WBC1(key, rounds=rounds)
                encrypted, block_size, iv = c.encrypt(data, mode=chosen_mode)
                ciphertext = encrypted
            c.avalanche_test(data, mode=chosen_mode, nonce=nonce)
            c.differential_test(data, mode=chosen_mode, nonce=nonce)
            c.statistics_tests(data, ciphertext, plot_graphs=True)
        else:
            print("Bye!")
            break
