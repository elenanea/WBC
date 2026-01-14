#!/usr/bin/env python3
"""
Parallel implementation of WBC1 block cipher algorithm using MPI (mpi4py).

This implementation includes:
- WBC1 block cipher with S-box, permutation, XOR, and cyclic shifts
- Parallel processing using MPI for distributing blocks across processes
- Statistical tests: Shannon entropy, avalanche effect test
- Round key generation from master key
"""

import numpy as np
from mpi4py import MPI
import sys
from typing import List, Tuple, Optional, Dict
import hashlib
import json


# ===== Helper Functions for Bit Rotation and Cube Operations =====

def rotate_right(byte: int, n: int) -> int:
    """Rotate byte right by n bits."""
    return ((byte >> n) | (byte << (8 - n))) & 0xFF


def rotate_left(byte: int, n: int) -> int:
    """Rotate byte left by n bits."""
    return ((byte << n) | (byte >> (8 - n))) & 0xFF


def _bitwise_rotate_cube(cube: np.ndarray, n: int, direction: str) -> np.ndarray:
    """Apply bitwise rotation to all bytes in cube."""
    flat = cube.flatten()
    if direction == 'right':
        rotated = np.array([rotate_right(b, n % 8) for b in flat], dtype=np.uint8)
    else:
        rotated = np.array([rotate_left(b, n % 8) for b in flat], dtype=np.uint8)
    return rotated.reshape(cube.shape)


def _parse_alg_string(alg: str):
    """Parse Rubik's cube algorithm string into moves."""
    tokens = alg.replace(",", " ").split()
    return tokens


def build_127_ascii_operations(key: bytes) -> list:
    """
    Build 127 unique operations based on encryption key.
    Operations include Rubik's cube moves, algorithms, and dynamic patterns.
    """
    faces = ['U', 'D', 'L', 'R', 'F', 'B']
    directions = ['', "'", '2', '3']
    slices = ['M', 'E', 'S']
    wide_moves = ['u', 'd', 'l', 'r', 'f', 'b']
    cube_rot = ['x', 'y', 'z']
    
    # PLL Algorithms
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
    
    # Patterns
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
    
    # Build base operations
    base_ops = []
    
    # Face rotations
    for face in faces:
        for dir in directions:
            base_ops.append(('face', face, dir, f"Rotate {face} face {dir}"))
    
    # Slice moves
    for sl in slices:
        for dir in directions:
            base_ops.append(('slice', sl, dir, f"Rotate {sl} slice {dir}"))
    
    # Wide moves
    for move in wide_moves:
        for dir in directions:
            base_ops.append(('wide', move, dir, f"Wide move {move}{dir}"))
    
    # Cube rotations
    for rot in cube_rot:
        for dir in directions:
            base_ops.append(('cube', rot, dir, f"Cube rotation {rot}{dir}"))
    
    # Algorithms
    for name, alg in algs:
        base_ops.append(('alg', name, alg, f"Algorithm: {name}"))
    
    # Patterns
    for name, pattern in patterns:
        base_ops.append(('pattern', name, pattern, f"Pattern: {name}"))
    
    # Swap operations
    for axis in range(3):
        for k in range(4):
            base_ops.append(('swap', axis, k, f"Swap axis={axis}, offset={k}"))
    
    # Diagonal flip operations
    for axis in range(3):
        base_ops.append(('diagflip', axis, '', f"Diagonal flip axis={axis}"))
    
    static_ops = base_ops[:]
    
    # Generate dynamic operations
    dynamic_ops = []
    for i in range(20):
        seed = int(hashlib.sha256(key + i.to_bytes(2, "little")).hexdigest(), 16) & 0xFFFFFFFF
        rng = np.random.RandomState(seed)
        ops = []
        n_ops = rng.randint(4, 8)  # 4-7 operations
        for _ in range(n_ops):
            op = static_ops[rng.randint(0, len(static_ops))]
            ops.append(op)
        dynamic_ops.append(('dynamic', i, ops, f"Dynamic pattern {i}"))
    
    all_ops = static_ops + dynamic_ops
    
    # Generate 127 unique operation chains
    op_list = []
    seen = set()
    for i in range(127):
        attempt = 0
        while True:
            seed = int(hashlib.sha256(
                key + b"WBC1_OP" + i.to_bytes(2, 'little') + attempt.to_bytes(2, 'little')
            ).hexdigest(), 16) & 0xFFFFFFFF
            rng = np.random.RandomState(seed)
            chain_len = rng.randint(3, 7)  # 3-6 operations per chain
            chain = tuple(all_ops[rng.randint(0, len(all_ops))] for _ in range(chain_len))
            chain_serialized = str(chain)
            if chain_serialized not in seen:
                seen.add(chain_serialized)
                op_list.append(('dynamic', i, list(chain), f"Dynamic ASCII op {i+1}"))
                break
            attempt += 1
            if attempt > 1000:  # Safety limit
                op_list.append(('dynamic', i, [all_ops[i % len(all_ops)]], f"Dynamic ASCII op {i+1}"))
                break
    
    return op_list


class WBC1Cipher:
    """WBC1 block cipher implementation with configurable parameters."""
    
    def __init__(self, key: bytes, block_size: int = 16, num_rounds: int = 16):
        """
        Initialize WBC1 cipher.
        
        Args:
            key: Master encryption key (bytes)
            block_size: Size of each block in bytes (default: 16)
            num_rounds: Number of encryption rounds (default: 16)
        """
        self.block_size = block_size
        self.num_rounds = num_rounds
        self.key = key
        
        # Generate S-box and inverse S-box
        self.sbox = self._generate_sbox()
        self.inv_sbox = self._generate_inverse_sbox()
        
        # Generate permutation table
        self.perm_table = self._generate_permutation()
        self.inv_perm_table = self._generate_inverse_permutation()
        
        # Generate round keys
        self.round_keys = self._generate_round_keys()
        
        # Generate dynamic operations for enhanced security
        self._base_operations = build_127_ascii_operations(self.key)
        self.operations = self._individualize_operations()
    
    def _generate_sbox(self) -> np.ndarray:
        """Generate S-box using key-dependent transformation."""
        # Create a pseudo-random S-box based on the key
        seed = int.from_bytes(hashlib.sha256(self.key).digest()[:4], 'big')
        rng = np.random.RandomState(seed)
        sbox = np.arange(256, dtype=np.uint8)
        rng.shuffle(sbox)
        return sbox
    
    def _generate_inverse_sbox(self) -> np.ndarray:
        """Generate inverse S-box."""
        inv_sbox = np.zeros(256, dtype=np.uint8)
        for i in range(256):
            inv_sbox[self.sbox[i]] = i
        return inv_sbox
    
    def _generate_permutation(self) -> np.ndarray:
        """Generate bit permutation table."""
        seed = int.from_bytes(hashlib.sha256(self.key + b'perm').digest()[:4], 'big')
        rng = np.random.RandomState(seed)
        perm = np.arange(self.block_size * 8, dtype=np.int32)
        rng.shuffle(perm)
        return perm
    
    def _generate_inverse_permutation(self) -> np.ndarray:
        """Generate inverse permutation table."""
        inv_perm = np.zeros(self.block_size * 8, dtype=np.int32)
        for i in range(self.block_size * 8):
            inv_perm[self.perm_table[i]] = i
        return inv_perm
    
    def _generate_round_keys(self) -> List[np.ndarray]:
        """Generate round keys from master key."""
        round_keys = []
        for round_num in range(self.num_rounds):
            # Use SHA-256 to derive round key
            key_material = hashlib.sha256(
                self.key + round_num.to_bytes(4, 'big')
            ).digest()
            round_key = np.frombuffer(
                key_material[:self.block_size], 
                dtype=np.uint8
            )
            round_keys.append(round_key)
        return round_keys
    
    def _individualize_operations(self) -> Dict[int, Tuple]:
        """Sort operations by hash for key-dependent ordering."""
        ops = self._base_operations[:]
        
        def op_sort_key(op):
            # Convert tuple to serializable structure for hashing
            serializable = [str(x) for x in op]
            h = hashlib.sha256(
                json.dumps(serializable, sort_keys=True).encode() + self.key
            ).digest()
            return h
        
        ops.sort(key=op_sort_key)
        return {i: op for i, op in enumerate(ops)}
    
    def _substitute_bytes(self, block: np.ndarray) -> np.ndarray:
        """Apply S-box substitution to block."""
        return self.sbox[block]
    
    def _inverse_substitute_bytes(self, block: np.ndarray) -> np.ndarray:
        """Apply inverse S-box substitution to block."""
        return self.inv_sbox[block]
    
    def _permute_bits(self, block: np.ndarray) -> np.ndarray:
        """Apply bit-level permutation to block."""
        # Convert to bit array
        bits = np.unpackbits(block)
        # Apply permutation
        permuted_bits = bits[self.perm_table]
        # Convert back to bytes
        return np.packbits(permuted_bits)
    
    def _inverse_permute_bits(self, block: np.ndarray) -> np.ndarray:
        """Apply inverse bit-level permutation to block."""
        bits = np.unpackbits(block)
        inv_permuted_bits = bits[self.inv_perm_table]
        return np.packbits(inv_permuted_bits)
    
    def _rotate_left(self, block: np.ndarray, shift: int) -> np.ndarray:
        """Cyclic left shift of bytes in block."""
        shift = shift % self.block_size
        return np.concatenate([block[shift:], block[:shift]])
    
    def _rotate_right(self, block: np.ndarray, shift: int) -> np.ndarray:
        """Cyclic right shift of bytes in block."""
        shift = shift % self.block_size
        return np.concatenate([block[-shift:], block[:-shift]]) if shift > 0 else block
    
    def _xor_with_key(self, block: np.ndarray, round_key: np.ndarray) -> np.ndarray:
        """XOR block with round key."""
        return block ^ round_key
    
    def _apply_operation(self, block: np.ndarray, op_id: int, inverse=False) -> np.ndarray:
        """
        Apply a dynamic operation to the block.
        Note: This is a simplified version for fixed block sizes.
        The full cube operations require 3D reshaping which is not compatible
        with arbitrary block sizes. This applies the operation concept using
        permutation and XOR based on the operation ID.
        """
        op = self.operations[op_id % len(self.operations)]
        op_type = op[0]
        
        # For dynamic operations, apply the sequence
        if op_type == 'dynamic':
            for subop in (reversed(op[2]) if inverse else op[2]):
                block = self._apply_single_operation(block, subop, inverse)
            return block
        
        return self._apply_single_operation(block, op, inverse)
    
    def _apply_single_operation(self, block: np.ndarray, op, inverse=False) -> np.ndarray:
        """
        Apply a single operation. Simplified for compatibility with fixed block sizes.
        Uses operation metadata to derive a deterministic transformation.
        """
        # Generate a deterministic permutation based on operation
        op_hash = hashlib.sha256(str(op).encode() + self.key).digest()
        seed = int.from_bytes(op_hash[:4], 'big')
        rng = np.random.RandomState(seed)
        
        # Create a byte-level permutation
        perm = np.arange(self.block_size, dtype=np.int32)
        rng.shuffle(perm)
        
        if inverse:
            # Apply inverse permutation
            inv_perm = np.zeros(self.block_size, dtype=np.int32)
            for i in range(self.block_size):
                inv_perm[perm[i]] = i
            return block[inv_perm]
        else:
            # Apply forward permutation
            return block[perm]
    
    def encrypt_block(self, plaintext_block: np.ndarray) -> np.ndarray:
        """
        Encrypt a single block.
        
        Args:
            plaintext_block: Input block as numpy array of uint8
            
        Returns:
            Encrypted block as numpy array of uint8
        """
        if len(plaintext_block) != self.block_size:
            raise ValueError(f"Block size must be {self.block_size} bytes")
        
        state = plaintext_block.copy()
        
        # Initial round key addition
        state = self._xor_with_key(state, self.round_keys[0])
        
        # Main rounds with dynamic operations
        for round_num in range(1, self.num_rounds):
            # Apply dynamic operation based on round key
            op_id = self.round_keys[round_num][0] % len(self.operations)
            state = self._apply_operation(state, op_id, inverse=False)
            
            # Substitution layer
            state = self._substitute_bytes(state)
            
            # Diffusion: cumulative XOR (forward)
            for i in range(1, len(state)):
                state[i] ^= state[i-1]
            
            # Permutation layer
            state = self._permute_bits(state)
            
            # Bitwise rotation based on operation ID
            state_flat = state.copy()
            for i in range(len(state_flat)):
                state_flat[i] = rotate_right(int(state_flat[i]), op_id % 8)
            state = state_flat
            
            # Cyclic shift
            state = self._rotate_left(state, round_num % self.block_size)
            
            # Key mixing
            state = self._xor_with_key(state, self.round_keys[round_num])
        
        # Final substitution
        state = self._substitute_bytes(state)
        
        return state
    
    def decrypt_block(self, ciphertext_block: np.ndarray) -> np.ndarray:
        """
        Decrypt a single block.
        
        Args:
            ciphertext_block: Input block as numpy array of uint8
            
        Returns:
            Decrypted block as numpy array of uint8
        """
        if len(ciphertext_block) != self.block_size:
            raise ValueError(f"Block size must be {self.block_size} bytes")
        
        state = ciphertext_block.copy()
        
        # Inverse final substitution
        state = self._inverse_substitute_bytes(state)
        
        # Inverse main rounds with dynamic operations
        for round_num in range(self.num_rounds - 1, 0, -1):
            # Inverse key mixing
            state = self._xor_with_key(state, self.round_keys[round_num])
            
            # Inverse cyclic shift
            state = self._rotate_right(state, round_num % self.block_size)
            
            # Inverse bitwise rotation
            op_id = self.round_keys[round_num][0] % len(self.operations)
            state_flat = state.copy()
            for i in range(len(state_flat)):
                state_flat[i] = rotate_left(int(state_flat[i]), op_id % 8)
            state = state_flat
            
            # Inverse permutation
            state = self._inverse_permute_bits(state)
            
            # Inverse diffusion: cumulative XOR (backward)
            for i in range(len(state)-1, 0, -1):
                state[i] ^= state[i-1]
            
            # Inverse substitution
            state = self._inverse_substitute_bytes(state)
            
            # Apply inverse dynamic operation
            state = self._apply_operation(state, op_id, inverse=True)
        
        # Inverse initial round key addition
        state = self._xor_with_key(state, self.round_keys[0])
        
        return state


class ParallelWBC1:
    """Parallel implementation of WBC1 using MPI."""
    
    def __init__(self, key: bytes, block_size: int = 16, num_rounds: int = 16):
        """
        Initialize parallel WBC1.
        
        Args:
            key: Master encryption key
            block_size: Size of each block in bytes
            num_rounds: Number of encryption rounds
        """
        self.comm = MPI.COMM_WORLD
        self.rank = self.comm.Get_rank()
        self.size = self.comm.Get_size()
        
        # Each process creates its own cipher instance with same parameters
        self.cipher = WBC1Cipher(key, block_size, num_rounds)
        self.block_size = block_size
    
    def _pad_data(self, data: bytes) -> bytes:
        """Apply PKCS7 padding to data."""
        padding_length = self.block_size - (len(data) % self.block_size)
        if padding_length == 0:
            padding_length = self.block_size
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _unpad_data(self, data: bytes) -> bytes:
        """Remove PKCS7 padding from data."""
        if len(data) == 0:
            return data
        padding_length = data[-1]
        if padding_length > self.block_size or padding_length == 0:
            return data
        # Verify padding
        if data[-padding_length:] == bytes([padding_length] * padding_length):
            return data[:-padding_length]
        return data
    
    def _split_into_blocks(self, data: bytes) -> List[np.ndarray]:
        """Split data into blocks."""
        blocks = []
        for i in range(0, len(data), self.block_size):
            block = np.frombuffer(
                data[i:i + self.block_size], 
                dtype=np.uint8
            ).copy()
            blocks.append(block)
        return blocks
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext using parallel processing.
        
        Args:
            plaintext: Input plaintext bytes
            
        Returns:
            Encrypted ciphertext bytes
        """
        if self.rank == 0:
            # Master process: prepare data
            padded_data = self._pad_data(plaintext)
            blocks = self._split_into_blocks(padded_data)
            num_blocks = len(blocks)
        else:
            blocks = None
            num_blocks = None
        
        # Broadcast number of blocks to all processes
        num_blocks = self.comm.bcast(num_blocks, root=0)
        
        # Scatter blocks to all processes
        # Calculate distribution
        blocks_per_process = num_blocks // self.size
        remainder = num_blocks % self.size
        
        if self.rank == 0:
            # Master prepares send counts and displacements
            send_counts = [blocks_per_process + (1 if i < remainder else 0) 
                          for i in range(self.size)]
            displacements = [sum(send_counts[:i]) for i in range(self.size)]
            
            # Flatten blocks for scattering
            all_blocks_flat = []
            for block in blocks:
                all_blocks_flat.extend(block.tolist())
            all_blocks_flat = np.array(all_blocks_flat, dtype=np.uint8)
        else:
            send_counts = None
            displacements = None
            all_blocks_flat = None
        
        # Broadcast send_counts
        send_counts = self.comm.bcast(send_counts, root=0)
        
        # Calculate receive count for this process
        recv_count = send_counts[self.rank] * self.block_size
        
        # Prepare receive buffer
        local_blocks_flat = np.zeros(recv_count, dtype=np.uint8)
        
        # Adjust send_counts and displacements for byte-level scatter
        if self.rank == 0:
            send_counts_bytes = [c * self.block_size for c in send_counts]
            displacements_bytes = [d * self.block_size for d in displacements]
        else:
            send_counts_bytes = None
            displacements_bytes = None
        
        # Scatter blocks
        self.comm.Scatterv(
            [all_blocks_flat, send_counts_bytes, displacements_bytes, MPI.BYTE] if self.rank == 0 else None,
            local_blocks_flat,
            root=0
        )
        
        # Reshape received data into blocks
        num_local_blocks = send_counts[self.rank]
        local_blocks = [local_blocks_flat[i*self.block_size:(i+1)*self.block_size] 
                       for i in range(num_local_blocks)]
        
        # Encrypt local blocks
        encrypted_local_blocks = []
        for block in local_blocks:
            encrypted_block = self.cipher.encrypt_block(block)
            encrypted_local_blocks.append(encrypted_block)
        
        # Flatten encrypted blocks
        encrypted_local_flat = np.concatenate(encrypted_local_blocks) if encrypted_local_blocks else np.array([], dtype=np.uint8)
        
        # Gather encrypted blocks at master
        if self.rank == 0:
            recv_counts_bytes = [c * self.block_size for c in send_counts]
            displacements_bytes = [d * self.block_size for d in displacements]
            all_encrypted_flat = np.zeros(num_blocks * self.block_size, dtype=np.uint8)
        else:
            recv_counts_bytes = None
            displacements_bytes = None
            all_encrypted_flat = None
        
        self.comm.Gatherv(
            encrypted_local_flat,
            [all_encrypted_flat, recv_counts_bytes, displacements_bytes, MPI.BYTE] if self.rank == 0 else None,
            root=0
        )
        
        if self.rank == 0:
            return all_encrypted_flat.tobytes()
        else:
            return None
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext using parallel processing.
        
        Args:
            ciphertext: Input ciphertext bytes
            
        Returns:
            Decrypted plaintext bytes
        """
        if self.rank == 0:
            # Master process: prepare data
            blocks = self._split_into_blocks(ciphertext)
            num_blocks = len(blocks)
        else:
            blocks = None
            num_blocks = None
        
        # Broadcast number of blocks
        num_blocks = self.comm.bcast(num_blocks, root=0)
        
        # Calculate distribution
        blocks_per_process = num_blocks // self.size
        remainder = num_blocks % self.size
        
        if self.rank == 0:
            send_counts = [blocks_per_process + (1 if i < remainder else 0) 
                          for i in range(self.size)]
            displacements = [sum(send_counts[:i]) for i in range(self.size)]
            
            all_blocks_flat = []
            for block in blocks:
                all_blocks_flat.extend(block.tolist())
            all_blocks_flat = np.array(all_blocks_flat, dtype=np.uint8)
        else:
            send_counts = None
            all_blocks_flat = None
        
        send_counts = self.comm.bcast(send_counts, root=0)
        recv_count = send_counts[self.rank] * self.block_size
        local_blocks_flat = np.zeros(recv_count, dtype=np.uint8)
        
        if self.rank == 0:
            send_counts_bytes = [c * self.block_size for c in send_counts]
            displacements_bytes = [d * self.block_size for d in displacements]
        else:
            send_counts_bytes = None
            displacements_bytes = None
        
        self.comm.Scatterv(
            [all_blocks_flat, send_counts_bytes, displacements_bytes, MPI.BYTE] if self.rank == 0 else None,
            local_blocks_flat,
            root=0
        )
        
        num_local_blocks = send_counts[self.rank]
        local_blocks = [local_blocks_flat[i*self.block_size:(i+1)*self.block_size] 
                       for i in range(num_local_blocks)]
        
        # Decrypt local blocks
        decrypted_local_blocks = []
        for block in local_blocks:
            decrypted_block = self.cipher.decrypt_block(block)
            decrypted_local_blocks.append(decrypted_block)
        
        decrypted_local_flat = np.concatenate(decrypted_local_blocks) if decrypted_local_blocks else np.array([], dtype=np.uint8)
        
        # Gather decrypted blocks at master
        if self.rank == 0:
            recv_counts_bytes = [c * self.block_size for c in send_counts]
            displacements_bytes = [d * self.block_size for d in displacements]
            all_decrypted_flat = np.zeros(num_blocks * self.block_size, dtype=np.uint8)
        else:
            recv_counts_bytes = None
            displacements_bytes = None
            all_decrypted_flat = None
        
        self.comm.Gatherv(
            decrypted_local_flat,
            [all_decrypted_flat, recv_counts_bytes, displacements_bytes, MPI.BYTE] if self.rank == 0 else None,
            root=0
        )
        
        if self.rank == 0:
            decrypted_data = all_decrypted_flat.tobytes()
            return self._unpad_data(decrypted_data)
        else:
            return None


# Statistical Testing Functions

def shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data.
    
    Args:
        data: Input data bytes
        
    Returns:
        Shannon entropy value
    """
    if len(data) == 0:
        return 0.0
    
    # Count frequency of each byte value
    frequency = np.zeros(256, dtype=np.int64)
    for byte in data:
        frequency[byte] += 1
    
    # Calculate probabilities
    probabilities = frequency[frequency > 0] / len(data)
    
    # Calculate entropy
    entropy = -np.sum(probabilities * np.log2(probabilities))
    
    return entropy


def avalanche_test(cipher: WBC1Cipher, num_tests: int = 1000) -> dict:
    """
    Test avalanche effect of the cipher.
    
    The avalanche effect means that changing a single bit in the input
    should change approximately 50% of the output bits.
    
    Args:
        cipher: WBC1Cipher instance
        num_tests: Number of test iterations
        
    Returns:
        Dictionary with test results
    """
    bit_flip_percentages = []
    
    for _ in range(num_tests):
        # Generate random plaintext block
        plaintext = np.random.randint(0, 256, cipher.block_size, dtype=np.uint8)
        
        # Encrypt original
        ciphertext1 = cipher.encrypt_block(plaintext)
        
        # Flip one random bit in plaintext
        bit_position = np.random.randint(0, cipher.block_size * 8)
        byte_index = bit_position // 8
        bit_index = bit_position % 8
        
        plaintext_flipped = plaintext.copy()
        plaintext_flipped[byte_index] ^= (1 << bit_index)
        
        # Encrypt modified plaintext
        ciphertext2 = cipher.encrypt_block(plaintext_flipped)
        
        # Count bit differences
        diff = ciphertext1 ^ ciphertext2
        bits_changed = np.unpackbits(diff).sum()
        total_bits = cipher.block_size * 8
        flip_percentage = (bits_changed / total_bits) * 100
        
        bit_flip_percentages.append(flip_percentage)
    
    results = {
        'mean_flip_percentage': np.mean(bit_flip_percentages),
        'std_flip_percentage': np.std(bit_flip_percentages),
        'min_flip_percentage': np.min(bit_flip_percentages),
        'max_flip_percentage': np.max(bit_flip_percentages),
        'num_tests': num_tests
    }
    
    return results


def frequency_test(data: bytes) -> dict:
    """
    Perform frequency test on data.
    
    Args:
        data: Input data bytes
        
    Returns:
        Dictionary with frequency statistics
    """
    if len(data) == 0:
        return {'mean': 0, 'std': 0, 'min': 0, 'max': 0}
    
    frequency = np.zeros(256, dtype=np.int64)
    for byte in data:
        frequency[byte] += 1
    
    return {
        'mean': np.mean(frequency),
        'std': np.std(frequency),
        'min': np.min(frequency),
        'max': np.max(frequency),
        'chi_square': np.sum((frequency - len(data)/256)**2 / (len(data)/256)) if len(data) > 0 else 0
    }


def correlation_test(data1: bytes, data2: bytes) -> float:
    """
    Calculate correlation between two data sequences.
    
    Args:
        data1: First data sequence
        data2: Second data sequence
        
    Returns:
        Correlation coefficient
    """
    if len(data1) != len(data2) or len(data1) == 0:
        return 0.0
    
    arr1 = np.frombuffer(data1, dtype=np.uint8).astype(np.float64)
    arr2 = np.frombuffer(data2, dtype=np.uint8).astype(np.float64)
    
    correlation = np.corrcoef(arr1, arr2)[0, 1]
    
    return correlation if not np.isnan(correlation) else 0.0


def run_statistical_tests(plaintext: bytes, ciphertext: bytes, cipher: WBC1Cipher) -> dict:
    """
    Run comprehensive statistical tests.
    
    Args:
        plaintext: Original plaintext
        ciphertext: Encrypted ciphertext
        cipher: Cipher instance for avalanche test
        
    Returns:
        Dictionary with all test results
    """
    results = {
        'plaintext_entropy': shannon_entropy(plaintext),
        'ciphertext_entropy': shannon_entropy(ciphertext),
        'plaintext_frequency': frequency_test(plaintext),
        'ciphertext_frequency': frequency_test(ciphertext),
        'correlation': correlation_test(plaintext, ciphertext),
        'avalanche_effect': avalanche_test(cipher, num_tests=100)
    }
    
    return results


def main():
    """Main function demonstrating parallel WBC1 usage."""
    # Initialize MPI
    comm = MPI.COMM_WORLD
    rank = comm.Get_rank()
    size = comm.Get_size()
    
    # Configuration
    master_key = b"MySecretKey12345"  # 16-byte key
    block_size = 16
    num_rounds = 16
    
    # Create parallel cipher
    parallel_cipher = ParallelWBC1(master_key, block_size, num_rounds)
    
    if rank == 0:
        print(f"=== Parallel WBC1 Cipher Demo ===")
        print(f"Number of MPI processes: {size}")
        print(f"Block size: {block_size} bytes")
        print(f"Number of rounds: {num_rounds}")
        print()
        
        # Test data
        plaintext = b"Hello, this is a test message for parallel WBC1 encryption! " * 4
        print(f"Original plaintext length: {len(plaintext)} bytes")
        print(f"Original plaintext: {plaintext[:80]}...")
        print()
    else:
        plaintext = None
    
    # Encrypt
    ciphertext = parallel_cipher.encrypt(plaintext)
    
    if rank == 0:
        print(f"Encrypted ciphertext length: {len(ciphertext)} bytes")
        print(f"Ciphertext (hex): {ciphertext[:40].hex()}...")
        print()
    
    # Decrypt
    decrypted = parallel_cipher.decrypt(ciphertext)
    
    if rank == 0:
        print(f"Decrypted plaintext length: {len(decrypted)} bytes")
        print(f"Decrypted plaintext: {decrypted[:80]}...")
        print()
        
        # Verify correctness
        if plaintext == decrypted:
            print("✓ Encryption/Decryption successful!")
        else:
            print("✗ Encryption/Decryption failed!")
        print()
        
        # Run statistical tests
        print("=== Statistical Tests ===")
        cipher = WBC1Cipher(master_key, block_size, num_rounds)
        test_results = run_statistical_tests(plaintext, ciphertext, cipher)
        
        print(f"Plaintext entropy: {test_results['plaintext_entropy']:.4f} bits")
        print(f"Ciphertext entropy: {test_results['ciphertext_entropy']:.4f} bits")
        print(f"Correlation: {test_results['correlation']:.6f}")
        print()
        
        print("Frequency Test (Plaintext):")
        print(f"  Mean: {test_results['plaintext_frequency']['mean']:.2f}")
        print(f"  Std: {test_results['plaintext_frequency']['std']:.2f}")
        print(f"  Chi-square: {test_results['plaintext_frequency']['chi_square']:.2f}")
        print()
        
        print("Frequency Test (Ciphertext):")
        print(f"  Mean: {test_results['ciphertext_frequency']['mean']:.2f}")
        print(f"  Std: {test_results['ciphertext_frequency']['std']:.2f}")
        print(f"  Chi-square: {test_results['ciphertext_frequency']['chi_square']:.2f}")
        print()
        
        print("Avalanche Effect Test:")
        avalanche = test_results['avalanche_effect']
        print(f"  Mean flip percentage: {avalanche['mean_flip_percentage']:.2f}%")
        print(f"  Std deviation: {avalanche['std_flip_percentage']:.2f}%")
        print(f"  Min: {avalanche['min_flip_percentage']:.2f}%")
        print(f"  Max: {avalanche['max_flip_percentage']:.2f}%")
        print(f"  (Ideal avalanche effect is around 50%)")


def interactive_demo():
    """
    Interactive demonstration of WBC1 cipher with hardcoded text.
    User can select key, rounds, and encryption mode interactively.
    """
    comm = MPI.COMM_WORLD
    rank = comm.Get_rank()
    
    # Hardcoded demonstration text
    DEMO_TEXT = "This is a demonstration of the WBC1 parallel cipher with dynamic Rubik's cube permutation operations!"
    
    if rank == 0:
        print("=" * 70)
        print("   ИНТЕРАКТИВНАЯ ДЕМОНСТРАЦИЯ WBC1 / Interactive WBC1 Demo")
        print("=" * 70)
        print()
        print(f"Демонстрационный текст / Demo text:")
        print(f"  '{DEMO_TEXT}'")
        print()
        print("=" * 70)
        print()
        
        # Get key selection
        print("1. ВЫБОР КЛЮЧА / KEY SELECTION")
        print()
        print("  1) Ввести свой ключ (Enter custom key)")
        print("  2) Сгенерировать автоматически (Generate automatically)")
        print()
        
        choice = input("  Ваш выбор / Your choice (1/2): ").strip()
        print(f"  ✓ Выбрано / Selected: {choice}")
        print()
        
        if choice == "1":
            key_str = input("  Введите ключ / Enter key: ")
            print(f"  ✓ Ключ введён / Key entered: {key_str[:20]}{'...' if len(key_str) > 20 else ''}")
            print()
            key = key_str.encode('utf-8')
            key_source = "пользовательский / user-provided"
        else:
            print("2. ДЛИНА КЛЮЧА / KEY LENGTH")
            print()
            print("  Рекомендуемые значения / Recommended values:")
            print("  1) 16 байт (128 бит) / 16 bytes (128 bits)")
            print("  2) 24 байта (192 бита) / 24 bytes (192 bits)")
            print("  3) 32 байта (256 бит) / 32 bytes (256 bits)")
            print("  4) Другая длина / Custom")
            print()
            
            length_choice = input("  Ваш выбор / Your choice (1-4): ").strip()
            print(f"  ✓ Выбрано / Selected: {length_choice}")
            print()
            
            if length_choice == "1":
                length = 16
            elif length_choice == "2":
                length = 24
            elif length_choice == "3":
                length = 32
            else:
                try:
                    length = int(input("  Введите длину ключа в байтах / Enter key length in bytes: "))
                    print(f"  ✓ Введено / Entered: {length} байт / bytes")
                    print()
                    if length < 8:
                        print("  ⚠ Предупреждение: длина меньше 8 байт небезопасна!")
                        print("  ⚠ Warning: length less than 8 bytes is insecure!")
                        length = max(8, length)
                except ValueError:
                    print("  ⚠ Некорректный ввод, используется 16 байт")
                    print("  ⚠ Invalid input, using 16 bytes")
                    length = 16
            
            import secrets
            key = secrets.token_bytes(length)
            key_source = f"сгенерирован / generated ({length} байт / bytes)"
        
        # Get rounds
        print("=" * 70)
        print()
        print("3. КОЛИЧЕСТВО РАУНДОВ / NUMBER OF ROUNDS")
        print()
        print("  Рекомендуемые значения / Recommended values:")
        print("  1) 10 раундов (быстрее / faster)")
        print("  2) 16 раундов (рекомендуется / recommended)")
        print("  3) 20 раундов (медленнее, безопаснее / slower, more secure)")
        print("  4) 32 раунда (максимальная безопасность / maximum security)")
        print("  5) Другое значение / Custom")
        print()
        
        rounds_choice = input("  Ваш выбор / Your choice (1-5): ").strip()
        print(f"  ✓ Выбрано / Selected: {rounds_choice}")
        print()
        
        if rounds_choice == "1":
            num_rounds = 10
        elif rounds_choice == "2":
            num_rounds = 16
        elif rounds_choice == "3":
            num_rounds = 20
        elif rounds_choice == "4":
            num_rounds = 32
        else:
            try:
                num_rounds = int(input("  Введите количество раундов / Enter number of rounds: "))
                print(f"  ✓ Введено / Entered: {num_rounds} раундов / rounds")
                print()
                num_rounds = max(1, num_rounds)
            except ValueError:
                print("  ⚠ Некорректный ввод, используется 16 раундов")
                print("  ⚠ Invalid input, using 16 rounds")
                num_rounds = 16
        
        # Get mode
        print("=" * 70)
        print()
        print("4. РЕЖИМ ШИФРОВАНИЯ / ENCRYPTION MODE")
        print()
        print("  1) ECB (Electronic Codebook) - Параллельный / Parallel")
        print("  2) CBC (Cipher Block Chaining)")
        print("  3) CFB (Cipher Feedback)")
        print("  4) OFB (Output Feedback)")
        print("  5) CTR (Counter mode) - Параллельный / Parallel")
        print("  6) Parallel MPI (полное параллельное шифрование / full parallel encryption)")
        print()
        
        mode_choice = input("  Ваш выбор / Your choice (1-6): ").strip()
        print(f"  ✓ Выбрано / Selected: {mode_choice}")
        print()
        
        mode_map = {
            "1": "ECB",
            "2": "CBC",
            "3": "CFB",
            "4": "OFB",
            "5": "CTR",
            "6": "Parallel"
        }
        
        mode = mode_map.get(mode_choice, "ECB")
        
        # Summary
        print("=" * 70)
        print("ПАРАМЕТРЫ ШИФРОВАНИЯ / ENCRYPTION PARAMETERS")
        print("=" * 70)
        print(f"Текст / Text: {DEMO_TEXT[:50]}...")
        print(f"Длина текста / Text length: {len(DEMO_TEXT)} символов / characters")
        print(f"Ключ / Key: {key_source}")
        print(f"Длина ключа / Key length: {len(key)} байт / bytes ({len(key)*8} бит / bits)")
        print(f"Ключ (hex): {key.hex()[:40]}...")
        print(f"Количество раундов / Rounds: {num_rounds}")
        print(f"Режим / Mode: {mode}")
        print("=" * 70)
        print()
        
        sys.stdout.flush()
    else:
        # Non-root processes wait for parameters
        key = None
        num_rounds = None
        mode = None
    
    # Broadcast parameters to all processes
    key = comm.bcast(key, root=0)
    num_rounds = comm.bcast(num_rounds, root=0)
    mode = comm.bcast(mode, root=0)
    
    # Run encryption based on mode
    if rank == 0:
        print("⏳ Выполняется шифрование / Encrypting...")
        print()
    
    plaintext = DEMO_TEXT.encode('utf-8')
    
    if mode == "Parallel":
        # Use parallel cipher
        parallel_cipher = ParallelWBC1(key, block_size=16, num_rounds=num_rounds)
        
        if rank == 0:
            start_time = time.time()
        
        ciphertext = parallel_cipher.encrypt(plaintext if rank == 0 else None)
        
        comm.Barrier()
        
        if rank == 0:
            enc_time = time.time() - start_time
            
            start_time = time.time()
        
        decrypted = parallel_cipher.decrypt(ciphertext if rank == 0 else None)
        
        comm.Barrier()
        
        if rank == 0:
            dec_time = time.time() - start_time
    else:
        # Use sequential cipher (only rank 0)
        if rank == 0:
            cipher = WBC1Cipher(key, block_size=16, num_rounds=num_rounds)
            
            # Pad data
            block_size = 16
            padding_length = block_size - (len(plaintext) % block_size)
            if padding_length == 0:
                padding_length = block_size
            padded_data = plaintext + bytes([padding_length] * padding_length)
            
            # Encrypt
            start_time = time.time()
            encrypted_blocks = []
            for i in range(0, len(padded_data), block_size):
                block = padded_data[i:i + block_size]
                block_array = np.frombuffer(block, dtype=np.uint8).copy()
                encrypted_block = cipher.encrypt_block(block_array)
                encrypted_blocks.append(encrypted_block.tobytes())
            ciphertext = b''.join(encrypted_blocks)
            enc_time = time.time() - start_time
            
            # Decrypt
            start_time = time.time()
            decrypted_blocks = []
            for i in range(0, len(ciphertext), block_size):
                block = ciphertext[i:i + block_size]
                block_array = np.frombuffer(block, dtype=np.uint8).copy()
                decrypted_block = cipher.decrypt_block(block_array)
                decrypted_blocks.append(decrypted_block.tobytes())
            decrypted_padded = b''.join(decrypted_blocks)
            
            # Remove padding
            padding_length = decrypted_padded[-1]
            decrypted = decrypted_padded[:-padding_length]
            dec_time = time.time() - start_time
        
        comm.Barrier()
    
    # Display results
    if rank == 0:
        print("✅ РЕЗУЛЬТАТЫ / RESULTS")
        print("=" * 70)
        print()
        print(f"Исходный текст / Original text:")
        print(f"  {DEMO_TEXT}")
        print()
        print(f"Зашифрованный текст (hex) / Encrypted text (hex):")
        print(f"  {ciphertext.hex()[:80]}...")
        print()
        print(f"Расшифрованный текст / Decrypted text:")
        print(f"  {decrypted.decode('utf-8')}")
        print()
        print(f"Проверка / Verification:")
        if decrypted.decode('utf-8') == DEMO_TEXT:
            print(f"  ✅ Успешно! Расшифровка совпадает с оригиналом")
            print(f"  ✅ Success! Decryption matches original")
        else:
            print(f"  ❌ Ошибка! Расшифровка не совпадает")
            print(f"  ❌ Error! Decryption does not match")
        print()
        print(f"Время шифрования / Encryption time: {enc_time:.6f} сек / sec")
        print(f"Время расшифрования / Decryption time: {dec_time:.6f} сек / sec")
        print()
        print("=" * 70)


if __name__ == "__main__":
    # Check if running in interactive mode
    if len(sys.argv) > 1 and sys.argv[1] == "--interactive":
        interactive_demo()
    else:
        main()
