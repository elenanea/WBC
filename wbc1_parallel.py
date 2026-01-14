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
from typing import List, Tuple, Optional
import hashlib


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
        
        # Main rounds
        for round_num in range(1, self.num_rounds):
            # Substitution layer
            state = self._substitute_bytes(state)
            
            # Permutation layer
            state = self._permute_bits(state)
            
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
        
        # Inverse main rounds
        for round_num in range(self.num_rounds - 1, 0, -1):
            # Inverse key mixing
            state = self._xor_with_key(state, self.round_keys[round_num])
            
            # Inverse cyclic shift
            state = self._rotate_right(state, round_num % self.block_size)
            
            # Inverse permutation
            state = self._inverse_permute_bits(state)
            
            # Inverse substitution
            state = self._inverse_substitute_bytes(state)
        
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


if __name__ == "__main__":
    main()
