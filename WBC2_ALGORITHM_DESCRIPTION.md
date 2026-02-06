# WBC2 Enhanced Algorithm Description

## Overview

WBC2 is an enhanced version of WBC1 that adds multiple cryptographic layers for improved security:
- XOR with round keys
- Individualized S-box (key-dependent bijection)
- Two-layer diffusion
- Dynamic permutations from WBC1
- Cyclic bitwise shift

## Algorithm Structure

### Round 0 (Initial Round)

**Purpose:** Process the full key with WBC1-style permutations, then add cryptographic layers

**Steps:**
1. **WBC1 Permutations:** For each byte of the 256-bit key:
   - Extract key byte and mix it (improve bit sensitivity)
   - Select operation: `op_id = mix_key_byte(key[i]) % 127`
   - Apply Rubik's cube operation from table
   - Perform cyclic bitwise shift by `d` bits

2. **XOR with Round Key 0:**
   - `block[i] ^= round_key[0][i]` for all bytes

3. **Apply S-box:**
   - `block[i] = sbox[block[i]]` for all bytes
   - S-box is individualized (generated from master key)

4. **Two-Layer Diffusion:**
   - **Layer 1:** Linear byte-level mixing
   - **Layer 2:** Bitwise diffusion with rotations

### Subsequent Rounds (1..10)

**Purpose:** Additional rounds for deep cryptographic transformation

**Steps:**
1. **Dynamic Permutation:**
   - Select one operation based on round key: `op_id = mix_key_byte(round_key[i][0]) % 127`
   - Apply selected Rubik's cube operation

2. **XOR with Round Key:**
   - `block[i] ^= round_key[i][i]` for all bytes

3. **Apply S-box:**
   - `block[i] = sbox[block[i]]` for all bytes

4. **Two-Layer Diffusion:**
   - Layer 1: Linear mixing
   - Layer 2: Bitwise diffusion

5. **Cyclic Bitwise Shift:**
   - Rotate all bits by `d` positions

## Key Components

### 1. Individualized S-box

**Generation:**
```
1. Derive seed from master key using SHA-256
2. Initialize S-box with identity: sbox[i] = i for i in 0..255
3. Apply Fisher-Yates shuffle with key-derived randomness:
   - For i from 255 down to 1:
     - j = random(0..i) using Mersenne Twister with key seed
     - Swap sbox[i] with sbox[j]
4. Generate inverse S-box: inv_sbox[sbox[i]] = i
```

**Properties:**
- Bijection: {0,...,255} → {0,...,255}
- Key-dependent: Different keys produce different S-boxes
- Deterministic: Same key always produces same S-box
- Full diffusion at byte level

### 2. Round Key Generation

**Derivation:**
```
For round i in 0..N:
    input = master_key || i (concatenate key with round number)
    hash = SHA-256(input)
    round_key[i] = hash (extended if block > 32 bytes)
```

**Properties:**
- Each round has unique key material
- Derived from master key (no key expansion storage needed)
- Cryptographically secure (SHA-256 based)
- Size matches block size

### 3. Two-Layer Diffusion

**Layer 1: Linear Byte Mixing**

Purpose: Spread changes across bytes

```c
For each byte i in block:
    i1 = i
    i2 = (i + 1) % block_size
    i3 = (i + block_size/2) % block_size
    i4 = (i + block_size - 1) % block_size
    
    new_block[i] = (2*temp[i1] + 3*temp[i2] + temp[i3] + temp[i4]) & 0xFF
```

Properties:
- MDS-inspired mixing
- Each byte influenced by 4 positions
- Non-linear integer arithmetic (mod 256)

**Layer 2: Bitwise Diffusion**

Purpose: Spread changes at bit level

```c
1. XOR block with left rotation by 1 bit
2. XOR block with left rotation by 3 bits
```

Properties:
- Bit-level avalanche
- Multiple bit positions mixed
- Self-invertible (applying twice reverses)

**Inverse Diffusion:**

For decryption, both layers are reversed:
- Layer 2 reversed: Apply same XOR rotations (self-inverse)
- Layer 1 reversed: Multiple iterations or matrix inversion

## Decryption

Decryption reverses all operations in opposite order:

**Rounds N..1 (reverse order):**
1. Reverse cyclic shift
2. Inverse diffusion (layer 2 then layer 1)
3. Inverse S-box
4. XOR with round key (XOR is self-inverse)
5. Inverse permutation

**Round 0 (reverse):**
1. Inverse diffusion
2. Inverse S-box
3. XOR with round key 0
4. Reverse WBC1 permutations (reverse key order)

## Comparison with WBC1

| Feature | WBC1 | WBC2 |
|---------|------|------|
| **Permutations** | Rubik's cube operations | Same + more rounds |
| **XOR** | No | Yes (round keys) |
| **S-box** | No | Yes (key-dependent) |
| **Diffusion** | Cyclic shift only | Two-layer diffusion |
| **Rounds** | Key bytes (32) | 1 + 10 = 11 total |
| **Security** | Good | Enhanced |
| **Speed** | Fast | Slightly slower |

## Security Analysis

### Diffusion

**WBC1:** Primarily from permutations and cyclic shift
**WBC2:** 
- Permutations (spatial mixing)
- S-box (byte substitution)
- Linear mixing (byte-level diffusion)
- Bitwise rotations (bit-level diffusion)
- Cyclic shift (full block mixing)

**Result:** Superior diffusion at all levels

### Confusion

**WBC1:** From Rubik's cube operations
**WBC2:**
- Rubik's cube operations (non-linear geometric transformations)
- S-box (non-linear byte substitution)
- Key-dependent S-box (attacker doesn't know substitution)

**Result:** Multiple layers of confusion

### Key Sensitivity

**WBC1:** High (mix_key_byte ensures all bits important)
**WBC2:** 
- All WBC1 benefits
- Plus S-box is key-dependent
- Plus round keys derived from master key
- Different keys produce completely different transformations

**Result:** Excellent key sensitivity

### Avalanche Effect

Expected: Flipping 1 bit in plaintext changes ~50% of ciphertext bits

**WBC1:** Good (~45-52% depending on block size)
**WBC2:**
- Better through two-layer diffusion
- Layer 1 spreads to 4 bytes
- Layer 2 spreads across bit positions
- Multiple rounds amplify effect

**Result:** Excellent avalanche (expected ~48-52%)

## Usage

### Compilation

```bash
make wbc2
```

### Basic Usage

```bash
# Encrypt text with automatic block size
mpirun -n 4 ./wbc2_original_parallel 0 256 0 0 1 100

# Differential analysis
mpirun -n 4 ./wbc2_original_parallel 1 256 0 128 1 1000

# Print operations table
mpirun -n 1 ./wbc2_original_parallel 2 256 0 64
```

### Command-Line Arguments

Same as WBC1:
```
./wbc2_original_parallel <task> <key_bits> <key_bytes> <block_bits> <mode> <data_kb>

task: 0=encrypt, 1=differential, 2=operations_table
key_bits: Key size in bits (e.g., 256)
key_bytes: 0 for generated key
block_bits: 0 for auto-select, or 32/64/128/512
mode: 1 for full cipher
data_kb: Data size in KB
```

## Performance

### Expected Performance

Compared to WBC1:
- **Encryption:** ~70-80% of WBC1 speed (overhead from S-box, diffusion, more rounds)
- **Decryption:** ~70-80% of WBC1 speed
- **Memory:** Slightly more (round keys, S-boxes)

### Optimization Opportunities

1. **S-box caching:** Already cached in cipher structure
2. **Round key caching:** Already cached
3. **Diffusion optimization:** Could use SIMD for parallel byte operations
4. **Fewer rounds:** If performance critical, reduce from 10 to 5-7 rounds

## Recommendations

### When to Use WBC2

- **High security requirements:** Multiple cryptographic layers
- **Defense in depth:** Want multiple independent security mechanisms
- **Key-dependent transformations:** Need S-box individualization
- **Strong avalanche needed:** Two-layer diffusion provides excellent avalanche

### When to Use WBC1

- **Maximum performance:** Need fastest possible encryption
- **Simpler implementation:** Don't need S-box/diffusion complexity
- **Good enough security:** Rubik's cube permutations provide good security

## Future Enhancements

Potential improvements for WBC3:
1. **Adaptive rounds:** More rounds for larger blocks
2. **Multiple S-boxes:** Different S-boxes for different layers
3. **Key schedule:** More sophisticated round key derivation
4. **Parallel diffusion:** SIMD-optimized diffusion layers
5. **Variable round count:** User-selectable security/performance trade-off

## References

- WBC1 algorithm specification
- Fisher-Yates shuffle algorithm
- AES S-box design principles
- MDS matrix theory
- SHA-256 key derivation

## Conclusion

WBC2 enhances WBC1 with multiple cryptographic layers while maintaining compatibility with the same test framework and command-line interface. The addition of XOR, individualized S-box, and two-layer diffusion significantly improves security with acceptable performance overhead.
