# WBC2 Quick Start Guide

## What is WBC2?

WBC2 is an enhanced version of WBC1 with additional cryptographic layers:
- **XOR** with round keys
- **Individualized S-box** (key-dependent bijection)
- **Two-layer diffusion** (byte-level + bit-level)
- **Multiple rounds** (11 total: 1 initial + 10 enhanced)

## Quick Compilation

```bash
cd /path/to/WBC
make wbc2
```

## Quick Usage

### Basic Encryption
```bash
# Encrypt 100 KB of data with 256-bit key and auto block size
mpirun -n 4 ./wbc2_original_parallel 0 256 0 0 1 100
```

### Differential Analysis
```bash
# Test key sensitivity with 128-bit blocks and 1 MB data
mpirun -n 4 ./wbc2_original_parallel 1 256 0 128 1 1000
```

### Operations Table
```bash
# Display the 127 Rubik's cube operations
mpirun -n 1 ./wbc2_original_parallel 2 256 0 64
```

## Command-Line Format

```
./wbc2_original_parallel <task> <key_bits> <key_bytes> <block_bits> <mode> <data_kb>
```

**Parameters:**
- `task`: 0 = encrypt/decrypt, 1 = differential test, 2 = show operations
- `key_bits`: Key size (always 256)
- `key_bytes`: 0 for auto-generated key
- `block_bits`: 0 for auto-select, or 32/64/128/512
- `mode`: 1 for full cipher
- `data_kb`: Data size in kilobytes

## Algorithm Overview

### Round 0 (Initial)
1. WBC1 permutations (32 operations from key bytes)
2. XOR with round_key[0]
3. S-box substitution
4. Two-layer diffusion

### Rounds 1-10
1. One dynamic permutation
2. XOR with round_key[i]
3. S-box substitution  
4. Two-layer diffusion
5. Cyclic bitwise shift

### Decryption
- Reverse all operations in opposite order
- Uses inverse S-box and inverse diffusion

## Key Features

### 1. Individualized S-box
- Generated from master key using Fisher-Yates shuffle
- Different keys → different S-boxes
- Full bijection {0,...,255} → {0,...,255}

### 2. Round Keys
- Derived using SHA-256
- Unique key for each round
- Cryptographically secure

### 3. Two-Layer Diffusion

**Layer 1 (Byte-level):**
- Linear mixing of neighboring bytes
- MDS-inspired transformation

**Layer 2 (Bit-level):**
- XOR with 1-bit rotation
- XOR with 3-bit rotation
- Ensures bit-level avalanche

## WBC1 vs WBC2

| Feature | WBC1 | WBC2 |
|---------|------|------|
| Speed | Faster | ~70-80% of WBC1 |
| Security | Good | Enhanced |
| XOR | No | Yes |
| S-box | No | Yes (key-dependent) |
| Diffusion | Basic | Two-layer |
| Rounds | 32 | 11 |

## When to Use WBC2

**Use WBC2 when:**
- Maximum security is priority
- Need defense in depth
- Want key-dependent transformations
- Require strong avalanche effect

**Use WBC1 when:**
- Maximum performance is priority
- Good security is sufficient
- Simpler implementation preferred

## Expected Test Results

### Differential Analysis
- **Key sensitivity:** ~45-50% (good)
- **Min:** ~25%
- **Max:** ~60%
- **Status:** Good key sensitivity

### Avalanche Effect
- **Bit changes:** ~48-52% (excellent)
- **Expected:** Flipping 1 input bit changes ~50% of output bits

## Troubleshooting

### Compilation Errors

**MPI not found:**
```bash
# Install MPI
sudo apt-get install mpich libmpich-dev
# or
sudo apt-get install openmpi-bin libopenmpi-dev
```

**OpenSSL not found:**
```bash
# Install OpenSSL
sudo apt-get install libssl-dev
```

### Runtime Errors

**"Not enough processes":**
```bash
# Use --oversubscribe flag
mpirun --oversubscribe -n 4 ./wbc2_original_parallel ...
```

**Slow performance:**
- Reduce data size (data_kb parameter)
- Use fewer MPI processes
- Use smaller block size

## Files

- **Source:** `wbc2_original_parallel.c` (1,668 lines)
- **Documentation:** `WBC2_ALGORITHM_DESCRIPTION.md` (full spec)
- **This guide:** `WBC2_QUICKSTART.md`
- **Makefile:** Updated with wbc2 target

## Next Steps

1. **Compile:** `make wbc2`
2. **Test basic:** `make test-wbc2`
3. **Run differential:** Test key sensitivity
4. **Compare with WBC1:** Check speed vs security trade-off
5. **Read full spec:** See `WBC2_ALGORITHM_DESCRIPTION.md`

## Contact

For questions or issues:
- Check `WBC2_ALGORITHM_DESCRIPTION.md` for detailed information
- Review `wbc2_original_parallel.c` comments
- Compare with `wbc1_original_parallel.c` for differences

---

**WBC2: Enhanced Security Through Multiple Cryptographic Layers**
