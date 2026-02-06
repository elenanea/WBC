# WBC1 Parallel Cipher - Usage Guide

## Quick Start

### Installation

1. **Install MPI** (if not already installed):

   **Ubuntu/Debian:**
   ```bash
   sudo apt-get install openmpi-bin openmpi-common libopenmpi-dev
   ```

   **Fedora/RHEL:**
   ```bash
   sudo dnf install openmpi openmpi-devel
   ```

   **macOS:**
   ```bash
   brew install open-mpi
   ```

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation:**
   ```bash
   python3 test_wbc1.py
   ```

## Basic Usage

### Running with Single Process

```bash
# Standard execution
python3 wbc1_parallel.py

# Or with MPI (single process)
mpiexec -n 1 python3 wbc1_parallel.py
```

### Running with Multiple Processes

```bash
# Run with 2 processes
mpiexec -n 2 python3 wbc1_parallel.py

# Run with 4 processes
mpiexec -n 4 python3 wbc1_parallel.py

# If you have fewer CPU cores than requested processes
mpiexec --oversubscribe -n 8 python3 wbc1_parallel.py
```

## Programming Examples

### Example 1: Basic Encryption/Decryption

```python
from wbc1_parallel import ParallelWBC1
from mpi4py import MPI

# Initialize MPI
comm = MPI.COMM_WORLD
rank = comm.Get_rank()

# Create cipher
key = b"MySecretKey12345"
cipher = ParallelWBC1(key, block_size=16, num_rounds=16)

# Encrypt (only master process needs the data)
if rank == 0:
    plaintext = b"Hello, World!"
else:
    plaintext = None

ciphertext = cipher.encrypt(plaintext)

# Decrypt
decrypted = cipher.decrypt(ciphertext)

if rank == 0:
    print(f"Original:  {plaintext}")
    print(f"Decrypted: {decrypted}")
    assert plaintext == decrypted
```

### Example 2: Using WBC1Cipher Directly (Non-Parallel)

```python
from wbc1_parallel import WBC1Cipher
import numpy as np

# Create cipher
key = b"MySecretKey12345"
cipher = WBC1Cipher(key, block_size=16, num_rounds=16)

# Encrypt a single block (must be exactly block_size bytes)
plaintext = np.random.randint(0, 256, 16, dtype=np.uint8)
ciphertext = cipher.encrypt_block(plaintext)

# Decrypt
decrypted = cipher.decrypt_block(ciphertext)

print(f"Match: {np.array_equal(plaintext, decrypted)}")
```

### Example 3: Statistical Analysis

```python
from wbc1_parallel import (
    WBC1Cipher, shannon_entropy, avalanche_test, 
    frequency_test, run_statistical_tests
)

# Create cipher
cipher = WBC1Cipher(b"TestKey123456789", block_size=16, num_rounds=16)

# Test data
plaintext = b"This is a test message for analysis" * 10
# You would need to implement full data encryption for this

# Calculate entropy
entropy = shannon_entropy(plaintext)
print(f"Entropy: {entropy:.4f} bits/byte")

# Test avalanche effect
avalanche_results = avalanche_test(cipher, num_tests=1000)
print(f"Avalanche effect: {avalanche_results['mean_flip_percentage']:.2f}%")
print(f"Expected: ~50% (good diffusion)")

# Frequency test
freq_stats = frequency_test(plaintext)
print(f"Chi-square statistic: {freq_stats['chi_square']:.2f}")
```

### Example 4: Custom Parameters

```python
from wbc1_parallel import ParallelWBC1
from mpi4py import MPI

comm = MPI.COMM_WORLD
rank = comm.Get_rank()

# Create cipher with custom parameters
key = b"A" * 32  # 32-byte key
cipher = ParallelWBC1(
    key=key,
    block_size=32,     # 32-byte blocks
    num_rounds=20      # 20 encryption rounds
)

if rank == 0:
    plaintext = b"Custom configuration test"
else:
    plaintext = None

ciphertext = cipher.encrypt(plaintext)
decrypted = cipher.decrypt(ciphertext)

if rank == 0:
    print(f"Success: {plaintext == decrypted}")
```

## Running the Examples

### Test Suite

```bash
# Run all tests
python3 test_wbc1.py
```

Expected output:
```
============================================================
WBC1 Cipher Test Suite
============================================================
Testing WBC1Cipher (non-parallel)...
✓ Single block encryption/decryption: PASSED
...
============================================================
Test Results: 5/5 passed
============================================================
✓ All tests passed!
```

### Example Script

```bash
# Run with 2 processes
mpiexec --oversubscribe -n 2 python3 example_parallel.py

# Run with 4 processes
mpiexec --oversubscribe -n 4 python3 example_parallel.py
```

## Performance Tips

1. **Optimal Number of Processes:**
   - Use `nproc` command to find number of CPU cores
   - Generally best to use 1 process per core
   - For large datasets, more processes = better performance

2. **Block Size:**
   - Larger blocks = more security but slower
   - Default 16 bytes is a good balance
   - Common sizes: 16, 32, 64 bytes

3. **Number of Rounds:**
   - More rounds = more security but slower
   - Default 16 rounds provides good security
   - Minimum recommended: 10 rounds
   - Common values: 10, 16, 20, 32

4. **Data Size:**
   - Parallel processing benefits increase with data size
   - For small data (<1KB), single process may be faster
   - For large data (>10KB), parallel processing shines

## Common Issues

### Issue: "cannot load MPI library"

**Solution:** Install OpenMPI:
```bash
sudo apt-get install openmpi-bin libopenmpi-dev
pip uninstall mpi4py
pip install --no-cache-dir mpi4py
```

### Issue: "not enough slots available"

**Solution:** Use `--oversubscribe` flag:
```bash
mpiexec --oversubscribe -n 4 python3 wbc1_parallel.py
```

### Issue: Different output from different runs

**Cause:** Encryption is deterministic, but if you're using random data for testing, results will vary.

**Solution:** Use fixed test data or set random seed:
```python
import numpy as np
np.random.seed(42)
```

## Algorithm Details

### Encryption Process

1. **Key Setup:**
   - Generate key-dependent S-box
   - Create bit permutation table
   - Derive round keys from master key

2. **Block Processing:**
   - Pad input to block size (PKCS7)
   - Split into blocks
   - Distribute blocks to MPI processes

3. **Each Round:**
   - S-box substitution (confusion)
   - Bit permutation (diffusion)
   - Cyclic rotation
   - XOR with round key

4. **Finalization:**
   - Gather encrypted blocks
   - Combine into final ciphertext

### Security Features

- **Key-Dependent S-box:** Different keys produce different S-boxes
- **Bit-Level Permutation:** Enhanced diffusion
- **Multiple Rounds:** Increases security margin
- **Round Keys:** Derived securely from master key

## Performance Benchmarks

Approximate throughput on modern hardware:

| Processes | Block Size | Data Size | Throughput |
|-----------|-----------|-----------|------------|
| 1         | 16 bytes  | 10 KB     | ~200 KB/s  |
| 2         | 16 bytes  | 10 KB     | ~350 KB/s  |
| 4         | 16 bytes  | 10 KB     | ~600 KB/s  |
| 1         | 16 bytes  | 1 MB      | ~250 KB/s  |
| 4         | 16 bytes  | 1 MB      | ~900 KB/s  |

*Note: Actual performance depends on CPU, memory, and system configuration.*

## Further Reading

- MPI Tutorial: https://mpitutorial.com/
- mpi4py Documentation: https://mpi4py.readthedocs.io/
- Block Cipher Design: https://en.wikipedia.org/wiki/Block_cipher
- Avalanche Effect: https://en.wikipedia.org/wiki/Avalanche_effect
