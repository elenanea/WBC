# WBC1 Parallel Cipher

Parallel implementation of the WBC1 (White-Box Cipher 1) block cipher algorithm using MPI (Message Passing Interface) for distributed computing.

**NEW: C implementation with MPI support now available!** See [WBC1_C_README.md](WBC1_C_README.md) for the high-performance C version.

## Features

- **WBC1 Block Cipher**: Complete implementation with:
  - Key-dependent S-box generation using SHA-256
  - 127 dynamic Rubik's cube permutation operations
  - Bit-level permutation
  - Cumulative XOR diffusion
  - Cyclic bitwise rotation
  - Multiple encryption rounds with round keys
  - XOR operations for key mixing

- **Multiple Implementations**:
  - **Python** (wbc1_parallel.py, wbc1_parallel_cached.py): Reference implementation with statistical tests
  - **C** (wbc1_parallel.c, wbc1_parallel_cached.c): High-performance implementation (10-50x faster)

- **Parallel Processing**: Utilizes MPI (mpi4py for Python, native MPI for C) to distribute block encryption/decryption across multiple processes

- **Statistical Tests** (Python):
  - Shannon entropy calculation
  - Avalanche effect testing
  - Frequency analysis
  - Correlation testing

## Repository Structure

```
.
├── README.md                    # Main documentation
├── USAGE.md                     # Detailed usage guide (Python)
├── WBC1_C_README.md            # C implementation documentation
├── Makefile                     # Build system for C implementations
│
├── wbc1_parallel.py            # Python: Basic parallel implementation
├── wbc1_parallel_cached.py     # Python: Optimized with operation cache
├── example_parallel.py         # Python: Example demonstrations
├── test_wbc1.py                # Python: Test suite
├── benchmark.py                # Python: Performance benchmarks
├── requirements.txt            # Python dependencies
│
├── wbc1_parallel.c             # C: Basic parallel implementation
├── wbc1_parallel_cached.c      # C: Optimized with pre-computed cache
└── check_requirements.sh       # C: Dependency verification script
```

## Quick Start

### Python Implementation

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run with MPI:**
   ```bash
   mpirun -n 4 python3 wbc1_parallel_cached.py
   ```

### C Implementation

1. **Install MPI and OpenSSL:**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install libopenmpi-dev libssl-dev
   
   # macOS
   brew install open-mpi openssl
   ```

2. **Build:**
   ```bash
   make all
   ```

3. **Run:**
   ```bash
   mpirun -n 4 ./wbc1_parallel_cached 1 16
   ```

## Algorithm Modes

Both Python and C implementations support two algorithm modes:

- **Mode 0 (Simplified)**: 2 operations per round
  - Dynamic Rubik's cube permutation
  - Cyclic bitwise rotation
  - Faster, requires more rounds for security

- **Mode 1 (Full)**: 5 operations per round (default, recommended)
  - Dynamic Rubik's cube permutation
  - XOR with round key
  - S-box substitution
  - Cumulative XOR diffusion
  - Cyclic bitwise rotation

## Requirements

- Python 3.6+
- numpy
- mpi4py
- MPI implementation (OpenMPI, MPICH, etc.)

## Installation

1. Install MPI on your system:

   **Ubuntu/Debian:**
   ```bash
   sudo apt-get install openmpi-bin openmpi-common libopenmpi-dev
   ```

   **macOS (with Homebrew):**
   ```bash
   brew install open-mpi
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage

Run the cipher with default settings using a single process:
```bash
python wbc1_parallel.py
```

### Parallel Execution

Run with multiple MPI processes (e.g., 4 processes):
```bash
mpiexec -n 4 python wbc1_parallel.py
```

Or:
```bash
mpirun -n 4 python wbc1_parallel.py
```

### Programmatic Usage

```python
from wbc1_parallel import ParallelWBC1, WBC1Cipher
from mpi4py import MPI

# Initialize MPI
comm = MPI.COMM_WORLD
rank = comm.Get_rank()

# Create cipher with master key
master_key = b"MySecretKey12345"
parallel_cipher = ParallelWBC1(master_key, block_size=16, num_rounds=16)

# Encrypt data (only rank 0 needs the plaintext)
if rank == 0:
    plaintext = b"Secret message to encrypt"
else:
    plaintext = None

ciphertext = parallel_cipher.encrypt(plaintext)

# Decrypt data
decrypted = parallel_cipher.decrypt(ciphertext)

if rank == 0:
    print(f"Original: {plaintext}")
    print(f"Decrypted: {decrypted}")
    assert plaintext == decrypted
```

### Statistical Testing

```python
from wbc1_parallel import (
    WBC1Cipher, shannon_entropy, avalanche_test, 
    frequency_test, run_statistical_tests
)

# Create cipher
cipher = WBC1Cipher(b"TestKey123456789", block_size=16, num_rounds=16)

# Test data
plaintext = b"Test message for statistical analysis"
ciphertext = cipher.encrypt_block(plaintext)

# Calculate entropy
print(f"Plaintext entropy: {shannon_entropy(plaintext)}")
print(f"Ciphertext entropy: {shannon_entropy(ciphertext)}")

# Test avalanche effect
avalanche_results = avalanche_test(cipher, num_tests=1000)
print(f"Mean bit flip: {avalanche_results['mean_flip_percentage']:.2f}%")

# Comprehensive tests
all_results = run_statistical_tests(plaintext, ciphertext, cipher)
```

## Algorithm Description

The WBC1 cipher is a block cipher that processes data in fixed-size blocks (default 16 bytes) through multiple rounds of transformations:

1. **Initialization**: Generate key-dependent S-box, permutation table, and round keys from master key

2. **Encryption Round** (repeated for each round):
   - **Substitution Layer**: Apply S-box transformation to each byte
   - **Permutation Layer**: Perform bit-level permutation
   - **Cyclic Shift**: Rotate bytes within the block
   - **Key Mixing**: XOR with round key

3. **Parallel Processing**:
   - Master process divides input into blocks
   - Blocks are distributed across MPI processes
   - Each process encrypts its assigned blocks independently
   - Results are gathered back to master process

## Performance Considerations

### Python Implementation
- Benefits from parallel processing for large data
- Cached version (wbc1_parallel_cached.py) is 10-50x faster than basic version
- Optional Numba JIT compilation for additional speedup

### C Implementation
- **10-50x faster** than Python for encryption/decryption
- Cached version pre-computes all 127 permutations during initialization
- Near-linear MPI scaling for large datasets
- Minimal memory overhead

Example speedup (C cached version, Mode 1, 16 rounds):
- 1 process: baseline
- 2 processes: ~1.95x faster
- 4 processes: ~3.85x faster  
- 8 processes: ~7.6x faster

## Security Notes

⚠️ **Educational Purpose**: This implementation is for educational and research purposes. It has not undergone formal security analysis and should not be used in production systems without thorough cryptographic review.

Key security features:
- Key-dependent S-box generation using SHA-256
- 127 unique key-dependent permutation operations
- Multiple rounds of diffusion and confusion
- Bit-level permutation for enhanced security
- Avalanche effect ensures small input changes propagate throughout output
- Round keys independently derived from master key

### Recommended Parameters
- **Key size**: 256 bits (32 bytes) minimum
- **Mode 1**: 16+ rounds (32 for high security)
- **Mode 0**: 32+ rounds (64 for high security)

## Documentation

- **[README.md](README.md)**: Main documentation (this file)
- **[USAGE.md](USAGE.md)**: Detailed Python usage guide
- **[WBC1_C_README.md](WBC1_C_README.md)**: C implementation guide
- **[IMPLEMENTATION_SUMMARY.txt](IMPLEMENTATION_SUMMARY.txt)**: Algorithm details
- **[QUICKREF.md](QUICKREF.md)**: Quick reference guide

## Testing

The implementation includes several statistical tests to evaluate cipher quality:

- **Shannon Entropy**: Measures randomness of output (ideal: 8.0 bits for bytes)
- **Avalanche Effect**: Verifies that flipping one input bit changes ~50% of output bits
- **Frequency Test**: Checks uniform distribution of byte values
- **Correlation Test**: Ensures low correlation between plaintext and ciphertext

### Running Tests

**Python:**
```bash
# Run test suite
python3 test_wbc1.py

# Run examples with MPI
mpiexec -n 4 python3 example_parallel.py

# Run benchmarks
mpiexec -n 2 python3 benchmark.py
```

**C:**
```bash
# Build and test
make test

# Benchmark
make benchmark

# Check requirements
./check_requirements.sh
```

## License

This project is provided as-is for educational purposes.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.
