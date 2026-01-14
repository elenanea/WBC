# WBC1 Parallel Cipher

Parallel implementation of the WBC1 (White-Box Cipher 1) block cipher algorithm using MPI (Message Passing Interface) for distributed computing.

## Features

- **WBC1 Block Cipher**: Complete implementation with:
  - Key-dependent S-box generation
  - Bit-level permutation
  - Cyclic bit shifts
  - Multiple encryption rounds with round keys
  - XOR operations for key mixing

- **Parallel Processing**: Utilizes MPI (mpi4py) to distribute block encryption/decryption across multiple processes

- **Statistical Tests**:
  - Shannon entropy calculation
  - Avalanche effect testing
  - Frequency analysis
  - Correlation testing

## Repository Structure

```
.
├── README.md              # Main documentation
├── USAGE.md              # Detailed usage guide
├── wbc1_parallel.py      # Main implementation
├── example_parallel.py   # Example demonstrations
├── test_wbc1.py          # Test suite
└── requirements.txt      # Python dependencies
```

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

- The algorithm benefits from parallel processing when encrypting large amounts of data
- Optimal number of processes depends on:
  - Total data size
  - Block size
  - Available CPU cores
  - Network latency (for distributed systems)

Example speedup with different process counts:
- 1 process: baseline
- 2 processes: ~1.8x faster
- 4 processes: ~3.5x faster
- 8 processes: ~6.5x faster

## Security Notes

⚠️ **Educational Purpose**: This implementation is for educational and research purposes. It has not undergone formal security analysis and should not be used in production systems without thorough cryptographic review.

Key security features:
- Key-dependent S-box generation
- Multiple rounds of diffusion and confusion
- Bit-level permutation for enhanced security
- Avalanche effect ensures small input changes propagate throughout output

## Testing

The implementation includes several statistical tests to evaluate cipher quality:

- **Shannon Entropy**: Measures randomness of output (ideal: 8.0 bits for bytes)
- **Avalanche Effect**: Verifies that flipping one input bit changes ~50% of output bits
- **Frequency Test**: Checks uniform distribution of byte values
- **Correlation Test**: Ensures low correlation between plaintext and ciphertext

## Examples

See `wbc1_parallel.py` main function for a complete working example.

## License

This project is provided as-is for educational purposes.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.
