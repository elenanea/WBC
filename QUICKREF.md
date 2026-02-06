# WBC1 Parallel Cipher - Quick Reference

## Installation
```bash
sudo apt-get install openmpi-bin libopenmpi-dev
pip install -r requirements.txt
```

## Quick Start

### Single Process
```bash
python3 wbc1_parallel.py
```

### Multiple Processes
```bash
mpiexec -n 4 python3 wbc1_parallel.py
mpiexec --oversubscribe -n 8 python3 wbc1_parallel.py
```

## Basic Usage

```python
from wbc1_parallel import ParallelWBC1
from mpi4py import MPI

comm = MPI.COMM_WORLD
rank = comm.Get_rank()

# Create cipher
cipher = ParallelWBC1(b"SecretKey1234567", block_size=16, num_rounds=16)

# Encrypt
if rank == 0:
    plaintext = b"Your message here"
else:
    plaintext = None

ciphertext = cipher.encrypt(plaintext)
decrypted = cipher.decrypt(ciphertext)

if rank == 0:
    print(f"Match: {plaintext == decrypted}")
```

## Testing & Examples

```bash
# Run tests
python3 test_wbc1.py

# Run examples
mpiexec -n 2 python3 example_parallel.py

# Run benchmarks
mpiexec -n 2 python3 benchmark.py
```

## Key Functions

### WBC1Cipher (Sequential)
```python
from wbc1_parallel import WBC1Cipher
import numpy as np

cipher = WBC1Cipher(key, block_size=16, num_rounds=16)
block = np.random.randint(0, 256, 16, dtype=np.uint8)
encrypted = cipher.encrypt_block(block)
decrypted = cipher.decrypt_block(encrypted)
```

### ParallelWBC1 (MPI)
```python
from wbc1_parallel import ParallelWBC1

cipher = ParallelWBC1(key, block_size=16, num_rounds=16)
ciphertext = cipher.encrypt(plaintext)  # Only rank 0 needs plaintext
decrypted = cipher.decrypt(ciphertext)  # Only rank 0 gets result
```

### Statistical Tests
```python
from wbc1_parallel import (
    shannon_entropy, avalanche_test, frequency_test
)

entropy = shannon_entropy(data)                  # Randomness
avalanche = avalanche_test(cipher, num_tests=100)  # Diffusion
freq = frequency_test(data)                      # Distribution
```

## Parameters

- **key**: bytes - Encryption key (any length)
- **block_size**: int - Block size in bytes (default: 16)
- **num_rounds**: int - Number of rounds (default: 16)

## Common Options

```bash
# Specify number of processes
mpiexec -n <N> python3 script.py

# Allow oversubscription (more processes than cores)
mpiexec --oversubscribe -n <N> python3 script.py

# Specify hosts
mpiexec -host host1,host2 python3 script.py
```

## Expected Results

- **Entropy**: 7-8 bits/byte (higher is better)
- **Avalanche**: ~50% (ideal diffusion)
- **Correlation**: ~0.0 (low is better)
- **Throughput**: 200-400 KB/s (depends on processes)

## File Reference

| File | Purpose |
|------|---------|
| wbc1_parallel.py | Main implementation |
| test_wbc1.py | Test suite |
| example_parallel.py | Usage examples |
| benchmark.py | Performance tests |
| README.md | Full documentation |
| USAGE.md | Detailed guide |

## Troubleshooting

**Error: "cannot load MPI library"**
```bash
sudo apt-get install openmpi-bin libopenmpi-dev
pip uninstall mpi4py
pip install --no-cache-dir mpi4py
```

**Error: "not enough slots"**
```bash
mpiexec --oversubscribe -n <N> python3 script.py
```

## More Information

- Full documentation: README.md
- Usage guide: USAGE.md
- Implementation details: IMPLEMENTATION_SUMMARY.txt
