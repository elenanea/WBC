#!/usr/bin/env python3
"""
Benchmark script for WBC1 parallel cipher.
Run with: mpiexec -n <num_processes> python3 benchmark.py
"""

from mpi4py import MPI
from wbc1_parallel import ParallelWBC1
import numpy as np


def benchmark(num_processes, data_sizes_kb):
    """Run benchmarks with different data sizes."""
    comm = MPI.COMM_WORLD
    rank = comm.Get_rank()
    
    if rank == 0:
        print("=" * 70)
        print(f"WBC1 Parallel Cipher Benchmark")
        print(f"Number of MPI processes: {num_processes}")
        print("=" * 70)
        print()
    
    # Configuration
    key = b"BenchmarkKey1234"
    cipher = ParallelWBC1(key, block_size=16, num_rounds=16)
    
    for size_kb in data_sizes_kb:
        size_bytes = size_kb * 1024
        
        if rank == 0:
            # Generate test data
            data = bytes([i % 256 for i in range(size_bytes)])
            num_blocks = (len(data) + 15) // 16
            
            print(f"Data size: {size_kb} KB ({num_blocks} blocks)")
        else:
            data = None
        
        # Warm up
        if rank == 0:
            warmup_data = b"warmup" * 100
        else:
            warmup_data = None
        cipher.encrypt(warmup_data)
        
        # Benchmark encryption with MPI.Wtime()
        comm.Barrier()  # Synchronize all processes
        t0 = MPI.Wtime()
        ciphertext = cipher.encrypt(data)
        comm.Barrier()
        encryption_time = MPI.Wtime() - t0
        
        # Benchmark decryption with MPI.Wtime()
        comm.Barrier()
        t0 = MPI.Wtime()
        decrypted = cipher.decrypt(ciphertext)
        comm.Barrier()
        decryption_time = MPI.Wtime() - t0
        
        if rank == 0:
            # Calculate throughput
            enc_throughput = size_kb / encryption_time
            dec_throughput = size_kb / decryption_time
            
            print(f"  Encryption time:   {encryption_time:.6f} s")
            print(f"  Encryption speed:  {enc_throughput:.2f} KB/s")
            print(f"  Decryption time:   {decryption_time:.6f} s")
            print(f"  Decryption speed:  {dec_throughput:.2f} KB/s")
            print(f"  Total time:        {encryption_time + decryption_time:.6f} s")
            
            # Verify correctness
            if data == decrypted:
                print(f"  Verification:      ✓ PASSED")
            else:
                print(f"  Verification:      ✗ FAILED")
            print()


def main():
    """Main benchmark function."""
    comm = MPI.COMM_WORLD
    rank = comm.Get_rank()
    size = comm.Get_size()
    
    # Test with different data sizes
    data_sizes_kb = [1, 10, 50, 100, 500]  # KB
    
    benchmark(size, data_sizes_kb)
    
    if rank == 0:
        print("=" * 70)
        print("Benchmark completed successfully!")
        print("=" * 70)


if __name__ == "__main__":
    main()
