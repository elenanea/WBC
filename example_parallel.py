#!/usr/bin/env python3
"""
Example script demonstrating parallel WBC1 encryption with different configurations.
Run with: mpiexec -n <num_processes> python example_parallel.py
"""

from mpi4py import MPI
from wbc1_parallel import ParallelWBC1, run_statistical_tests, WBC1Cipher
import time


def example_basic():
    """Basic encryption/decryption example."""
    comm = MPI.COMM_WORLD
    rank = comm.Get_rank()
    size = comm.Get_size()
    
    if rank == 0:
        print("=" * 70)
        print("Example 1: Basic Parallel Encryption/Decryption")
        print("=" * 70)
        print(f"Running with {size} MPI process(es)")
        print()
    
    # Configuration
    master_key = b"ExampleKey123456"
    
    # Create parallel cipher
    cipher = ParallelWBC1(master_key, block_size=16, num_rounds=16)
    
    # Test data
    if rank == 0:
        plaintext = b"This is a test message for parallel WBC1 encryption!"
        print(f"Plaintext: {plaintext}")
        print(f"Length: {len(plaintext)} bytes")
        print()
    else:
        plaintext = None
    
    # Measure encryption time
    start_time = time.time()
    ciphertext = cipher.encrypt(plaintext)
    encryption_time = time.time() - start_time
    
    if rank == 0:
        print(f"Encryption time: {encryption_time:.6f} seconds")
        print(f"Ciphertext (hex): {ciphertext[:32].hex()}...")
        print()
    
    # Measure decryption time
    start_time = time.time()
    decrypted = cipher.decrypt(ciphertext)
    decryption_time = time.time() - start_time
    
    if rank == 0:
        print(f"Decryption time: {decryption_time:.6f} seconds")
        print(f"Decrypted: {decrypted}")
        print()
        
        if plaintext == decrypted:
            print("✓ SUCCESS: Decryption matches original plaintext!")
        else:
            print("✗ ERROR: Decryption does not match!")
        print()


def example_large_data():
    """Example with larger data to demonstrate parallel speedup."""
    comm = MPI.COMM_WORLD
    rank = comm.Get_rank()
    size = comm.Get_size()
    
    if rank == 0:
        print("=" * 70)
        print("Example 2: Large Data Parallel Encryption")
        print("=" * 70)
        print(f"Running with {size} MPI process(es)")
        print()
    
    master_key = b"LargeDataKey1234"
    cipher = ParallelWBC1(master_key, block_size=16, num_rounds=16)
    
    # Generate larger test data
    if rank == 0:
        # Create 10KB of data
        data_size = 10 * 1024  # 10KB
        plaintext = bytes([i % 256 for i in range(data_size)])
        print(f"Data size: {data_size} bytes ({data_size // 1024}KB)")
        print(f"Number of blocks: {(len(plaintext) + 15) // 16}")
        print()
    else:
        plaintext = None
    
    # Encrypt
    start_time = time.time()
    ciphertext = cipher.encrypt(plaintext)
    encryption_time = time.time() - start_time
    
    if rank == 0:
        print(f"Encryption time: {encryption_time:.6f} seconds")
        print(f"Throughput: {len(plaintext) / encryption_time / 1024:.2f} KB/s")
        print()
    
    # Decrypt
    start_time = time.time()
    decrypted = cipher.decrypt(ciphertext)
    decryption_time = time.time() - start_time
    
    if rank == 0:
        print(f"Decryption time: {decryption_time:.6f} seconds")
        print(f"Throughput: {len(ciphertext) / decryption_time / 1024:.2f} KB/s")
        print()
        
        if plaintext == decrypted:
            print("✓ SUCCESS: Large data encryption/decryption verified!")
        else:
            print("✗ ERROR: Decryption mismatch!")
        print()


def example_statistical_analysis():
    """Example with statistical analysis."""
    comm = MPI.COMM_WORLD
    rank = comm.Get_rank()
    size = comm.Get_size()
    
    if rank == 0:
        print("=" * 70)
        print("Example 3: Statistical Analysis")
        print("=" * 70)
        print(f"Running with {size} MPI process(es)")
        print()
    
    master_key = b"StatTestKey12345"
    parallel_cipher = ParallelWBC1(master_key, block_size=16, num_rounds=16)
    
    if rank == 0:
        plaintext = b"The quick brown fox jumps over the lazy dog. " * 10
        print(f"Analyzing encryption of {len(plaintext)} bytes...")
        print()
    else:
        plaintext = None
    
    # Encrypt
    ciphertext = parallel_cipher.encrypt(plaintext)
    
    if rank == 0:
        # Run statistical tests (only on master process)
        cipher = WBC1Cipher(master_key, block_size=16, num_rounds=16)
        results = run_statistical_tests(plaintext, ciphertext, cipher)
        
        print("Statistical Test Results:")
        print("-" * 70)
        print(f"Plaintext entropy:  {results['plaintext_entropy']:.6f} bits/byte")
        print(f"Ciphertext entropy: {results['ciphertext_entropy']:.6f} bits/byte")
        print(f"  (Higher entropy indicates more randomness, ideal: 8.0)")
        print()
        
        print(f"Plaintext-Ciphertext correlation: {results['correlation']:.6f}")
        print(f"  (Lower correlation is better, ideal: ~0.0)")
        print()
        
        print("Frequency Analysis (Ciphertext):")
        freq = results['ciphertext_frequency']
        print(f"  Mean frequency: {freq['mean']:.2f}")
        print(f"  Std deviation:  {freq['std']:.2f}")
        print(f"  Chi-square:     {freq['chi_square']:.2f}")
        print(f"  (Uniform distribution has low std deviation)")
        print()
        
        print("Avalanche Effect:")
        avalanche = results['avalanche_effect']
        print(f"  Mean bit flip:  {avalanche['mean_flip_percentage']:.2f}%")
        print(f"  Std deviation:  {avalanche['std_flip_percentage']:.2f}%")
        print(f"  Range: [{avalanche['min_flip_percentage']:.2f}%, "
              f"{avalanche['max_flip_percentage']:.2f}%]")
        print(f"  (Ideal avalanche effect: ~50%)")
        print()


def example_custom_parameters():
    """Example with custom cipher parameters."""
    comm = MPI.COMM_WORLD
    rank = comm.Get_rank()
    size = comm.Get_size()
    
    if rank == 0:
        print("=" * 70)
        print("Example 4: Custom Cipher Parameters")
        print("=" * 70)
        print(f"Running with {size} MPI process(es)")
        print()
    
    # Test different configurations
    configs = [
        (16, 8, "Standard (16 bytes, 8 rounds)"),
        (16, 16, "Standard (16 bytes, 16 rounds)"),
        (32, 16, "Large blocks (32 bytes, 16 rounds)"),
    ]
    
    for block_size, num_rounds, description in configs:
        if rank == 0:
            print(f"Configuration: {description}")
            print(f"  Block size: {block_size} bytes")
            print(f"  Rounds: {num_rounds}")
        
        master_key = b"CustomParamsKey!" * (max(1, block_size // 16))
        master_key = master_key[:block_size]  # Trim to block size
        
        cipher = ParallelWBC1(master_key, block_size=block_size, num_rounds=num_rounds)
        
        if rank == 0:
            plaintext = b"Test message for custom parameters. " * 3
        else:
            plaintext = None
        
        start_time = time.time()
        ciphertext = cipher.encrypt(plaintext)
        elapsed = time.time() - start_time
        
        decrypted = cipher.decrypt(ciphertext)
        
        if rank == 0:
            success = plaintext == decrypted
            status = "✓" if success else "✗"
            print(f"  {status} Encryption time: {elapsed:.6f}s, Status: {'PASS' if success else 'FAIL'}")
            print()


def main():
    """Run all examples."""
    comm = MPI.COMM_WORLD
    rank = comm.Get_rank()
    
    if rank == 0:
        print()
        print("╔" + "═" * 68 + "╗")
        print("║" + " " * 15 + "WBC1 Parallel Cipher Examples" + " " * 24 + "║")
        print("╚" + "═" * 68 + "╝")
        print()
    
    # Run examples
    example_basic()
    comm.Barrier()
    
    example_large_data()
    comm.Barrier()
    
    example_statistical_analysis()
    comm.Barrier()
    
    example_custom_parameters()
    comm.Barrier()
    
    if rank == 0:
        print("=" * 70)
        print("All examples completed successfully!")
        print("=" * 70)


if __name__ == "__main__":
    main()
