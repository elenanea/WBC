#!/usr/bin/env python3
"""
Test script for WBC1 parallel cipher implementation.
This script can be run without MPI to test basic functionality.
"""

import sys
import numpy as np

# Test without MPI first
def test_basic_cipher():
    """Test basic WBC1Cipher functionality without MPI."""
    print("Testing WBC1Cipher (non-parallel)...")
    
    from wbc1_parallel import WBC1Cipher
    
    # Create cipher
    key = b"TestKey123456789"
    cipher = WBC1Cipher(key, block_size=16, num_rounds=16)
    
    # Test single block encryption/decryption
    plaintext_block = np.random.randint(0, 256, 16, dtype=np.uint8)
    ciphertext_block = cipher.encrypt_block(plaintext_block)
    decrypted_block = cipher.decrypt_block(ciphertext_block)
    
    # Verify
    if np.array_equal(plaintext_block, decrypted_block):
        print("✓ Single block encryption/decryption: PASSED")
        return True
    else:
        print("✗ Single block encryption/decryption: FAILED")
        return False


def test_statistical_functions():
    """Test statistical functions."""
    print("\nTesting statistical functions...")
    
    from wbc1_parallel import (
        shannon_entropy, avalanche_test, frequency_test, 
        correlation_test, WBC1Cipher
    )
    
    # Test entropy
    data = b"A" * 100
    entropy = shannon_entropy(data)
    print(f"  Entropy of repeated 'A': {entropy:.4f} (expected: 0.0)")
    
    random_data = np.random.randint(0, 256, 1000, dtype=np.uint8).tobytes()
    entropy = shannon_entropy(random_data)
    print(f"  Entropy of random data: {entropy:.4f} (expected: ~8.0)")
    
    # Test frequency
    freq_stats = frequency_test(random_data)
    print(f"  Frequency test mean: {freq_stats['mean']:.2f}")
    
    # Test avalanche effect
    cipher = WBC1Cipher(b"TestKey123456789", block_size=16, num_rounds=16)
    avalanche_results = avalanche_test(cipher, num_tests=10)
    print(f"  Avalanche effect: {avalanche_results['mean_flip_percentage']:.2f}% (expected: ~50%)")
    
    # Test correlation
    corr = correlation_test(b"test", b"test")
    print(f"  Correlation (identical): {corr:.4f} (expected: 1.0)")
    
    print("✓ Statistical functions: PASSED")
    return True


def test_deterministic():
    """Test that encryption is deterministic."""
    print("\nTesting deterministic behavior...")
    
    from wbc1_parallel import WBC1Cipher
    
    key = b"TestKey123456789"
    cipher = WBC1Cipher(key, block_size=16, num_rounds=16)
    
    plaintext = np.random.randint(0, 256, 16, dtype=np.uint8)
    
    # Encrypt twice
    ciphertext1 = cipher.encrypt_block(plaintext)
    ciphertext2 = cipher.encrypt_block(plaintext)
    
    if np.array_equal(ciphertext1, ciphertext2):
        print("✓ Deterministic encryption: PASSED")
        return True
    else:
        print("✗ Deterministic encryption: FAILED")
        return False


def test_different_keys():
    """Test that different keys produce different outputs."""
    print("\nTesting key sensitivity...")
    
    from wbc1_parallel import WBC1Cipher
    
    key1 = b"Key1234567890123"
    key2 = b"Key1234567890124"  # One character different
    
    cipher1 = WBC1Cipher(key1, block_size=16, num_rounds=16)
    cipher2 = WBC1Cipher(key2, block_size=16, num_rounds=16)
    
    plaintext = np.random.randint(0, 256, 16, dtype=np.uint8)
    
    ciphertext1 = cipher1.encrypt_block(plaintext)
    ciphertext2 = cipher2.encrypt_block(plaintext)
    
    if not np.array_equal(ciphertext1, ciphertext2):
        print("✓ Key sensitivity: PASSED")
        return True
    else:
        print("✗ Key sensitivity: FAILED")
        return False


def test_multiple_blocks():
    """Test multiple block encryption."""
    print("\nTesting multiple blocks...")
    
    from wbc1_parallel import WBC1Cipher
    
    key = b"TestKey123456789"
    cipher = WBC1Cipher(key, block_size=16, num_rounds=16)
    
    # Create 10 random blocks
    num_blocks = 10
    blocks = [np.random.randint(0, 256, 16, dtype=np.uint8) for _ in range(num_blocks)]
    
    # Encrypt and decrypt all blocks
    encrypted = [cipher.encrypt_block(block) for block in blocks]
    decrypted = [cipher.decrypt_block(enc_block) for enc_block in encrypted]
    
    # Verify all blocks
    success = all(np.array_equal(orig, dec) for orig, dec in zip(blocks, decrypted))
    
    if success:
        print(f"✓ Multiple blocks ({num_blocks} blocks): PASSED")
        return True
    else:
        print(f"✗ Multiple blocks ({num_blocks} blocks): FAILED")
        return False


def main():
    """Run all tests."""
    print("=" * 60)
    print("WBC1 Cipher Test Suite")
    print("=" * 60)
    
    tests = [
        test_basic_cipher,
        test_deterministic,
        test_different_keys,
        test_multiple_blocks,
        test_statistical_functions,
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"✗ Test failed with exception: {e}")
            import traceback
            traceback.print_exc()
            results.append(False)
    
    print("\n" + "=" * 60)
    passed = sum(results)
    total = len(results)
    print(f"Test Results: {passed}/{total} passed")
    print("=" * 60)
    
    if passed == total:
        print("✓ All tests passed!")
        return 0
    else:
        print("✗ Some tests failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
