#!/usr/bin/env python3
"""
Interactive WBC1 Cipher - User-friendly interface with multiple modes
Интерактивная версия шифра WBC1 с пользовательским интерфейсом
Supports ISO/IEC 10116-2006/2017 modes: ECB, CBC, CFB, OFB, CTR, WBC-CTR-HMAC
"""

import sys
import time
import secrets
import hashlib
import hmac
import os
from typing import Tuple, Optional
from mpi4py import MPI
from wbc1_parallel import ParallelWBC1, WBC1Cipher
import numpy as np

# Redirect stdin for non-rank-0 processes to avoid input() issues in MPI
comm = MPI.COMM_WORLD
rank = comm.Get_rank()
if rank != 0:
    # Close stdin and redirect to /dev/null for non-root processes
    sys.stdin.close()
    sys.stdin = open(os.devnull, 'r')


def generate_random_key(length: int) -> bytes:
    """Generate a cryptographically secure random key."""
    return secrets.token_bytes(length)


def print_separator():
    """Print a visual separator."""
    print("=" * 70)


def print_header():
    """Print program header."""
    print_separator()
    print("       ИНТЕРАКТИВНЫЙ ШИФР WBC1 С MPI")
    print("       Interactive WBC1 Cipher with MPI")
    print_separator()
    print()


def get_text_input() -> str:
    """Get text to encrypt from user."""
    print("1. ВВОД ТЕКСТА ДЛЯ ШИФРОВАНИЯ")
    print("   Enter text to encrypt:")
    print()
    text = input("   Введите текст: ")
    print()
    # Show what was entered for clarity
    print(f"   ✓ Введено / Entered: {text[:80]}{'...' if len(text) > 80 else ''}")
    print()
    return text


def get_key_choice() -> Tuple[bytes, str]:
    """Get encryption key from user or generate automatically."""
    print("2. ВЫБОР КЛЮЧА ШИФРОВАНИЯ")
    print("   Encryption key selection:")
    print()
    print("   1) Ввести свой ключ (Enter custom key)")
    print("   2) Сгенерировать автоматически (Generate automatically)")
    print()
    
    choice = input("   Ваш выбор (1/2): ").strip()
    print(f"   ✓ Выбрано / Selected: {choice}")
    print()
    
    if choice == "1":
        key_str = input("   Введите ключ: ")
        print(f"   ✓ Ключ введён / Key entered: {key_str[:20]}{'...' if len(key_str) > 20 else ''}")
        print()
        key = key_str.encode('utf-8')
        key_source = "пользовательский (user-provided)"
    else:
        print("3. ДЛИНА КЛЮЧА")
        print("   Key length:")
        print()
        print("   Рекомендуемые значения / Recommended values:")
        print("   1) 16 байт (128 бит)")
        print("   2) 24 байта (192 бита)")
        print("   3) 32 байта (256 бит)")
        print("   4) Другая длина (Custom)")
        print()
        
        length_choice = input("   Ваш выбор (1-4): ").strip()
        print(f"   ✓ Выбрано / Selected: {length_choice}")
        print()
        
        if length_choice == "1":
            length = 16
        elif length_choice == "2":
            length = 24
        elif length_choice == "3":
            length = 32
        else:
            try:
                length = int(input("   Введите длину ключа в байтах: "))
                print(f"   ✓ Введено / Entered: {length} байт")
                print()
                if length < 8:
                    print("   ⚠ Предупреждение: длина меньше 8 байт небезопасна!")
                    length = max(8, length)
            except ValueError:
                print("   ⚠ Некорректный ввод, используется 16 байт")
                length = 16
        
        key = generate_random_key(length)
        key_source = f"сгенерирован ({length} байт)"
    
    return key, key_source


def get_rounds() -> int:
    """Get number of encryption rounds."""
    print("4. КОЛИЧЕСТВО РАУНДОВ ШИФРОВАНИЯ")
    print("   Number of encryption rounds:")
    print()
    print("   Рекомендуемые значения / Recommended values:")
    print("   1) 10 раундов (быстрее, базовая безопасность)")
    print("   2) 16 раундов (рекомендуется, баланс)")
    print("   3) 20 раундов (медленнее, повышенная безопасность)")
    print("   4) 32 раунда (максимальная безопасность)")
    print("   5) Другое значение (Custom)")
    print()
    
    choice = input("   Ваш выбор (1-5): ").strip()
    print(f"   ✓ Выбрано / Selected: {choice}")
    print()
    
    if choice == "1":
        return 10
    elif choice == "2":
        return 16
    elif choice == "3":
        return 20
    elif choice == "4":
        return 32
    else:
        try:
            rounds = int(input("   Введите количество раундов: "))
            print(f"   ✓ Введено / Entered: {rounds} раундов")
            print()
            return max(1, rounds)
        except ValueError:
            print("   ⚠ Некорректный ввод, используется 16 раундов")
            return 16


def get_mode() -> str:
    """Get encryption mode according to ISO/IEC 10116-2006/2017."""
    print("5. РЕЖИМ ШИФРОВАНИЯ (ISO/IEC 10116-2006/2017)")
    print("   Encryption mode:")
    print()
    print("   1) ECB (Electronic Codebook)")
    print("   2) CBC (Cipher Block Chaining)")
    print("   3) CFB (Cipher Feedback)")
    print("   4) OFB (Output Feedback)")
    print("   5) CTR (Counter mode)")
    print("   6) WBC-CTR-HMAC (Counter with HMAC)")
    print("   7) Parallel MPI (распределённое шифрование)")
    print()
    
    choice = input("   Ваш выбор (1-7): ").strip()
    print(f"   ✓ Выбрано / Selected: {choice}")
    print()
    
    mode_map = {
        "1": "ECB",
        "2": "CBC",
        "3": "CFB",
        "4": "OFB",
        "5": "CTR",
        "6": "WBC-CTR-HMAC",
        "7": "Parallel"
    }
    
    return mode_map.get(choice, "ECB")


def encrypt_ecb_mode(plaintext: bytes, key: bytes, block_size: int, num_rounds: int) -> Tuple[bytes, float, float]:
    """Encrypt using ECB mode (Electronic Codebook - ISO/IEC 10116)."""
    cipher = WBC1Cipher(key, block_size=block_size, num_rounds=num_rounds)
    
    # Pad data
    padding_length = block_size - (len(plaintext) % block_size)
    if padding_length == 0:
        padding_length = block_size
    padded_data = plaintext + bytes([padding_length] * padding_length)
    
    # Encrypt blocks
    start_time = time.time()
    encrypted_blocks = []
    for i in range(0, len(padded_data), block_size):
        block = padded_data[i:i + block_size]
        block_array = np.frombuffer(block, dtype=np.uint8).copy()
        encrypted_block = cipher.encrypt_block(block_array)
        encrypted_blocks.append(encrypted_block.tobytes())
    ciphertext = b''.join(encrypted_blocks)
    encryption_time = time.time() - start_time
    
    # Decrypt blocks
    start_time = time.time()
    decrypted_blocks = []
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        block_array = np.frombuffer(block, dtype=np.uint8).copy()
        decrypted_block = cipher.decrypt_block(block_array)
        decrypted_blocks.append(decrypted_block.tobytes())
    decrypted_padded = b''.join(decrypted_blocks)
    
    # Remove padding
    padding_length = decrypted_padded[-1]
    decrypted = decrypted_padded[:-padding_length]
    decryption_time = time.time() - start_time
    
    return decrypted, encryption_time, decryption_time


def encrypt_cbc_mode(plaintext: bytes, key: bytes, block_size: int, num_rounds: int) -> Tuple[bytes, float, float]:
    """Encrypt using CBC mode (Cipher Block Chaining - ISO/IEC 10116)."""
    cipher = WBC1Cipher(key, block_size=block_size, num_rounds=num_rounds)
    
    # Generate IV
    iv = secrets.token_bytes(block_size)
    
    # Pad data
    padding_length = block_size - (len(plaintext) % block_size)
    if padding_length == 0:
        padding_length = block_size
    padded_data = plaintext + bytes([padding_length] * padding_length)
    
    # Encrypt blocks with chaining
    start_time = time.time()
    encrypted_blocks = [iv]  # Prepend IV
    previous_block = np.frombuffer(iv, dtype=np.uint8).copy()
    
    for i in range(0, len(padded_data), block_size):
        block = padded_data[i:i + block_size]
        block_array = np.frombuffer(block, dtype=np.uint8).copy()
        # XOR with previous ciphertext block
        xored = block_array ^ previous_block
        encrypted_block = cipher.encrypt_block(xored)
        encrypted_blocks.append(encrypted_block.tobytes())
        previous_block = encrypted_block
    
    ciphertext = b''.join(encrypted_blocks)
    encryption_time = time.time() - start_time
    
    # Decrypt blocks
    start_time = time.time()
    # Extract IV
    iv_received = ciphertext[:block_size]
    ciphertext_only = ciphertext[block_size:]
    
    decrypted_blocks = []
    previous_block = np.frombuffer(iv_received, dtype=np.uint8).copy()
    
    for i in range(0, len(ciphertext_only), block_size):
        block = ciphertext_only[i:i + block_size]
        block_array = np.frombuffer(block, dtype=np.uint8).copy()
        decrypted_block = cipher.decrypt_block(block_array)
        # XOR with previous ciphertext block
        xored = decrypted_block ^ previous_block
        decrypted_blocks.append(xored.tobytes())
        previous_block = block_array
    
    decrypted_padded = b''.join(decrypted_blocks)
    
    # Remove padding
    padding_length = decrypted_padded[-1]
    decrypted = decrypted_padded[:-padding_length]
    decryption_time = time.time() - start_time
    
    return decrypted, encryption_time, decryption_time


def encrypt_cfb_mode(plaintext: bytes, key: bytes, block_size: int, num_rounds: int) -> Tuple[bytes, float, float]:
    """Encrypt using CFB mode (Cipher Feedback - ISO/IEC 10116)."""
    cipher = WBC1Cipher(key, block_size=block_size, num_rounds=num_rounds)
    
    # Generate IV
    iv = secrets.token_bytes(block_size)
    
    # Encrypt
    start_time = time.time()
    encrypted_blocks = [iv]
    feedback = np.frombuffer(iv, dtype=np.uint8).copy()
    
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        # Encrypt feedback
        encrypted_feedback = cipher.encrypt_block(feedback)
        # XOR with plaintext
        if len(block) < block_size:
            # Handle last block
            block = block + b'\x00' * (block_size - len(block))
        block_array = np.frombuffer(block, dtype=np.uint8).copy()
        ciphertext_block = block_array ^ encrypted_feedback[:len(block)]
        encrypted_blocks.append(ciphertext_block[:len(plaintext[i:i + block_size])].tobytes())
        # Update feedback
        feedback = ciphertext_block if len(block) == block_size else np.frombuffer(block + ciphertext_block[:len(plaintext[i:i + block_size])].tobytes(), dtype=np.uint8).copy()
    
    ciphertext = b''.join(encrypted_blocks)
    encryption_time = time.time() - start_time
    
    # Decrypt
    start_time = time.time()
    iv_received = ciphertext[:block_size]
    ciphertext_only = ciphertext[block_size:]
    
    decrypted_blocks = []
    feedback = np.frombuffer(iv_received, dtype=np.uint8).copy()
    
    for i in range(0, len(ciphertext_only), block_size):
        block = ciphertext_only[i:i + block_size]
        # Encrypt feedback
        encrypted_feedback = cipher.encrypt_block(feedback)
        # XOR with ciphertext
        if len(block) < block_size:
            block = block + b'\x00' * (block_size - len(block))
        block_array = np.frombuffer(block, dtype=np.uint8).copy()
        plaintext_block = block_array[:len(ciphertext_only[i:i + block_size])] ^ encrypted_feedback[:len(ciphertext_only[i:i + block_size])]
        decrypted_blocks.append(plaintext_block.tobytes())
        # Update feedback with ciphertext
        feedback = block_array
    
    decrypted = b''.join(decrypted_blocks)
    decryption_time = time.time() - start_time
    
    return decrypted, encryption_time, decryption_time


def encrypt_ofb_mode(plaintext: bytes, key: bytes, block_size: int, num_rounds: int) -> Tuple[bytes, float, float]:
    """Encrypt using OFB mode (Output Feedback - ISO/IEC 10116)."""
    cipher = WBC1Cipher(key, block_size=block_size, num_rounds=num_rounds)
    
    # Generate IV
    iv = secrets.token_bytes(block_size)
    
    # Encrypt
    start_time = time.time()
    encrypted_blocks = [iv]
    feedback = np.frombuffer(iv, dtype=np.uint8).copy()
    
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        # Encrypt feedback
        feedback = cipher.encrypt_block(feedback)
        # XOR with plaintext
        if len(block) < block_size:
            block = block + b'\x00' * (block_size - len(block))
        block_array = np.frombuffer(block, dtype=np.uint8).copy()
        ciphertext_block = block_array[:len(plaintext[i:i + block_size])] ^ feedback[:len(plaintext[i:i + block_size])]
        encrypted_blocks.append(ciphertext_block.tobytes())
    
    ciphertext = b''.join(encrypted_blocks)
    encryption_time = time.time() - start_time
    
    # Decrypt (same as encrypt for OFB)
    start_time = time.time()
    iv_received = ciphertext[:block_size]
    ciphertext_only = ciphertext[block_size:]
    
    decrypted_blocks = []
    feedback = np.frombuffer(iv_received, dtype=np.uint8).copy()
    
    for i in range(0, len(ciphertext_only), block_size):
        block = ciphertext_only[i:i + block_size]
        # Encrypt feedback
        feedback = cipher.encrypt_block(feedback)
        # XOR with ciphertext
        if len(block) < block_size:
            block = block + b'\x00' * (block_size - len(block))
        block_array = np.frombuffer(block, dtype=np.uint8).copy()
        plaintext_block = block_array[:len(ciphertext_only[i:i + block_size])] ^ feedback[:len(ciphertext_only[i:i + block_size])]
        decrypted_blocks.append(plaintext_block.tobytes())
    
    decrypted = b''.join(decrypted_blocks)
    decryption_time = time.time() - start_time
    
    return decrypted, encryption_time, decryption_time


def encrypt_ctr_mode(plaintext: bytes, key: bytes, block_size: int, num_rounds: int) -> Tuple[bytes, float, float]:
    """Encrypt using CTR mode (Counter - ISO/IEC 10116)."""
    cipher = WBC1Cipher(key, block_size=block_size, num_rounds=num_rounds)
    
    # Generate nonce
    nonce = secrets.token_bytes(block_size // 2)
    counter = 0
    
    # Encrypt
    start_time = time.time()
    encrypted_blocks = [nonce]
    
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        # Create counter block
        counter_block = nonce + counter.to_bytes(block_size // 2, 'big')
        counter_array = np.frombuffer(counter_block, dtype=np.uint8).copy()
        # Encrypt counter
        encrypted_counter = cipher.encrypt_block(counter_array)
        # XOR with plaintext
        if len(block) < block_size:
            block = block + b'\x00' * (block_size - len(block))
        block_array = np.frombuffer(block, dtype=np.uint8).copy()
        ciphertext_block = block_array[:len(plaintext[i:i + block_size])] ^ encrypted_counter[:len(plaintext[i:i + block_size])]
        encrypted_blocks.append(ciphertext_block.tobytes())
        counter += 1
    
    ciphertext = b''.join(encrypted_blocks)
    encryption_time = time.time() - start_time
    
    # Decrypt (same as encrypt for CTR)
    start_time = time.time()
    nonce_received = ciphertext[:block_size // 2]
    ciphertext_only = ciphertext[block_size // 2:]
    counter = 0
    
    decrypted_blocks = []
    
    for i in range(0, len(ciphertext_only), block_size):
        block = ciphertext_only[i:i + block_size]
        # Create counter block
        counter_block = nonce_received + counter.to_bytes(block_size // 2, 'big')
        counter_array = np.frombuffer(counter_block, dtype=np.uint8).copy()
        # Encrypt counter
        encrypted_counter = cipher.encrypt_block(counter_array)
        # XOR with ciphertext
        if len(block) < block_size:
            block = block + b'\x00' * (block_size - len(block))
        block_array = np.frombuffer(block, dtype=np.uint8).copy()
        plaintext_block = block_array[:len(ciphertext_only[i:i + block_size])] ^ encrypted_counter[:len(ciphertext_only[i:i + block_size])]
        decrypted_blocks.append(plaintext_block.tobytes())
        counter += 1
    
    decrypted = b''.join(decrypted_blocks)
    decryption_time = time.time() - start_time
    
    return decrypted, encryption_time, decryption_time


def encrypt_wbc_ctr_hmac_mode(plaintext: bytes, key: bytes, block_size: int, num_rounds: int) -> Tuple[bytes, float, float]:
    """Encrypt using WBC-CTR-HMAC mode (Counter with HMAC authentication)."""
    cipher = WBC1Cipher(key, block_size=block_size, num_rounds=num_rounds)
    
    # Derive separate keys for encryption and HMAC
    enc_key = key
    hmac_key = hashlib.sha256(key + b'hmac').digest()
    
    # Generate nonce
    nonce = secrets.token_bytes(block_size // 2)
    counter = 0
    
    # Encrypt
    start_time = time.time()
    encrypted_blocks = []
    
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        # Create counter block
        counter_block = nonce + counter.to_bytes(block_size // 2, 'big')
        counter_array = np.frombuffer(counter_block, dtype=np.uint8).copy()
        # Encrypt counter
        encrypted_counter = cipher.encrypt_block(counter_array)
        # XOR with plaintext
        if len(block) < block_size:
            block = block + b'\x00' * (block_size - len(block))
        block_array = np.frombuffer(block, dtype=np.uint8).copy()
        ciphertext_block = block_array[:len(plaintext[i:i + block_size])] ^ encrypted_counter[:len(plaintext[i:i + block_size])]
        encrypted_blocks.append(ciphertext_block.tobytes())
        counter += 1
    
    ciphertext_only = b''.join(encrypted_blocks)
    
    # Compute HMAC
    h = hmac.new(hmac_key, nonce + ciphertext_only, hashlib.sha256)
    mac = h.digest()
    
    # Combine: nonce + ciphertext + HMAC
    ciphertext = nonce + ciphertext_only + mac
    encryption_time = time.time() - start_time
    
    # Decrypt
    start_time = time.time()
    # Extract components
    nonce_received = ciphertext[:block_size // 2]
    mac_received = ciphertext[-32:]  # SHA-256 produces 32 bytes
    ciphertext_data = ciphertext[block_size // 2:-32]
    
    # Verify HMAC
    h = hmac.new(hmac_key, nonce_received + ciphertext_data, hashlib.sha256)
    if not hmac.compare_digest(h.digest(), mac_received):
        raise ValueError("HMAC verification failed - data may be corrupted or tampered!")
    
    counter = 0
    decrypted_blocks = []
    
    for i in range(0, len(ciphertext_data), block_size):
        block = ciphertext_data[i:i + block_size]
        # Create counter block
        counter_block = nonce_received + counter.to_bytes(block_size // 2, 'big')
        counter_array = np.frombuffer(counter_block, dtype=np.uint8).copy()
        # Encrypt counter
        encrypted_counter = cipher.encrypt_block(counter_array)
        # XOR with ciphertext
        if len(block) < block_size:
            block = block + b'\x00' * (block_size - len(block))
        block_array = np.frombuffer(block, dtype=np.uint8).copy()
        plaintext_block = block_array[:len(ciphertext_data[i:i + block_size])] ^ encrypted_counter[:len(ciphertext_data[i:i + block_size])]
        decrypted_blocks.append(plaintext_block.tobytes())
        counter += 1
    
    decrypted = b''.join(decrypted_blocks)
    decryption_time = time.time() - start_time
    
    return decrypted, encryption_time, decryption_time


def parallel_encrypt_ecb_mode(plaintext: bytes, key: bytes, block_size: int, num_rounds: int) -> Tuple[bytes, float, float]:
    """Encrypt using parallel ECB mode - distributes blocks across MPI processes."""
    global comm, rank
    size = comm.Get_size()
    
    cipher = WBC1Cipher(key, block_size=block_size, num_rounds=num_rounds)
    
    # Rank 0 prepares data
    if rank == 0:
        # Pad data
        padding_length = block_size - (len(plaintext) % block_size)
        if padding_length == 0:
            padding_length = block_size
        padded_data = plaintext + bytes([padding_length] * padding_length)
        
        # Split into blocks
        num_blocks = len(padded_data) // block_size
        blocks = [padded_data[i*block_size:(i+1)*block_size] for i in range(num_blocks)]
    else:
        blocks = None
        num_blocks = None
    
    # Broadcast number of blocks and all blocks to all processes
    num_blocks = comm.bcast(num_blocks, root=0)
    blocks = comm.bcast(blocks, root=0)
    
    # Each process determines which blocks it should encrypt (round-robin)
    local_blocks = [blocks[i] for i in range(num_blocks) if i % size == rank]
    
    # Each process encrypts its blocks
    comm.Barrier()
    start_time = time.time()
    local_encrypted = []
    for block in local_blocks:
        block_array = np.frombuffer(block, dtype=np.uint8).copy()
        encrypted_block = cipher.encrypt_block(block_array)
        local_encrypted.append(encrypted_block.tobytes())
    
    # Gather encrypted blocks
    all_encrypted = comm.gather(local_encrypted, root=0)
    
    if rank == 0:
        # Reconstruct ciphertext in correct order
        encrypted_blocks = [None] * num_blocks
        for proc_rank, proc_blocks in enumerate(all_encrypted):
            block_idx = proc_rank
            for block in proc_blocks:
                encrypted_blocks[block_idx] = block
                block_idx += size
        ciphertext = b''.join(encrypted_blocks)
        encryption_time = time.time() - start_time
    else:
        ciphertext = None
        encryption_time = None
    
    comm.Barrier()
    
    # Broadcast ciphertext and time for decryption
    ciphertext = comm.bcast(ciphertext, root=0)
    encryption_time = comm.bcast(encryption_time, root=0)
    
    # Parallel decryption
    num_blocks = len(ciphertext) // block_size
    blocks = [ciphertext[i*block_size:(i+1)*block_size] for i in range(num_blocks)]
    
    # Each process determines which blocks to decrypt (round-robin)
    local_blocks = [blocks[i] for i in range(num_blocks) if i % size == rank]
    
    # Each process decrypts its blocks
    comm.Barrier()
    start_time = time.time()
    local_decrypted = []
    for block in local_blocks:
        block_array = np.frombuffer(block, dtype=np.uint8).copy()
        decrypted_block = cipher.decrypt_block(block_array)
        local_decrypted.append(decrypted_block.tobytes())
    
    # Gather decrypted blocks
    all_decrypted = comm.gather(local_decrypted, root=0)
    
    if rank == 0:
        # Reconstruct plaintext in correct order
        decrypted_blocks = [None] * num_blocks
        for proc_rank, proc_blocks in enumerate(all_decrypted):
            block_idx = proc_rank
            for block in proc_blocks:
                decrypted_blocks[block_idx] = block
                block_idx += size
        decrypted_padded = b''.join(decrypted_blocks)
        
        # Remove padding
        padding_length = decrypted_padded[-1]
        decrypted = decrypted_padded[:-padding_length]
        decryption_time = time.time() - start_time
    else:
        decrypted = None
        decryption_time = None
    
    comm.Barrier()
    
    # Broadcast results
    decrypted = comm.bcast(decrypted, root=0)
    decryption_time = comm.bcast(decryption_time, root=0)
    
    return decrypted, encryption_time, decryption_time


def parallel_encrypt_ctr_mode(plaintext: bytes, key: bytes, block_size: int, num_rounds: int) -> Tuple[bytes, float, float]:
    """Encrypt using parallel CTR mode - distributes counter blocks across MPI processes."""
    global comm, rank
    size = comm.Get_size()
    
    cipher = WBC1Cipher(key, block_size=block_size, num_rounds=num_rounds)
    
    # Rank 0 prepares data
    if rank == 0:
        # Generate nonce
        nonce = secrets.token_bytes(block_size // 2)
        data_len = len(plaintext)
        num_blocks = (data_len + block_size - 1) // block_size
    else:
        nonce = None
        data_len = None
        num_blocks = None
        plaintext = None
    
    # Broadcast parameters
    nonce = comm.bcast(nonce, root=0)
    data_len = comm.bcast(data_len, root=0)
    num_blocks = comm.bcast(num_blocks, root=0)
    plaintext = comm.bcast(plaintext, root=0)
    
    # Each process generates keystream for its assigned counters
    comm.Barrier()
    start_time = time.time()
    
    local_keystream_blocks = []
    for i in range(num_blocks):
        if i % size == rank:
            # This process handles this counter
            counter = i.to_bytes(block_size // 2, 'big')
            counter_block = nonce + counter
            counter_array = np.frombuffer(counter_block, dtype=np.uint8).copy()
            keystream_block = cipher.encrypt_block(counter_array)
            local_keystream_blocks.append((i, keystream_block.tobytes()))
    
    # Gather all keystream blocks
    all_keystream = comm.gather(local_keystream_blocks, root=0)
    
    if rank == 0:
        # Reconstruct keystream in correct order
        keystream_blocks = {}
        for proc_blocks in all_keystream:
            for idx, block in proc_blocks:
                keystream_blocks[idx] = block
        
        # XOR with plaintext
        encrypted_data = []
        for i in range(num_blocks):
            start = i * block_size
            end = min(start + block_size, data_len)
            plaintext_block = plaintext[start:end]
            keystream_block = keystream_blocks[i][:len(plaintext_block)]
            
            plaintext_array = np.frombuffer(plaintext_block, dtype=np.uint8).copy()
            keystream_array = np.frombuffer(keystream_block, dtype=np.uint8).copy()
            encrypted_block = (plaintext_array ^ keystream_array).tobytes()
            encrypted_data.append(encrypted_block)
        
        ciphertext_data = b''.join(encrypted_data)
        ciphertext = nonce + ciphertext_data
        encryption_time = time.time() - start_time
    else:
        ciphertext = None
        encryption_time = None
    
    comm.Barrier()
    
    # Broadcast for decryption
    ciphertext = comm.bcast(ciphertext, root=0)
    encryption_time = comm.bcast(encryption_time, root=0)
    
    # Parallel decryption (same keystream generation)
    if rank == 0:
        nonce_received = ciphertext[:block_size // 2]
        ciphertext_data = ciphertext[block_size // 2:]
        data_len = len(ciphertext_data)
        num_blocks = (data_len + block_size - 1) // block_size
    else:
        nonce_received = None
        ciphertext_data = None
        data_len = None
        num_blocks = None
    
    nonce_received = comm.bcast(nonce_received, root=0)
    ciphertext_data = comm.bcast(ciphertext_data, root=0)
    data_len = comm.bcast(data_len, root=0)
    num_blocks = comm.bcast(num_blocks, root=0)
    
    # Each process generates keystream for decryption
    comm.Barrier()
    start_time = time.time()
    
    local_keystream_blocks = []
    for i in range(num_blocks):
        if i % size == rank:
            counter = i.to_bytes(block_size // 2, 'big')
            counter_block = nonce_received + counter
            counter_array = np.frombuffer(counter_block, dtype=np.uint8).copy()
            keystream_block = cipher.encrypt_block(counter_array)
            local_keystream_blocks.append((i, keystream_block.tobytes()))
    
    # Gather all keystream blocks
    all_keystream = comm.gather(local_keystream_blocks, root=0)
    
    if rank == 0:
        # Reconstruct keystream
        keystream_blocks = {}
        for proc_blocks in all_keystream:
            for idx, block in proc_blocks:
                keystream_blocks[idx] = block
        
        # XOR with ciphertext
        decrypted_data = []
        for i in range(num_blocks):
            start = i * block_size
            end = min(start + block_size, data_len)
            ciphertext_block = ciphertext_data[start:end]
            keystream_block = keystream_blocks[i][:len(ciphertext_block)]
            
            ciphertext_array = np.frombuffer(ciphertext_block, dtype=np.uint8).copy()
            keystream_array = np.frombuffer(keystream_block, dtype=np.uint8).copy()
            decrypted_block = (ciphertext_array ^ keystream_array).tobytes()
            decrypted_data.append(decrypted_block)
        
        decrypted = b''.join(decrypted_data)
        decryption_time = time.time() - start_time
    else:
        decrypted = None
        decryption_time = None
    
    comm.Barrier()
    
    # Broadcast results
    decrypted = comm.bcast(decrypted, root=0)
    decryption_time = comm.bcast(decryption_time, root=0)
    
    return decrypted, encryption_time, decryption_time


def encrypt_parallel_mode(plaintext: bytes, key: bytes, block_size: int, num_rounds: int) -> Tuple[Optional[bytes], float, float]:
    """Encrypt using parallel MPI mode."""
    global comm, rank
    
    cipher = ParallelWBC1(key, block_size=block_size, num_rounds=num_rounds)
    
    # Prepare data
    if rank == 0:
        data = plaintext
    else:
        data = None
    
    # Encrypt
    start_time = time.time()
    ciphertext = cipher.encrypt(data)
    encryption_time = time.time() - start_time
    
    # Decrypt
    start_time = time.time()
    decrypted = cipher.decrypt(ciphertext)
    decryption_time = time.time() - start_time
    
    return decrypted, encryption_time, decryption_time


def display_key(key: bytes, source: str):
    """Display the encryption key."""
    print()
    print_separator()
    print("ИСПОЛЬЗУЕМЫЙ КЛЮЧ / ENCRYPTION KEY USED:")
    print_separator()
    print(f"Источник / Source: {source}")
    print(f"Длина / Length: {len(key)} байт / bytes")
    print(f"Hex: {key.hex()}")
    if len(key) <= 32:
        try:
            print(f"UTF-8: {key.decode('utf-8', errors='replace')}")
        except:
            pass
    print_separator()


def display_results(original: str, decrypted: bytes, enc_time: float, dec_time: float, mode: str):
    """Display encryption/decryption results."""
    print()
    print_separator()
    print("РЕЗУЛЬТАТЫ / RESULTS:")
    print_separator()
    print(f"Режим / Mode: {mode}")
    print()
    print(f"Исходный текст / Original text:")
    print(f"  {original}")
    print()
    print(f"Расшифрованный текст / Decrypted text:")
    try:
        decrypted_str = decrypted.decode('utf-8')
        print(f"  {decrypted_str}")
        
        if original == decrypted_str:
            print()
            print("  ✓ УСПЕХ: Расшифровка совпадает с оригиналом!")
            print("  ✓ SUCCESS: Decryption matches original!")
        else:
            print()
            print("  ✗ ОШИБКА: Расшифровка не совпадает!")
            print("  ✗ ERROR: Decryption mismatch!")
    except Exception as e:
        print(f"  [Ошибка декодирования: {e}]")
    
    print()
    print_separator()
    print("ВРЕМЯ ВЫПОЛНЕНИЯ / EXECUTION TIME:")
    print_separator()
    print(f"Шифрование / Encryption:   {enc_time:.6f} секунд / seconds")
    print(f"Расшифрование / Decryption: {dec_time:.6f} секунд / seconds")
    print(f"Общее время / Total time:   {enc_time + dec_time:.6f} секунд / seconds")
    print_separator()


def run_statistical_analysis(key: bytes, key_size: int, mode_name: str, num_rounds: int, data_size_kb: int):
    """Run statistical analysis and tests on the cipher."""
    global comm, rank
    size = comm.Get_size()
    
    from wbc1_parallel import shannon_entropy, avalanche_test, frequency_test, correlation_test
    
    if rank == 0:
        print()
        print_separator()
        print("СТАТИСТИЧЕСКИЙ АНАЛИЗ / STATISTICAL ANALYSIS")
        print_separator()
        print(f"Размер данных / Data size: {data_size_kb} KB")
        print(f"Количество процессов / Processes: {size}")
        print(f"Размер ключа / Key size: {key_size} bits ({key_size // 8} bytes)")
        print(f"Режим / Mode: {mode_name}")
        print(f"Раунды / Rounds: {num_rounds}")
        print_separator()
        print()
        
        # Generate test data
        data_size_bytes = data_size_kb * 1024
        plaintext = bytes([i % 256 for i in range(data_size_bytes)])
        print(f"Сгенерировано {data_size_bytes} байт тестовых данных")
        print()
        
        # Map mode to function
        parallel_mode_map = {
            "ECB": parallel_encrypt_ecb_mode,
            "CTR": parallel_encrypt_ctr_mode,
        }
        
        sequential_mode_map = {
            "CBC": encrypt_cbc_mode,
            "CFB": encrypt_cfb_mode,
            "OFB": encrypt_ofb_mode,
            "WBC-CTR-HMAC": encrypt_wbc_ctr_hmac_mode
        }
        
        block_size = 16
        
        if mode_name == "Parallel":
            # Use parallel mode
            cipher = ParallelWBC1(key, block_size=block_size, num_rounds=num_rounds)
            plaintext_bcast = None
        elif mode_name in parallel_mode_map:
            # Parallel ECB or CTR
            enc_func = parallel_mode_map[mode_name]
        else:
            # Use sequential mode
            enc_func = sequential_mode_map.get(mode_name, encrypt_cbc_mode)
    else:
        plaintext = None
        plaintext_bcast = None
    
    # Broadcast plaintext for parallel modes
    if mode_name == "Parallel":
        plaintext_bcast = comm.bcast(plaintext, root=0)
    elif mode_name in ["ECB", "CTR"]:
        # For parallel ECB/CTR, broadcast plaintext to all ranks
        plaintext = comm.bcast(plaintext, root=0)
    
    # Perform encryption
    if rank == 0:
        print("⏳ Выполняется шифрование...")
        
    if mode_name == "Parallel":
        cipher = ParallelWBC1(key, block_size=16, num_rounds=num_rounds)
        start_time = time.time()
        ciphertext = cipher.encrypt(plaintext_bcast if rank == 0 else None)
        enc_time = time.time() - start_time
        
        start_time = time.time()
        decrypted = cipher.decrypt(ciphertext)
        dec_time = time.time() - start_time
    elif mode_name in parallel_mode_map:
        # Parallel ECB or CTR - all ranks participate
        enc_func = parallel_mode_map[mode_name]
        decrypted, enc_time, dec_time = enc_func(plaintext, key, block_size, num_rounds)
        if rank == 0:
            ciphertext = b"N/A"  # Not storing full ciphertext for large data
    else:
        # Sequential modes - only rank 0
        if rank == 0:
            enc_func = sequential_mode_map.get(mode_name, encrypt_cbc_mode)
            decrypted, enc_time, dec_time = enc_func(plaintext, key, 16, num_rounds)
            ciphertext = b"N/A"  # Not storing full ciphertext for large data
        else:
            decrypted = None
            enc_time = None
            dec_time = None
        # Synchronize
        comm.Barrier()
        decrypted = comm.bcast(decrypted, root=0)
        enc_time = comm.bcast(enc_time, root=0)
        dec_time = comm.bcast(dec_time, root=0)
    
    if rank == 0:
        print(f"✓ Шифрование завершено / Encryption completed")
        print()
        
        # Performance metrics
        print_separator()
        print("ПРОИЗВОДИТЕЛЬНОСТЬ / PERFORMANCE")
        print_separator()
        print(f"Время шифрования / Encryption time:   {enc_time:.6f} сек")
        print(f"Время расшифрования / Decryption time: {dec_time:.6f} сек")
        print(f"Общее время / Total time:             {enc_time + dec_time:.6f} сек")
        
        throughput_enc = (data_size_kb / enc_time) if enc_time > 0 else 0
        throughput_dec = (data_size_kb / dec_time) if dec_time > 0 else 0
        print(f"Пропускная способность (шифр.) / Throughput (enc): {throughput_enc:.2f} KB/s")
        print(f"Пропускная способность (расш.) / Throughput (dec): {throughput_dec:.2f} KB/s")
        print_separator()
        print()
        
        # Verify correctness
        if plaintext == decrypted:
            print("✓ ВЕРИФИКАЦИЯ ПРОЙДЕНА / VERIFICATION PASSED")
            print()
        else:
            print("✗ ОШИБКА ВЕРИФИКАЦИИ / VERIFICATION FAILED")
            print()
        
        # Statistical tests
        print_separator()
        print("СТАТИСТИЧЕСКИЕ ТЕСТЫ / STATISTICAL TESTS")
        print_separator()
        
        # Sample for statistics (use first 10KB max for speed)
        sample_size = min(10240, len(plaintext))
        plaintext_sample = plaintext[:sample_size]
        
        # For statistical tests, we need actual ciphertext
        if mode_name != "Parallel":
            # Already have it from encryption
            pass
        
        # Entropy
        print(f"\n1. Энтропия Шеннона / Shannon Entropy:")
        pt_entropy = shannon_entropy(plaintext_sample)
        print(f"   Открытый текст / Plaintext:  {pt_entropy:.4f} бит/байт")
        
        # For ciphertext entropy, encrypt a sample
        cipher_obj = WBC1Cipher(key, block_size=16, num_rounds=num_rounds)
        # Pad sample
        padding_length = 16 - (len(plaintext_sample) % 16)
        if padding_length == 0:
            padding_length = 16
        padded_sample = plaintext_sample + bytes([padding_length] * padding_length)
        
        encrypted_blocks = []
        for i in range(0, len(padded_sample), 16):
            block = padded_sample[i:i + 16]
            block_array = np.frombuffer(block, dtype=np.uint8).copy()
            encrypted_block = cipher_obj.encrypt_block(block_array)
            encrypted_blocks.append(encrypted_block.tobytes())
        ciphertext_sample = b''.join(encrypted_blocks)
        
        ct_entropy = shannon_entropy(ciphertext_sample)
        print(f"   Шифртекст / Ciphertext:      {ct_entropy:.4f} бит/байт")
        print(f"   (Идеально / Ideal: 8.0 бит/байт)")
        
        # Frequency test
        print(f"\n2. Частотный тест / Frequency Test:")
        freq_stats = frequency_test(ciphertext_sample)
        print(f"   Среднее / Mean:        {freq_stats['mean']:.2f}")
        print(f"   Ст. откл. / Std dev:   {freq_stats['std']:.2f}")
        print(f"   Хи-квадрат / Chi-sq:   {freq_stats['chi_square']:.2f}")
        
        # Avalanche effect
        print(f"\n3. Лавинный эффект / Avalanche Effect:")
        num_tests = min(100, sample_size // 16)  # Limit for speed
        avalanche_results = avalanche_test(cipher_obj, num_tests=num_tests)
        print(f"   Среднее изменение битов / Mean bit flip: {avalanche_results['mean_flip_percentage']:.2f}%")
        print(f"   Ст. откл. / Std dev:                     {avalanche_results['std_flip_percentage']:.2f}%")
        print(f"   Диапазон / Range: [{avalanche_results['min_flip_percentage']:.2f}%, {avalanche_results['max_flip_percentage']:.2f}%]")
        print(f"   (Идеально / Ideal: ~50%)")
        
        # Correlation
        print(f"\n4. Корреляция / Correlation:")
        corr = correlation_test(plaintext_sample, ciphertext_sample[:len(plaintext_sample)])
        print(f"   Корреляция открытый-шифр / PT-CT: {corr:.6f}")
        print(f"   (Идеально / Ideal: ~0.0)")
        
        print()
        print_separator()
        print("АНАЛИЗ ЗАВЕРШЕН / ANALYSIS COMPLETED")
        print_separator()


def main_cmdline(args):
    """Main function for command-line mode."""
    global comm, rank
    size = comm.Get_size()
    
    # Parse arguments: mpi_mode key_size key_source mode rounds task [data_size]
    # mpi_mode: 0 or 1 (not used, MPI determined by mpiexec)
    # key_size: in bits (e.g., 128, 192, 256)
    # key_source: 0=auto-generate, 1=user-provided
    # mode: 1-7 (ECB, CBC, CFB, OFB, CTR, WBC-CTR-HMAC, Parallel)
    # rounds: number of rounds
    # task: 0=text encryption, 1=statistical analysis
    # data_size: size in KB (only for task=1)
    
    if len(args) < 6:
        if rank == 0:
            print("Usage: python3 interactive_cipher.py <mpi_mode> <key_size> <key_source> <mode> <rounds> <task> [data_size]")
            print("  mpi_mode: 0 or 1 (placeholder)")
            print("  key_size: key size in bits (e.g., 128, 192, 256)")
            print("  key_source: 0=auto-generate, 1=user-provided")
            print("  mode: 1=ECB, 2=CBC, 3=CFB, 4=OFB, 5=CTR, 6=WBC-CTR-HMAC, 7=Parallel")
            print("  rounds: number of rounds (e.g., 16, 32, 64)")
            print("  task: 0=text encryption, 1=statistical analysis")
            print("  data_size: size in KB (required for task=1)")
            print()
            print("Example: mpiexec -n 4 python3 interactive_cipher.py 0 256 0 2 64 0")
            print("Example: mpiexec -n 4 python3 interactive_cipher.py 0 256 0 2 64 1 1000")
        return
    
    try:
        mpi_mode = int(args[0])
        key_size_bits = int(args[1])
        key_source = int(args[2])
        mode_num = int(args[3])
        num_rounds = int(args[4])
        task = int(args[5])
        data_size_kb = int(args[6]) if len(args) > 6 else 10
    except ValueError:
        if rank == 0:
            print("Error: Invalid arguments. All must be integers.")
        return
    
    # Map mode number to mode name
    mode_map_num = {
        1: "ECB",
        2: "CBC",
        3: "CFB",
        4: "OFB",
        5: "CTR",
        6: "WBC-CTR-HMAC",
        7: "Parallel"
    }
    
    mode_name = mode_map_num.get(mode_num, "ECB")
    key_size_bytes = key_size_bits // 8
    
    # Generate or get key
    if rank == 0:
        if key_source == 0:
            # Auto-generate
            key = generate_random_key(key_size_bytes)
            key_source_str = "автоматически сгенерирован / auto-generated"
        else:
            # User-provided
            print("Введите ключ / Enter key:")
            key_str = input()
            key = key_str.encode('utf-8')
            # Pad or truncate to desired size
            if len(key) < key_size_bytes:
                key = key + b'\x00' * (key_size_bytes - len(key))
            elif len(key) > key_size_bytes:
                key = key[:key_size_bytes]
            key_source_str = "задан пользователем / user-provided"
    else:
        key = None
        key_source_str = None
    
    # Broadcast key
    key = comm.bcast(key, root=0)
    key_source_str = comm.bcast(key_source_str, root=0)
    
    # Print protocol header
    if rank == 0:
        print()
        print_separator()
        print("ПРОТОКОЛ ВЫПОЛНЕНИЯ / EXECUTION PROTOCOL")
        print_separator()
        print(f"Количество процессов / Number of processes: {size}")
        print(f"Размер ключа / Key size: {key_size_bits} бит ({key_size_bytes} байт)")
        print(f"Источник ключа / Key source: {key_source_str}")
        print(f"Режим выполнения / Execution mode: {mode_name}")
        print(f"Количество раундов / Number of rounds: {num_rounds}")
        print(f"Ключ / Key (hex): {key.hex()}")
        print_separator()
        print()
    
    if task == 0:
        # Text encryption mode
        if rank == 0:
            print("РЕЖИМ ШИФРОВАНИЯ ТЕКСТА / TEXT ENCRYPTION MODE")
            print()
            print("Введите текст для шифрования:")
            print("Enter text to encrypt:")
            sys.stdout.flush()  # Ensure output is displayed before input
            text = input()
            print()
        else:
            text = None
        
        # Broadcast text to all processes
        text = comm.bcast(text, root=0)
        
        if rank == 0:
            print(f"Введенный текст / Input text: {text}")
            print()
            print("⏳ Выполняется шифрование / Encrypting...")
            sys.stdout.flush()  # Ensure message is displayed
        
        # Encrypt
        block_size = 16
        
        # Initialize variables for all ranks to avoid scoping issues
        ciphertext = None
        decrypted = None
        enc_time = 0.0
        dec_time = 0.0
        
        # Parallel modes that use all MPI processes
        parallel_mode_functions = {
            "ECB": parallel_encrypt_ecb_mode,
            "CTR": parallel_encrypt_ctr_mode,
        }
        
        # Sequential modes that run on rank 0 only
        sequential_mode_functions = {
            "CBC": encrypt_cbc_mode,
            "CFB": encrypt_cfb_mode,
            "OFB": encrypt_ofb_mode,
            "WBC-CTR-HMAC": encrypt_wbc_ctr_hmac_mode
        }
        
        if mode_name in parallel_mode_functions:
            # Parallel ECB or CTR - all ranks participate
            # All ranks need the plaintext for parallel processing
            plaintext = text.encode('utf-8')
            decrypted, enc_time, dec_time = parallel_mode_functions[mode_name](plaintext, key, block_size, num_rounds)
            # Set ciphertext placeholder for all ranks
            ciphertext = b"<encrypted>"  # Placeholder for display
            # Synchronize after parallel encryption/decryption
            comm.Barrier()
        elif mode_name in sequential_mode_functions:
            # Sequential modes - only rank 0 does the work
            if rank == 0:
                plaintext = text.encode('utf-8')
                decrypted, enc_time, dec_time = sequential_mode_functions[mode_name](plaintext, key, block_size, num_rounds)
                ciphertext = b"<encrypted>"  # We don't need full ciphertext display
            else:
                # Other ranks wait
                decrypted = None
                enc_time = None
                dec_time = None
            # Synchronize all processes
            comm.Barrier()
            # Broadcast results to all ranks for consistency
            decrypted = comm.bcast(decrypted, root=0)
            enc_time = comm.bcast(enc_time, root=0)
            dec_time = comm.bcast(dec_time, root=0)
        elif mode_name == "Parallel":
            # Parallel MPI mode - all ranks participate
            cipher = ParallelWBC1(key, block_size=block_size, num_rounds=num_rounds)
            if rank == 0:
                plaintext = text.encode('utf-8')
            else:
                plaintext = None
            
            start_time = time.time()
            ciphertext = cipher.encrypt(plaintext)
            enc_time = time.time() - start_time
            
            start_time = time.time()
            decrypted = cipher.decrypt(ciphertext)
            dec_time = time.time() - start_time
            
            # Synchronize after parallel mode
            comm.Barrier()
        
        # Display results - only rank 0
        if rank == 0:
            print()
            print_separator()
            print("РЕЗУЛЬТАТЫ / RESULTS")
            print_separator()
            print(f"Зашифрованный текст / Encrypted text (hex): {ciphertext[:64].hex() if isinstance(ciphertext, bytes) and len(ciphertext) > 0 else 'N/A'}...")
            print(f"Расшифрованный текст / Decrypted text: {decrypted.decode('utf-8', errors='replace')}")
            print()
            print(f"Время шифрования / Encryption time:   {enc_time:.6f} сек")
            print(f"Время расшифрования / Decryption time: {dec_time:.6f} сек")
            print()
            
            if text == decrypted.decode('utf-8', errors='replace'):
                print("✓ УСПЕХ: Расшифровка совпадает с оригиналом!")
                print("✓ SUCCESS: Decryption matches original!")
            else:
                print("✗ ОШИБКА: Расшифровка не совпадает!")
                print("✗ ERROR: Decryption mismatch!")
            print_separator()
            sys.stdout.flush()  # Ensure all output is displayed
    
    elif task == 1:
        # Statistical analysis mode
        run_statistical_analysis(key, key_size_bits, mode_name, num_rounds, data_size_kb)


def main():
    """Main interactive program."""
    global comm, rank
    size = comm.Get_size()
    
    # Check if command-line arguments are provided
    if len(sys.argv) > 1:
        # Command-line mode
        main_cmdline(sys.argv[1:])
        return
    
    # Interactive mode (original behavior)
    # Only master process handles user interaction
    if rank == 0:
        print_header()
        
        if size > 1:
            print(f"ℹ MPI: Запущено {size} процессов / Running with {size} processes")
            print()
        
        # Get user inputs
        text = get_text_input()
        key, key_source = get_key_choice()
        num_rounds = get_rounds()
        mode = get_mode()
        
        # Display key
        display_key(key, key_source)
        
        print()
        print("⏳ Выполняется шифрование / Encrypting...")
    else:
        # Non-master processes wait
        text = None
        key = None
        num_rounds = None
        mode = None
    
    # Broadcast parameters to all processes
    key = comm.bcast(key, root=0)
    num_rounds = comm.bcast(num_rounds, root=0)
    mode = comm.bcast(mode, root=0)
    
    # Execute encryption based on mode
    block_size = 16  # Standard block size
    
    # Map modes to encryption functions
    mode_functions = {
        "ECB": encrypt_ecb_mode,
        "CBC": encrypt_cbc_mode,
        "CFB": encrypt_cfb_mode,
        "OFB": encrypt_ofb_mode,
        "CTR": encrypt_ctr_mode,
        "WBC-CTR-HMAC": encrypt_wbc_ctr_hmac_mode
    }
    
    if mode in mode_functions:
        # Sequential modes
        if rank == 0:
            plaintext = text.encode('utf-8')
            try:
                decrypted, enc_time, dec_time = mode_functions[mode](plaintext, key, block_size, num_rounds)
                display_results(text, decrypted, enc_time, dec_time, mode)
            except Exception as e:
                print(f"\n✗ Ошибка шифрования / Encryption error: {e}")
                import traceback
                traceback.print_exc()
    elif mode == "Parallel":
        # Parallel MPI mode
        if rank == 0:
            plaintext = text.encode('utf-8')
        else:
            plaintext = None
        
        decrypted, enc_time, dec_time = encrypt_parallel_mode(plaintext, key, block_size, num_rounds)
        
        if rank == 0:
            display_results(text, decrypted, enc_time, dec_time, f"{mode} ({size} процессов/processes)")
    else:
        if rank == 0:
            print(f"\n✗ Неизвестный режим / Unknown mode: {mode}")
    
    if rank == 0:
        print()
        print("✓ Программа завершена / Program completed")
        print()


if __name__ == "__main__":
    try:
        import numpy as np
        main()
    except KeyboardInterrupt:
        print("\n\n⚠ Программа прервана пользователем / Program interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Ошибка / Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
