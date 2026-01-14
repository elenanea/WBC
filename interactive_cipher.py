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
from typing import Tuple, Optional
from mpi4py import MPI
from wbc1_parallel import ParallelWBC1, WBC1Cipher
import numpy as np


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


def encrypt_parallel_mode(plaintext: bytes, key: bytes, block_size: int, num_rounds: int) -> Tuple[Optional[bytes], float, float]:
    """Encrypt using parallel MPI mode."""
    comm = MPI.COMM_WORLD
    rank = comm.Get_rank()
    
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


def main():
    """Main interactive program."""
    comm = MPI.COMM_WORLD
    rank = comm.Get_rank()
    size = comm.Get_size()
    
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
