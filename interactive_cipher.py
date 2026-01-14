#!/usr/bin/env python3
"""
Interactive WBC1 Cipher - User-friendly interface with multiple modes
Интерактивная версия шифра WBC1 с пользовательским интерфейсом
"""

import sys
import time
import secrets
import hashlib
from typing import Tuple, Optional
from mpi4py import MPI
from wbc1_parallel import ParallelWBC1, WBC1Cipher


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
    return text


def get_key_choice() -> Tuple[bytes, str]:
    """Get encryption key from user or generate automatically."""
    print()
    print("2. ВЫБОР КЛЮЧА ШИФРОВАНИЯ")
    print("   Encryption key selection:")
    print()
    print("   1) Ввести свой ключ (Enter custom key)")
    print("   2) Сгенерировать автоматически (Generate automatically)")
    print()
    
    choice = input("   Ваш выбор (1/2): ").strip()
    
    if choice == "1":
        key_str = input("   Введите ключ: ")
        key = key_str.encode('utf-8')
        key_source = "пользовательский (user-provided)"
    else:
        print()
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
        
        if length_choice == "1":
            length = 16
        elif length_choice == "2":
            length = 24
        elif length_choice == "3":
            length = 32
        else:
            try:
                length = int(input("   Введите длину ключа в байтах: "))
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
    print()
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
            return max(1, rounds)
        except ValueError:
            print("   ⚠ Некорректный ввод, используется 16 раундов")
            return 16


def get_mode() -> str:
    """Get encryption mode."""
    print()
    print("5. РЕЖИМ ШИФРОВАНИЯ")
    print("   Encryption mode:")
    print()
    print("   1) ECB (Electronic Codebook) - базовый режим")
    print("   2) Параллельный (Parallel) - распределённое шифрование")
    print()
    
    choice = input("   Ваш выбор (1-2): ").strip()
    
    if choice == "1":
        return "ECB"
    else:
        return "Parallel"


def encrypt_ecb_mode(plaintext: bytes, key: bytes, block_size: int, num_rounds: int) -> Tuple[bytes, float, float]:
    """Encrypt using ECB mode (sequential block processing)."""
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
    
    if mode == "ECB":
        if rank == 0:
            plaintext = text.encode('utf-8')
            decrypted, enc_time, dec_time = encrypt_ecb_mode(plaintext, key, block_size, num_rounds)
            display_results(text, decrypted, enc_time, dec_time, mode)
    else:  # Parallel mode
        if rank == 0:
            plaintext = text.encode('utf-8')
        else:
            plaintext = None
        
        decrypted, enc_time, dec_time = encrypt_parallel_mode(plaintext, key, block_size, num_rounds)
        
        if rank == 0:
            display_results(text, decrypted, enc_time, dec_time, f"{mode} ({size} процессов/processes)")
    
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
