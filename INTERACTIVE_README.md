# Интерактивный шифр WBC1 / Interactive WBC1 Cipher

Интерактивная версия параллельного шифра WBC1 с удобным пользовательским интерфейсом.

Interactive version of the parallel WBC1 cipher with user-friendly interface.

## Возможности / Features

1. **Интерактивный ввод текста** / Interactive text input
2. **Выбор ключа** / Key selection:
   - Пользовательский ключ / User-provided key
   - Автоматическая генерация / Automatic generation
3. **Выбор длины ключа** / Key length selection (16, 24, 32 bytes or custom)
4. **Количество раундов** / Number of rounds (10, 16, 20, 32 or custom)
5. **Режимы шифрования** / Encryption modes:
   - ECB (Electronic Codebook) - последовательный / sequential
   - Parallel - параллельный с MPI / parallel with MPI
6. **Отображение ключа** / Key display (always shown)
7. **Расшифрованный текст** / Decrypted text (always shown)
8. **Измерение времени** / Timing measurements (encryption & decryption)

## Использование / Usage

### Режим ECB / ECB Mode

```bash
python3 interactive_cipher.py
```

### Параллельный режим / Parallel Mode

```bash
# С 2 процессами / With 2 processes
mpiexec --allow-run-as-root --oversubscribe -n 2 python3 interactive_cipher.py

# С 4 процессами / With 4 processes
mpiexec --allow-run-as-root --oversubscribe -n 4 python3 interactive_cipher.py
```

## Примеры диалога / Example Interactions

### Пример 1: Автоматический ключ, ECB режим

```
1. ВВОД ТЕКСТА ДЛЯ ШИФРОВАНИЯ
   Введите текст: Hello World!

2. ВЫБОР КЛЮЧА ШИФРОВАНИЯ
   Ваш выбор (1/2): 2

3. ДЛИНА КЛЮЧА
   Ваш выбор (1-4): 2  # 24 байта

4. КОЛИЧЕСТВО РАУНДОВ ШИФРОВАНИЯ
   Ваш выбор (1-5): 2  # 16 раундов

5. РЕЖИМ ШИФРОВАНИЯ
   Ваш выбор (1-2): 1  # ECB
```

### Пример 2: Пользовательский ключ, параллельный режим

```
1. ВВОД ТЕКСТА ДЛЯ ШИФРОВАНИЯ
   Введите текст: Secret message

2. ВЫБОР КЛЮЧА ШИФРОВАНИЯ
   Ваш выбор (1/2): 1
   Введите ключ: MyPassword123

4. КОЛИЧЕСТВО РАУНДОВ ШИФРОВАНИЯ
   Ваш выбор (1-5): 3  # 20 раундов

5. РЕЖИМ ШИФРОВАНИЯ
   Ваш выбор (1-2): 2  # Параллельный
```

## Что показывается / What is Displayed

### Всегда выводится / Always Shown:

1. **Используемый ключ** / Encryption key:
   - Источник (пользовательский или сгенерирован) / Source
   - Длина в байтах / Length in bytes
   - Hex представление / Hex representation
   - UTF-8 (если возможно) / UTF-8 (if possible)

2. **Результаты** / Results:
   - Исходный текст / Original text
   - Расшифрованный текст / Decrypted text
   - Статус проверки / Verification status

3. **Время выполнения** / Execution time:
   - Время шифрования / Encryption time
   - Время расшифрования / Decryption time
   - Общее время / Total time

## Безопасность / Security

⚠️ **Внимание / Warning:**
- Программа для образовательных целей / Educational purposes
- Всегда отображает ключи / Always displays keys
- Используйте безопасные каналы / Use secure channels

## Сравнение с оригиналом / Comparison with Original

| Функция / Feature | Оригинал / Original | Interactive |
|-------------------|---------------------|-------------|
| Интерактивный ввод / Interactive input | ❌ | ✅ |
| Выбор ключа / Key choice | ❌ | ✅ |
| Длина ключа / Key length | Фиксированная / Fixed | Настраиваемая / Configurable |
| Количество раундов / Rounds | Фиксированное / Fixed | Настраиваемое / Configurable |
| Режимы / Modes | ECB | ECB, Parallel |
| Отображение ключа / Key display | ❌ | ✅ |
| Измерение времени / Timing | Частично / Partial | Полное / Complete |
| Язык интерфейса / UI language | Английский / English | Двуязычный / Bilingual |

## Технические детали / Technical Details

- **Язык / Language:** Python 3.6+
- **Зависимости / Dependencies:** numpy, mpi4py
- **Размер блока / Block size:** 16 байт / bytes (фиксированный / fixed)
- **Padding:** PKCS7
- **Генерация ключей / Key generation:** Криптографически безопасная / Cryptographically secure (secrets module)

## Файлы / Files

- `interactive_cipher.py` - Основная программа / Main program
- `INTERACTIVE_README.md` - Эта документация / This documentation

## Использованные библиотеки / Libraries Used

- **wbc1_parallel.py** - Оригинальная реализация WBC1 / Original WBC1 implementation
- **numpy** - Численные операции / Numerical operations
- **mpi4py** - Параллельные вычисления / Parallel computing
- **secrets** - Криптографически безопасная генерация / Cryptographically secure generation
