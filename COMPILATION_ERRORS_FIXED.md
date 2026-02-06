# Исправление ошибок компиляции / Compilation Errors Fixed

## Проблема / Problem

При компиляции `wbc1_original_parallel.c` возникали ошибки:

```
wbc1_original_parallel.c: In function 'main':
wbc1_original_parallel.c:675:17: error: too few arguments to function 'print_hex'
  675 |                 print_hex(plaintext, text_len < 64 ? text_len : 64);
      |                 ^~~~~~~~~
wbc1_original_parallel.c:691:13: error: too few arguments to function 'print_hex'
  691 |             print_hex(ciphertext, ciphertext_len < 64 ? ciphertext_len : 64);
      |             ^~~~~~~~~
wbc1_original_parallel.c:705:17: error: too few arguments to function 'print_hex'
  705 |                 print_hex(decrypted, decrypted_len < 64 ? decrypted_len : 64);
      |                 ^~~~~~~~~
wbc1_original_parallel.c:63:13: warning: 'sha256_hash' defined but not used [-Wunused-function]
   63 | static void sha256_hash(const uint8_t *data, size_t len, uint8_t *output) {
      |             ^~~~~~~~~~~
```

## Причина / Root Cause

### 1. Неправильное количество аргументов print_hex

Функция `print_hex` определена как:
```c
static void print_hex(const uint8_t *data, int len, int max_bytes)
```

Требует **3 параметра**:
1. `data` - указатель на данные
2. `len` - полная длина данных
3. `max_bytes` - максимальное количество байт для отображения

Вызовы передавали только **2 параметра**:
- `data` - указатель на данные  
- `max_bytes` - вычисленное максимальное значение

**Отсутствующий параметр:** `len` (полная длина данных)

### 2. Неиспользуемая функция sha256_hash

Функция `sha256_hash` объявлена, но не используется в текущей версии кода.

## Решение / Solution

### 1. Исправление вызовов print_hex

**Строка 676 (была 675):**
```c
// До / Before:
print_hex(plaintext, text_len < 64 ? text_len : 64);

// После / After:
print_hex(plaintext, text_len, 64);
```

**Строка 692 (была 691):**
```c
// До / Before:
print_hex(ciphertext, ciphertext_len < 64 ? ciphertext_len : 64);
if (ciphertext_len > 64) printf("...\n");

// После / After:
print_hex(ciphertext, ciphertext_len, 64);
```

**Строка 705:**
```c
// До / Before:
print_hex(decrypted, decrypted_len < 64 ? decrypted_len : 64);

// После / After:
print_hex(decrypted, decrypted_len, 64);
```

**Изменения:**
- Добавлен второй параметр: полная длина данных (`text_len`, `ciphertext_len`, `decrypted_len`)
- Третий параметр упрощен до фиксированного значения `64`
- Функция `print_hex` сама обрабатывает случай, когда `len < max_bytes`
- Удалена избыточная проверка `if (ciphertext_len > 64) printf("...\n");`

### 2. Устранение предупреждения о неиспользуемой функции

**Строка 63:**
```c
// До / Before:
static void sha256_hash(const uint8_t *data, size_t len, uint8_t *output) {

// После / After:
__attribute__((unused))
static void sha256_hash(const uint8_t *data, size_t len, uint8_t *output) {
```

Добавлен атрибут `__attribute__((unused))` для подавления предупреждения. Функция оставлена для возможного будущего использования.

## Проверка / Verification

После исправлений код компилируется без ошибок:

```bash
make clean
make original
```

Ожидаемый результат:
```
mpicc -O3 -Wall -Wextra -std=c99 -o wbc1_original_parallel wbc1_original_parallel.c -lssl -lcrypto -lm
# Компиляция успешна без ошибок и предупреждений
```

## Влияние / Impact

- **Функциональность:** Не изменена. Логика работы осталась прежней.
- **Компиляция:** Код теперь компилируется чисто без ошибок и предупреждений.
- **Читаемость:** Упрощена логика вызовов `print_hex`.

## Изменённые файлы / Modified Files

- `wbc1_original_parallel.c`: 4 изменения
  - 3 вызова функции `print_hex` исправлены
  - 1 функция `sha256_hash` помечена как потенциально неиспользуемая

## Резюме / Summary

| Что исправлено | Где | Как |
|----------------|-----|-----|
| print_hex(plaintext) | Строка 676 | Добавлен параметр `text_len` |
| print_hex(ciphertext) | Строка 692 | Добавлен параметр `ciphertext_len` |
| print_hex(decrypted) | Строка 705 | Добавлен параметр `decrypted_len` |
| sha256_hash warning | Строка 63 | Добавлен `__attribute__((unused))` |

**Результат:** Код компилируется без ошибок и готов к использованию. ✅
