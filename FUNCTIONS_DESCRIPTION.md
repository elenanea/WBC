# Описание функций WBC (C/CUDA)

## Назначение комплекса программ

Комплекс програм реалізує паралельні симетричні блочні криптографічні алгоритми PWBC1, PWBC1.1, PWBC2, PWBC2.1 та PWBCCuda, які є паралельними модифікаціями послідовних алгоритмів WBC1 і WBC2.

Призначення комплексу — шифрування та дешифрування блоків даних у багатопроцесному (MPI) і GPU-орієнтованому (CUDA) середовищах із підтримкою статистичного аналізу стійкості.

В основі алгоритмів — динамічна ключозалежна таблиця з 127 унікальних операцій (комбіновані кубічні повороти, ротування зрізів і патерни), яка генерується з ключа.

Документ содержит краткое назначение функций в файлах:
- `wbc0_original_parallel.c`
- `wbc1_original_parallel.c`
- `wbc2_original_parallel.c`
- `wbc1_parallel_cached.c`
- `wbc0_original_parallel_cuda.cu`

Формат параметров в описании ниже:
- `in` — входной аргумент
- `out` — выходной аргумент (результат пишется по указателю)
- `in/out` — аргумент модифицируется функцией

## Перед початком роботи з програмою

Перед початком роботи з програмою переконайтеся, що на вашому комп'ютері встановлено необхідні бібліотеки.

Обов'язкові залежності для C/MPI-реалізацій:
- MPI: `openmpi-bin`, `libopenmpi-dev` (або сумісний MPICH).
- OpenSSL: `libssl-dev` (заголовки `openssl/evp.h`, `openssl/sha.h`).
- Базові інструменти збірки: `build-essential` (gcc, make).

Обов'язкові залежності для Python-частини:
- `numpy>=1.19.0`
- `mpi4py>=3.0.0`

Опційно для CUDA-версії (`wbc0_original_parallel_cuda.cu`):
- CUDA Toolkit (`nvcc`), наприклад пакет `nvidia-cuda-toolkit`.

Що потрібно прописати (Ubuntu/Debian):

```bash
sudo apt-get update
sudo apt-get install -y build-essential openmpi-bin libopenmpi-dev libssl-dev
python3 -m pip install -r requirements.txt
```

Для CUDA-варіанту додатково:

```bash
sudo apt-get install -y nvidia-cuda-toolkit
```

Під час компіляції потрібно лінкувати бібліотеки:
- `-lssl -lcrypto -lm` (вже прописано в `Makefile` у `LDFLAGS`).
- Для CUDA-таргета також `-lmpi` (вже прописано в `Makefile` для `wbc0-cuda`).

---

## Характеристика програми

### `wbc0_original_parallel`

- **Тип реалізації:** базова MPI-реалізація PWBC1 (оригінальна паралельна схема WBC0).
- **Криптографічне ядро:** 127 ключозалежних операцій, каскадна обробка підблоків, циклічні побітові зсуви.
- **Паралелізація:** `MPI_Scatterv`/`MPI_Gatherv` для розподілу блоків між процесами.
- **Сильні сторони:** добра масштабованість на CPU-кластерах, детермінована генерація таблиць із ключа.
- **Обмеження:** без GPU-прискорення; продуктивність залежить від мережевих витрат MPI.
- **Типове застосування:** порівняльні тести, багатопроцесне шифрування великих масивів даних на CPU.

### `wbc1_original_parallel`

- **Тип реалізації:** MPI-реалізація оригінального WBC1.
- **Криптографічне ядро:** таблиця операцій, ключозалежний вибір `op_id`, блокові прямі/зворотні перетворення.
- **Паралелізація:** поблочний розподіл навантаження між MPI-процесами.
- **Сильні сторони:** простіша структура раундів порівняно з розширеними версіями, зручна для верифікації коректності.
- **Обмеження:** нижча швидкодія порівняно з кешованими/оптимізованими реалізаціями.
- **Типове застосування:** базова еталонна реалізація для перевірки сумісності та регресійних тестів.

### `wbc2_original_parallel`

- **Тип реалізації:** MPI-реалізація оригінального WBC2.
- **Криптографічне ядро:** ключозалежні `S-box`/`inv_sbox`, раундові ключі, шари дифузії та інверсні перетворення.
- **Паралелізація:** блокова MPI-обробка із збиранням результату на root-процесі.
- **Сильні сторони:** посилене нелінійне перетворення за рахунок S-box і дифузійних шарів.
- **Обмеження:** вища обчислювальна складність і більші накладні витрати на раунд.
- **Типове застосування:** сценарії, де пріоритет на криптостійкість і статистичні властивості шифртексту.

### `wbc1_parallel_cached`

- **Тип реалізації:** оптимізована MPI-реалізація WBC1 із кешуванням операцій.
- **Криптографічне ядро:** попередньо обчислені кеші прямих/обернених перестановок, S-box, round keys, `cumulative_xor`.
- **Паралелізація:** MPI-розподіл блоків плюс локальне прискорення за рахунок `precompute_operation_cache`.
- **Сильні сторони:** краща продуктивність на CPU порівняно з оригінальним WBC1, стабільний час застосування операцій.
- **Обмеження:** додаткові витрати пам'яті на кеш та ініціалізацію стану перед шифруванням.
- **Типове застосування:** практичне високошвидкісне шифрування/дешифрування великих буферів у MPI-середовищі.

### `wbc1_original_parallel_cuda`

- **Відповідний файл у репозиторії:** `wbc0_original_parallel_cuda.cu`.
- **Тип реалізації:** гібридна MPI + CUDA-реалізація (із CPU fallback).
- **Криптографічне ядро:** сумісне з WBC0/PWBC1-пайплайном, з GPU-прискоренням обраних етапів (зокрема бітових зсувів).
- **Паралелізація:** міжвузлова через MPI, внутрішньовузлова через CUDA-ядра.
- **Сильні сторони:** потенційно найвища пропускна здатність за наявності сумісного GPU.
- **Обмеження:** залежність від CUDA-драйверів/Toolkit; за відсутності GPU працює у CPU fallback-режимі.
- **Типове застосування:** змішані HPC-середовища, де потрібно максимально прискорити обробку блоків.

---

## 1) wbc0_original_parallel.c

- `sha256_hash` — вычисляет SHA-256 для входного буфера.
- `mt_init_seed` — инициализирует состояние генератора MT19937.
- `mt_generate` — генерирует следующий набор значений MT19937.
- `mt_random_init` — возвращает одно псевдослучайное значение MT19937.
- `get_key_bit` — получает бит ключа по индексу (с циклическим доступом).
- `get_shift_bitmap` — получает/строит кеш карт соответствия битов для сдвига.
- `cyclic_bitwise_shift` — выполняет циклический побитовый сдвиг блока.
- `init_operations` — строит таблицы базовых и итоговых операций (127 ops).
- `min_int` — возвращает минимум двух целых.
- `rotl8` — циклический сдвиг байта влево.
- `rotr8` — циклический сдвиг байта вправо.
- `gcd_int` — вычисляет НОД двух чисел.
- `mod_inverse` — находит мультипликативный обратный по модулю.
- `hash_operation_seed` — строит детерминированный seed для операции.
- `parse_turn_value` — парсит параметр поворота (`'`, `2`, `3`, etc.).
- `op_param_cache_index` — индексирует кеш параметров операции.
- `get_cached_op_params` — получает/вычисляет кешированные параметры базовой операции.
- `rotate_block_bytes` — циклически сдвигает байты блока.
- `apply_affine_permutation` — применяет аффинную перестановку байтов.
- `apply_swap_style` — применяет swap-стиль перестановки.
- `apply_diagflip_style` — применяет реверс/diagflip перестановку.
- `apply_base_operation_permutation` — применяет базовую операцию (и её инверсию).
- `apply_operation_sized` — применяет составную операцию для заданного размера подблока.
- `wbc1_original_init` — инициализирует состояние шифра (ключ, размеры, операции).
- `wbc1_original_free` — освобождает ресурсы шифра.
- `mix_key_byte` — перемешивает байт ключа для выбора операции.
- `expand_round_key_byte` — локально расширяет байт раундового ключа.
- `build_round_schedule` — строит расписание (`op_id`, `shift`) на раунд.
- `process_subblock_with_key` — обрабатывает один подблок (encrypt/decrypt).
- `get_subblock_size` — вычисляет размер подблока (с учётом override).
- `derive_round_key_from_subblock_bits` — формирует каскадный ключ из шифроподблока.
- `wbc1_original_encrypt_block` — шифрует один блок WBC0.
- `wbc1_original_decrypt_block` — дешифрует один блок WBC0.
- `parallel_original_encrypt` — MPI-шифрование массива блоков (Scatterv/Gatherv).
- `parallel_original_decrypt` — MPI-дешифрование массива блоков.
- `generate_random_bytes` — генерирует буфер случайных байтов.
- `shannon_entropy` — считает энтропию Шеннона.
- `frequency_test` — частотный/chi-square тест.
- `avalanche_test` — тест лавинного эффекта.
- `correlation_test` — тест корреляции plaintext/ciphertext.
- `differential_test` — тест чувствительности к изменению ключа.
- `print_hex` — печать данных в hex-формате.
- `print_key_hex` — печать ключа в hex.
- `print_key_operation_mapping` — печать соответствия «ключ → операция».
- `print_operations_table` — печать таблиц операций.
- `main` — CLI, выбор задачи, запуск тестов/шифрования.

### Переменные (параметры вызова) для `wbc0_original_parallel.c`

- `cipher` (`in/out`) — структура состояния шифра (`key`, размеры, таблицы операций).
- `key`, `key_len`, `key_len_bytes` (`in`) — мастер-ключ и его длина.
- `block`, `size`, `size_bytes`, `block_size_bits`, `block_size_bytes` (`in/out`) — буфер блока и его размеры.
- `subblock_size`, `subblock_size_bytes` (`in`) — размер подблока для шагов каскадного шифрования.
- `shift`, `shift_bits`, `total_bits` (`in`) — параметры циклического сдвига.
- `op`, `op_id`, `base_idx`, `inverse` (`in`) — идентификация операции и режим (encrypt/decrypt).
- `round_key`, `round_key_len`, `current_key`, `current_key_len` (`in/out`) — текущий раундовый/каскадный ключ.
- `op_ids`, `shifts` (`out`) — расписание операций и сдвигов на проход по ключу.
- `plaintext`, `ciphertext`, `plaintext_len`, `ciphertext_len` (`in/out`) — вход/выход блочных MPI-процедур.
- `data`, `len`, `mean`, `std`, `chi_square`, `results` (`in/out`) — аргументы статистических тестов.
- `rank`, `size` (`in`) — параметры MPI-процесса.
- `argc`, `argv` (`in`) — CLI-аргументы программы.

---

## 2) wbc1_original_parallel.c

- `sha256_hash` — вычисляет SHA-256.
- `mt_init_seed` — инициализация MT19937.
- `mt_generate` — генерация следующего состояния MT.
- `mt_random_init` — выдаёт одно число MT.
- `get_key_bit` — получение бита ключа.
- `cyclic_bitwise_shift` — циклический побитовый сдвиг блока.
- `init_operations` — инициализация таблиц операций.
- `apply_operation` — применяет операцию/цепочку операций к блоку.
- `wbc1_original_init` — инициализация шифра WBC1.
- `wbc1_original_free` — освобождение ресурсов.
- `mix_key_byte` — перемешивание байта ключа.
- `wbc1_original_encrypt_block` — шифрование блока WBC1.
- `wbc1_original_decrypt_block` — дешифрование блока WBC1.
- `parallel_original_encrypt` — MPI-шифрование.
- `parallel_original_decrypt` — MPI-дешифрование.
- `generate_random_bytes` — генерация тестовых данных.
- `shannon_entropy` — энтропийный тест.
- `frequency_test` — частотный тест.
- `avalanche_test` — лавинный тест.
- `correlation_test` — корреляционный тест.
- `differential_test` — дифференциальный тест по ключу.
- `print_hex` — печать hex.
- `print_key_hex` — печать ключа.
- `print_key_operation_mapping` — печать mapping ключа на операции.
- `print_operations_table` — печать таблиц операций.
- `main` — точка входа, режимы task 0/1/2.

### Переменные (параметры вызова) для `wbc1_original_parallel.c`

- `cipher` (`in/out`) — состояние WBC1 (ключ, операции, размеры блока).
- `key`, `key_len` (`in`) — ключ и длина ключа.
- `block`, `size_bytes`, `shift_bits` (`in/out`) — данные для циклического сдвига.
- `op_id`, `inverse` (`in`) — выбор операции и направление применения.
- `plaintext`, `ciphertext`, `plaintext_len`, `ciphertext_len` (`in/out`) — буферы/длины для MPI-шифрования.
- `data`, `len` (`in`) — входы статистических тестов.
- `num_tests`, `results` (`in/out`) — число итераций и буфер результатов тестов.
- `rank`, `size` (`in`) — MPI-контекст.
- `argc`, `argv` (`in`) — параметры командной строки.

---

## 3) wbc2_original_parallel.c

- `sha256_hash` — вычисляет SHA-256.
- `mt_init_seed` — инициализация MT19937.
- `mt_generate` — обновление состояния MT.
- `mt_random_init` — генерация псевдослучайного значения MT.
- `generate_sbox` — строит ключезависимую S-box.
- `generate_round_keys` — генерирует раундовые ключи.
- `apply_sbox` — применяет S-box к блоку.
- `apply_inv_sbox` — применяет обратную S-box.
- `xor_round_key` — XOR блока с раундовым ключом.
- `diffusion_layer1` — 1-й слой диффузии.
- `diffusion_layer2` — 2-й слой диффузии.
- `apply_diffusion` — полная диффузия (композиция слоёв).
- `inverse_diffusion_layer1` — обратный 1-й слой диффузии.
- `apply_inverse_diffusion` — обратная полная диффузия.
- `get_key_bit` — получение бита ключа.
- `cyclic_bitwise_shift` — циклический побитовый сдвиг.
- `init_operations` — инициализация таблицы операций.
- `apply_operation` — применение рубиковой операции.
- `wbc2_original_init` — инициализация WBC2 (включая S-box/round keys).
- `wbc2_original_free` — освобождение ресурсов WBC2.
- `mix_key_byte` — перемешивание байта для выбора операции.
- `wbc2_original_encrypt_block` — шифрование блока WBC2.
- `wbc2_original_decrypt_block` — дешифрование блока WBC2.
- `parallel_original_encrypt` — MPI-шифрование.
- `parallel_original_decrypt` — MPI-дешифрование.
- `generate_random_bytes` — генерация тестового массива.
- `shannon_entropy` — энтропийный тест.
- `frequency_test` — частотный тест.
- `avalanche_test` — тест лавинного эффекта.
- `correlation_test` — корреляционный тест.
- `differential_test` — тест чувствительности к ключу.
- `print_hex` — печать буфера в hex.
- `print_key_hex` — печать ключа.
- `print_key_operation_mapping` — печать соответствий ключ/операции.
- `print_operations_table` — печать операций.
- `main` — CLI, режимы task и число раундов.

### Переменные (параметры вызова) для `wbc2_original_parallel.c`

- `cipher` (`in/out`) — состояние WBC2 (включая `sbox`, `inv_sbox`, `round_keys`, `num_rounds`).
- `key`, `key_len` (`in`) — мастер-ключ и его длина.
- `sbox[256]`, `inv_sbox[256]` (`out`) — таблицы прямой/обратной подстановки.
- `round_key` (`in`) — текущий раундовый ключ для XOR.
- `block`, `block_size_bytes` (`in/out`) — блок и размер блока в байтах.
- `op_id`, `inverse` (`in`) — код операции и направление (прямое/обратное).
- `plaintext`, `ciphertext`, `*_len` (`in/out`) — буферы и длины для MPI-обработки.
- `num_rounds` (`in`) — количество раундов WBC2.
- `num_tests`, `results` (`in/out`) — параметры статистических тестов.
- `rank`, `size` (`in`) — параметры MPI-процесса.
- `argc`, `argv` (`in`) — аргументы CLI.

---

## 4) wbc0_original_parallel_cuda.cu

- `sha256_hash` — вычисляет SHA-256.
- `mt_init_seed` — инициализирует MT19937.
- `mt_generate` — генерирует очередную пачку MT.
- `mt_random_init` — возвращает одно число MT.
- `get_key_bit` — получает бит ключа.
- `cuda_is_available` — проверяет доступность CUDA-устройства.
- `print_cuda_runtime_status_once` — печатает статус CUDA/CPU fallback.
- `cyclic_bitwise_shift_kernel` — CUDA-ядро циклического побитового сдвига.
- `get_shift_bitmap` — получает/строит кеш карты битовых индексов для сдвига.
- `cyclic_bitwise_shift` — гибридная реализация сдвига (CUDA + CPU fallback).
- `init_operations` — инициализация таблиц операций.
- `min_int` — минимум двух целых.
- `rotl8` — rotate-left для байта.
- `rotr8` — rotate-right для байта.
- `gcd_int` — НОД.
- `mod_inverse` — обратный элемент по модулю.
- `hash_operation_seed` — seed для операции.
- `parse_turn_value` — парсинг параметра поворота.
- `op_param_cache_index` — индекс кеша параметров операции.
- `get_cached_op_params` — получает/вычисляет кеш параметров операции.
- `rotate_block_bytes` — циклический сдвиг байтов.
- `apply_affine_permutation` — аффинная перестановка.
- `apply_swap_style` — swap-перестановка.
- `apply_diagflip_style` — diagflip/реверс.
- `apply_base_operation_permutation` — базовая операция и её инверсия.
- `apply_operation_sized` — применение операции на подблоке.
- `wbc1_original_init` — инициализация шифра.
- `wbc1_original_free` — освобождение ресурсов.
- `mix_key_byte` — перемешивание байта ключа.
- `expand_round_key_byte` — расширение байта ключа.
- `build_round_schedule` — подготовка `op_id`/`shift`.
- `process_subblock_with_key` — обработка подблока.
- `get_subblock_size` — вычисление размера подблока.
- `derive_round_key_from_subblock_bits` — каскадный ключ из шифроподблока.
- `wbc1_original_encrypt_block` — шифрование блока.
- `wbc1_original_decrypt_block` — дешифрование блока.
- `parallel_original_encrypt` — MPI-шифрование блоков.
- `parallel_original_decrypt` — MPI-дешифрование блоков.
- `generate_random_bytes` — генерация случайных данных.
- `shannon_entropy` — энтропия.
- `frequency_test` — частотный тест.
- `avalanche_test` — лавинный тест.
- `correlation_test` — корреляционный тест.
- `differential_test` — дифференциальный тест.
- `print_hex` — печать hex-буфера.
- `print_key_hex` — печать ключа.
- `print_key_operation_mapping` — печать mapping ключа.
- `print_operations_table` — печать таблиц операций.
- `main` — CLI и запуск CUDA/CPU вариантов задач.

### Переменные (параметры вызова) для `wbc0_original_parallel_cuda.cu`

- `rank` (`in`) — MPI rank, используется для вывода CUDA-статуса только на root.
- `temp`, `block` (`in/out`) — входной и выходной буферы сдвига (host/device).
- `src_byte`, `src_mask`, `dst_byte`, `dst_mask` (`in`) — карты битовых индексов/масок для kernel.
- `total_bits`, `size_bytes`, `shift_bits` (`in`) — размеры и сдвиг для CUDA/CPU реализации.
- `d_temp`, `d_block`, `d_src_*`, `d_dst_*` (`in/out`) — device-буферы в CUDA-ветке.
- `ok`, `err` (`in/out`) — коды ошибок CUDA (`cudaError_t`).
- `cipher`, `key`, `round_key`, `op_id`, `inverse` — те же смысловые параметры, что и в WBC0 CPU-версии.
- `plaintext`, `ciphertext`, `*_len`, `results` — параметры MPI-обработки и статистических тестов.
- `argc`, `argv` (`in`) — аргументы CLI.

---

## 5) wbc1_parallel_cached.c

- `mt_init` — инициализация состояния MT19937 (основной PRNG).
- `mt_random` — генерация следующего псевдослучайного значения MT19937.
- `rotate_right` — циклический сдвиг байта вправо.
- `rotate_left` — циклический сдвиг байта влево.
- `sha256_hash` — вычисляет SHA-256.
- `mt_init_seed` — инициализация MT19937 для генерации таблицы операций.
- `mt_generate` — генерация следующего состояния MT19937 init-генератора.
- `mt_random_init` — выдача псевдослучайного значения init-генератора.
- `init_operations` — построение 127 ключезависимых операций.
- `generate_sbox` — генерация ключезависимой S-box.
- `generate_inverse_sbox` — генерация обратной S-box.
- `generate_permutation` — генерация перестановки бит/байт для блока.
- `generate_inverse_permutation` — генерация обратной перестановки.
- `generate_round_keys` — генерация раундовых ключей.
- `precompute_operation_cache` — предвычисление кеша прямых/обратных перестановок операций.
- `apply_operation_cached` — применение операции через предвычисленный кеш.
- `substitute_bytes` — прямое/обратное S-box преобразование блока.
- `xor_with_key` — XOR блока с ключом.
- `cumulative_xor` — накопительное XOR-диффузионное преобразование.
- `cyclic_bitwise_rotate` — циклическое побитовое вращение блока.
- `wbc1_init` — ініціалізація структури стану шифру WBC1 (таблиці, ключі, кеш).
- `wbc1_free` — звільнення ресурсів структури стану шифру.
- `wbc1_encrypt_block` — шифрование одного блока.
- `wbc1_decrypt_block` — дешифрование одного блока.
- `pad_data` — добавление PKCS#7 padding.
- `unpad_data` — удаление и проверка PKCS#7 padding.
- `parallel_encrypt` — параллельное MPI-шифрование данных.
- `parallel_decrypt` — параллельное MPI-дешифрование данных.
- `shannon_entropy` — расчёт энтропии Шеннона.
- `avalanche_test` — оценка лавинного эффекта.
- `frequency_test` — частотный (chi-square) тест.
- `correlation_test` — тест корреляции между наборами данных.
- `main` — CLI, выбор режима, запуск шифрования/тестов.

### Переменные (параметры вызова) для `wbc1_parallel_cached.c`

- `cipher` (`in/out`) — состояние шифра (`sbox`, `inv_sbox`, `perm`, `inv_perm`, `round_keys`, кеш операций, `num_rounds`, `algorithm_mode`).
- `key`, `key_len` (`in`) — мастер-ключ и длина ключа.
- `block`, `size`, `op_id`, `inverse` (`in/out`) — блок данных, размер, идентификатор операции и направление преобразования.
- `plaintext`, `ciphertext`, `plaintext_len`, `ciphertext_len` (`in/out`) — вход/выход и длины для блочных и MPI-процедур.
- `padded`, `padded_len`, `unpadded`, `unpadded_len` (`out`) — буферы/длины для padding/unpadding.
- `round_key`, `round` (`in`) — параметры раундового преобразования.
- `num_tests`, `results` (`in/out`) — число тестов и выходной массив статистики.
- `mean`, `std`, `chi_square` (`out`) — агрегированные метрики частотного теста.
- `data`, `data1`, `data2`, `len` (`in`) — входы энтропийного/частотного/корреляционного тестов.
- `rank`, `size` (`in`) — MPI-контекст процесса.
- `argc`, `argv` (`in`) — аргументы командной строки.

---

## 6) Функції шифрування та дешифрування (за шаблоном)

### 6.1 `wbc0_original_parallel.c`

#### `wbc1_original_encrypt_block`
- **Призначення та умови використання:** шифрує один блок фіксованого розміру; `cipher` має бути попередньо ініціалізований.
- **Загальний вигляд функції з перемінними:** `void wbc1_original_encrypt_block(WBC1OriginalCipher *cipher, const uint8_t *plaintext, uint8_t *ciphertext)`.
- **Вхідні та вихідні дані:**
	- `cipher` (`in/out`) — структура стану шифру (ключ, таблиці операцій, параметри блока); читається і тимчасово модифікується під час раундів.
	- `plaintext` (`in`) — вхідний блок відкритого тексту довжиною `cipher->block_size_bytes`.
	- `ciphertext` (`out`) — вихідний буфер зашифрованого блока, довжина `cipher->block_size_bytes`.
- **Значення, що повертається:** не повертає (`void`), результат записується у `ciphertext`.

#### `wbc1_original_decrypt_block`
- **Призначення та умови використання:** дешифрує один блок, зашифрований тим самим ключем/параметрами.
- **Загальний вигляд функції з перемінними:** `void wbc1_original_decrypt_block(WBC1OriginalCipher *cipher, const uint8_t *ciphertext, uint8_t *plaintext)`.
- **Вхідні та вихідні дані:**
	- `cipher` (`in/out`) — структура стану шифру (має відповідати структурі стану під час шифрування).
	- `ciphertext` (`in`) — вхідний шифртекст блока довжиною `cipher->block_size_bytes`.
	- `plaintext` (`out`) — буфер для відновленого блока відкритого тексту.
- **Значення, що повертається:** не повертає (`void`), результат записується у `plaintext`.

#### `parallel_original_encrypt`
- **Призначення та умови використання:** виконує MPI-шифрування масиву блоків із padding та збіркою результату на root-процесі.
- **Загальний вигляд функції з перемінними:** `void parallel_original_encrypt(WBC1OriginalCipher *cipher, const uint8_t *plaintext, int plaintext_len, uint8_t **ciphertext, int *ciphertext_len)`.
- **Вхідні та вихідні дані:**
	- `cipher` (`in/out`) — спільна структура стану шифру на кожному MPI-процесі.
	- `plaintext` (`in`) — вхідний масив байтів (на root містить дані, на інших процесах може бути `NULL`).
	- `plaintext_len` (`in`) — довжина відкритого тексту в байтах до padding.
	- `ciphertext` (`out`) — адреса вказівника, куди на root буде записано виділений буфер шифртексту.
	- `ciphertext_len` (`out`) — адреса змінної довжини шифртексту після padding/блочного вирівнювання.
- **Значення, що повертається:** не повертає (`void`), вихід передається через `*ciphertext` і `*ciphertext_len`.

#### `parallel_original_decrypt`
- **Призначення та умови використання:** виконує MPI-дешифрування масиву блоків і видаляє PKCS#7 padding.
- **Загальний вигляд функції з перемінними:** `void parallel_original_decrypt(WBC1OriginalCipher *cipher, const uint8_t *ciphertext, int ciphertext_len, uint8_t **plaintext, int *plaintext_len)`.
- **Вхідні та вихідні дані:**
	- `cipher` (`in/out`) — структура стану шифру, ідентична до структури стану під час шифрування.
	- `ciphertext` (`in`) — вхідний шифртекст кратний розміру блока (на root), на інших процесах може бути `NULL`.
	- `ciphertext_len` (`in`) — довжина шифртексту в байтах (має бути кратною `block_size`).
	- `plaintext` (`out`) — адреса вказівника на виділений буфер розшифрованих даних.
	- `plaintext_len` (`out`) — адреса змінної, у яку записується довжина plaintext після зняття padding.
- **Значення, що повертається:** не повертає (`void`), результат повертається через `*plaintext` і `*plaintext_len`.

### 6.2 `wbc1_original_parallel.c`

#### `wbc1_original_encrypt_block`
- **Призначення та умови використання:** шифрує один блок WBC1 у локальному процесі.
- **Загальний вигляд функції з перемінними:** `void wbc1_original_encrypt_block(WBC1OriginalCipher *cipher, const uint8_t *plaintext, uint8_t *ciphertext)`.
- **Вхідні та вихідні дані:**
	- `cipher` (`in/out`) — структура стану шифру WBC1 з ініціалізованими операціями.
	- `plaintext` (`in`) — вхідний блок даних розміром `cipher->block_size_bytes`.
	- `ciphertext` (`out`) — буфер для результату шифрування такого самого розміру.
- **Значення, що повертається:** не повертає (`void`).

#### `wbc1_original_decrypt_block`
- **Призначення та умови використання:** виконує зворотне перетворення одного блока WBC1.
- **Загальний вигляд функції з перемінними:** `void wbc1_original_decrypt_block(WBC1OriginalCipher *cipher, const uint8_t *ciphertext, uint8_t *plaintext)`.
- **Вхідні та вихідні дані:**
	- `cipher` (`in/out`) — та сама структура стану шифру WBC1, що застосовувалася при шифруванні.
	- `ciphertext` (`in`) — вхідний зашифрований блок розміром `cipher->block_size_bytes`.
	- `plaintext` (`out`) — буфер для відновленого відкритого тексту блока.
- **Значення, що повертається:** не повертає (`void`).

#### `parallel_original_encrypt`
- **Призначення та умови використання:** паралельно шифрує довільний буфер через MPI з поблочним розподілом.
- **Загальний вигляд функції з перемінними:** `void parallel_original_encrypt(WBC1OriginalCipher *cipher, const uint8_t *plaintext, int plaintext_len, uint8_t **ciphertext, int *ciphertext_len)`.
- **Вхідні та вихідні дані:**
	- `cipher` (`in/out`) — структура стану шифру в кожному процесі.
	- `plaintext` (`in`) — вхідні дані на root (для інших процесів не використовується напряму).
	- `plaintext_len` (`in`) — початкова довжина вхідних даних.
	- `ciphertext` (`out`) — адреса вказівника для буфера фінального шифртексту на root.
	- `ciphertext_len` (`out`) — довжина сформованого шифртексту.
- **Значення, що повертається:** не повертає (`void`).

#### `parallel_original_decrypt`
- **Призначення та умови використання:** паралельно дешифрує блоки та формує суцільний plaintext.
- **Загальний вигляд функції з перемінними:** `void parallel_original_decrypt(WBC1OriginalCipher *cipher, const uint8_t *ciphertext, int ciphertext_len, uint8_t **plaintext, int *plaintext_len)`.
- **Вхідні та вихідні дані:**
	- `cipher` (`in/out`) — структура стану шифру WBC1 для дешифрування.
	- `ciphertext` (`in`) — зашифрований буфер (на root), що передається для scatter/gather.
	- `ciphertext_len` (`in`) — довжина шифртексту в байтах.
	- `plaintext` (`out`) — адреса вказівника на новий буфер розшифрованих даних.
	- `plaintext_len` (`out`) — фактична довжина plaintext після перевірки/зняття padding.
- **Значення, що повертається:** не повертає (`void`).

### 6.3 `wbc2_original_parallel.c`

#### `wbc2_original_encrypt_block`
- **Призначення та умови використання:** шифрує один блок WBC2 з S-box, дифузією та раундовими ключами.
- **Загальний вигляд функції з перемінними:** `void wbc2_original_encrypt_block(WBC2OriginalCipher *cipher, const uint8_t *plaintext, uint8_t *ciphertext)`.
- **Вхідні та вихідні дані:**
	- `cipher` (`in/out`) — структура стану шифру WBC2 (S-box, round keys, таблиці операцій, `num_rounds`).
	- `plaintext` (`in`) — вхідний блок довжиною `cipher->block_size_bytes`.
	- `ciphertext` (`out`) — вихідний зашифрований блок того ж розміру.
- **Значення, що повертається:** не повертає (`void`).

#### `wbc2_original_decrypt_block`
- **Призначення та умови використання:** відновлює plaintext одного блока WBC2 у зворотному порядку раундів.
- **Загальний вигляд функції з перемінними:** `void wbc2_original_decrypt_block(WBC2OriginalCipher *cipher, const uint8_t *ciphertext, uint8_t *plaintext)`.
- **Вхідні та вихідні дані:**
	- `cipher` (`in/out`) — структура стану шифру WBC2, синхронна з параметрами шифрування.
	- `ciphertext` (`in`) — вхідний шифртекст блока.
	- `plaintext` (`out`) — буфер для розшифрованого блока.
- **Значення, що повертається:** не повертає (`void`).

#### `parallel_original_encrypt`
- **Призначення та умови використання:** MPI-шифрування вхідного буфера на всіх процесах із збіркою на root.
- **Загальний вигляд функції з перемінними:** `void parallel_original_encrypt(WBC2OriginalCipher *cipher, const uint8_t *plaintext, int plaintext_len, uint8_t **ciphertext, int *ciphertext_len)`.
- **Вхідні та вихідні дані:**
	- `cipher` (`in/out`) — структура стану шифру WBC2 для локального шифрування частини блоків.
	- `plaintext` (`in`) — вхідний масив байтів (валидний вміст потрібний на root).
	- `plaintext_len` (`in`) — довжина вхідних даних.
	- `ciphertext` (`out`) — адреса для повернення вказівника на шифртекст.
	- `ciphertext_len` (`out`) — довжина фінального шифртексту в байтах.
- **Значення, що повертається:** не повертає (`void`).

#### `parallel_original_decrypt`
- **Призначення та умови використання:** MPI-дешифрування із відновленням plaintext після об’єднання частин від усіх процесів.
- **Загальний вигляд функції з перемінними:** `void parallel_original_decrypt(WBC2OriginalCipher *cipher, const uint8_t *ciphertext, int ciphertext_len, uint8_t **plaintext, int *plaintext_len)`.
- **Вхідні та вихідні дані:**
	- `cipher` (`in/out`) — структура стану шифру WBC2 для зворотних раундових перетворень.
	- `ciphertext` (`in`) — зашифрований буфер для розподілу між процесами.
	- `ciphertext_len` (`in`) — повна довжина шифртексту.
	- `plaintext` (`out`) — повертає вказівник на виділений буфер відновленого тексту.
	- `plaintext_len` (`out`) — кількість корисних байтів у `*plaintext`.
- **Значення, що повертається:** не повертає (`void`).

### 6.4 `wbc1_parallel_cached.c`

#### `wbc1_encrypt_block`
- **Призначення та умови використання:** шифрує один блок WBC1 із використанням кешу операцій.
- **Загальний вигляд функції з перемінними:** `void wbc1_encrypt_block(WBC1Cipher *cipher, const uint8_t *plaintext, uint8_t *ciphertext)`.
- **Вхідні та вихідні дані:**
	- `cipher` (`in/out`) — структура стану шифру з уже підготовленим кешем (`precompute_operation_cache`).
	- `plaintext` (`in`) — вхідний блок даних розміру `BLOCK_SIZE`.
	- `ciphertext` (`out`) — буфер для зашифрованого блока (`BLOCK_SIZE`).
- **Значення, що повертається:** не повертає (`void`).

#### `wbc1_decrypt_block`
- **Призначення та умови використання:** дешифрує блок, зашифрований `wbc1_encrypt_block` з тим самим `cipher`.
- **Загальний вигляд функції з перемінними:** `void wbc1_decrypt_block(WBC1Cipher *cipher, const uint8_t *ciphertext, uint8_t *plaintext)`.
- **Вхідні та вихідні дані:**
	- `cipher` (`in/out`) — структура стану шифру WBC1 Cached з тими самими ключами/режимом.
	- `ciphertext` (`in`) — вхідний зашифрований блок.
	- `plaintext` (`out`) — вихідний розшифрований блок.
- **Значення, що повертається:** не повертає (`void`).

#### `parallel_encrypt`
- **Призначення та умови використання:** паралельно шифрує масив даних з автоматичним PKCS#7 padding.
- **Загальний вигляд функції з перемінними:** `void parallel_encrypt(WBC1Cipher *cipher, const uint8_t *plaintext, int plaintext_len, uint8_t **ciphertext, int *ciphertext_len)`.
- **Вхідні та вихідні дані:**
	- `cipher` (`in/out`) — структура стану шифру з налаштованими раундами/режимом.
	- `plaintext` (`in`) — вихідний текст (на root); для інших процесів може бути порожнім.
	- `plaintext_len` (`in`) — довжина вхідних даних до padding.
	- `ciphertext` (`out`) — повертає вказівник на виділений буфер шифртексту.
	- `ciphertext_len` (`out`) — довжина шифртексту після вирівнювання до блоку.
- **Значення, що повертається:** не повертає (`void`).

#### `parallel_decrypt`
- **Призначення та умови використання:** паралельно дешифрує дані та прибирає PKCS#7 padding.
- **Загальний вигляд функції з перемінними:** `void parallel_decrypt(WBC1Cipher *cipher, const uint8_t *ciphertext, int ciphertext_len, uint8_t **plaintext, int *plaintext_len)`.
- **Вхідні та вихідні дані:**
	- `cipher` (`in/out`) — структура стану шифру WBC1 Cached для дешифрування.
	- `ciphertext` (`in`) — вхідний шифртекст для обробки в MPI.
	- `ciphertext_len` (`in`) — довжина шифртексту.
	- `plaintext` (`out`) — адреса вказівника на розшифрований буфер.
	- `plaintext_len` (`out`) — довжина відновленого plaintext після unpad.
- **Значення, що повертається:** не повертає (`void`).

### 6.5 `wbc0_original_parallel_cuda.cu`

#### `wbc1_original_encrypt_block`
- **Призначення та умови використання:** шифрує один блок у CUDA-варіанті WBC0 з можливим GPU-прискоренням окремих кроків.
- **Загальний вигляд функції з перемінними:** `void wbc1_original_encrypt_block(WBC1OriginalCipher *cipher, const uint8_t *plaintext, uint8_t *ciphertext)`.
- **Вхідні та вихідні дані:**
	- `cipher` (`in/out`) — структура стану шифру WBC0 CUDA (операції, ключ, параметри блока, CUDA-стан).
	- `plaintext` (`in`) — вхідний блок відкритого тексту.
	- `ciphertext` (`out`) — вихідний зашифрований блок.
- **Значення, що повертається:** не повертає (`void`).

#### `wbc1_original_decrypt_block`
- **Призначення та умови використання:** дешифрує один блок у CUDA-реалізації (або CPU fallback).
- **Загальний вигляд функції з перемінними:** `void wbc1_original_decrypt_block(WBC1OriginalCipher *cipher, const uint8_t *ciphertext, uint8_t *plaintext)`.
- **Вхідні та вихідні дані:**
	- `cipher` (`in/out`) — структура стану шифру для дешифрування з тими самими параметрами, що при шифруванні.
	- `ciphertext` (`in`) — вхідний зашифрований блок.
	- `plaintext` (`out`) — буфер для розшифрованого блока.
- **Значення, що повертається:** не повертає (`void`).

#### `parallel_original_encrypt`
- **Призначення та умови використання:** виконує MPI-шифрування в CUDA-версії; працює і без GPU через fallback.
- **Загальний вигляд функції з перемінними:** `void parallel_original_encrypt(WBC1OriginalCipher *cipher, const uint8_t *plaintext, int plaintext_len, uint8_t **ciphertext, int *ciphertext_len)`.
- **Вхідні та вихідні дані:**
	- `cipher` (`in/out`) — структура стану шифру на кожному процесі.
	- `plaintext` (`in`) — вхідний буфер на root-процесі.
	- `plaintext_len` (`in`) — довжина відкритого тексту.
	- `ciphertext` (`out`) — повертає вказівник на буфер шифртексту (root).
	- `ciphertext_len` (`out`) — повертає довжину шифртексту в байтах.
- **Значення, що повертається:** не повертає (`void`).

#### `parallel_original_decrypt`
- **Призначення та умови використання:** MPI-дешифрування у CUDA/CPU режимах із відновленням початкового тексту.
- **Загальний вигляд функції з перемінними:** `void parallel_original_decrypt(WBC1OriginalCipher *cipher, const uint8_t *ciphertext, int ciphertext_len, uint8_t **plaintext, int *plaintext_len)`.
- **Вхідні та вихідні дані:**
	- `cipher` (`in/out`) — структура стану шифру WBC0 CUDA для зворотних перетворень.
	- `ciphertext` (`in`) — вхідний шифртекст (на root), розподіляється через MPI.
	- `ciphertext_len` (`in`) — загальна довжина шифртексту.
	- `plaintext` (`out`) — адреса вказівника на виділений вихідний буфер plaintext.
	- `plaintext_len` (`out`) — довжина результату після видалення padding.
- **Значення, що повертається:** не повертає (`void`).

---

## 7) Функції ключових етапів алгоритмів

### 7.1 Вибір операції

#### `mix_key_byte` (`wbc0_original_parallel.c`, `wbc1_original_parallel.c`, `wbc2_original_parallel.c`, `wbc0_original_parallel_cuda.cu`)
- **Призначення та умови використання:** нормалізує/перемішує байт ключа для стабільного вибору `op_id` у таблиці операцій.
- **Загальний вигляд функції з перемінними:** `uint8_t mix_key_byte(uint8_t byte)`.
- **Вхідні та вихідні дані:** `byte` (`in`) — байт ключового матеріалу.
- **Значення, що повертається:** `uint8_t` — перетворений байт для подальшого мапінгу на операцію.

#### `build_round_schedule` (`wbc0_original_parallel.c`, `wbc0_original_parallel_cuda.cu`)
- **Призначення та умови використання:** формує послідовність `op_id` і `shift` для раунду/проходу за ключем.
- **Загальний вигляд функції з перемінними:** `void build_round_schedule(..., uint8_t *op_ids, int *shifts, ...)`.
- **Вхідні та вихідні дані:** ключ/раундові параметри (`in`), масиви `op_ids`, `shifts` (`out`).
- **Значення, що повертається:** не повертає (`void`), результат записується у вихідні масиви.

### 7.2 Циклічний зсув

#### `cyclic_bitwise_shift` (`wbc0_original_parallel.c`, `wbc1_original_parallel.c`, `wbc2_original_parallel.c`, `wbc0_original_parallel_cuda.cu`)
- **Призначення та умови використання:** виконує циклічний побітовий зсув блока; використовується як етап перемішування бітів у раунді.
- **Загальний вигляд функції з перемінними:** `void cyclic_bitwise_shift(uint8_t *block, int size_bytes, int shift_bits)`.
- **Вхідні та вихідні дані:**
	- `block` (`in/out`) — буфер блока, змінюється in-place;
	- `size_bytes` (`in`) — розмір блока в байтах;
	- `shift_bits` (`in`) — величина зсуву в бітах (нормалізується по модулю довжини блока).
- **Значення, що повертається:** не повертає (`void`).

#### `cyclic_bitwise_rotate` (`wbc1_parallel_cached.c`)
- **Призначення та умови використання:** циклічне побітове обертання блока у cached-реалізації WBC1.
- **Загальний вигляд функції з перемінними:** `void cyclic_bitwise_rotate(uint8_t *block, int size, int shift, int direction)`.
- **Вхідні та вихідні дані:** `block` (`in/out`), `size` (`in`), `shift` (`in`), `direction` (`in`, напрямок обертання).
- **Значення, що повертається:** не повертає (`void`).

### 7.3 Дифузія

#### `cumulative_xor` (`wbc1_parallel_cached.c`)
- **Призначення та умови використання:** реалізує кумулятивну XOR-дифузію між байтами блока.
- **Загальний вигляд функції з перемінними:** `void cumulative_xor(uint8_t *block, int size, int inverse)`.
- **Вхідні та вихідні дані:** `block` (`in/out`) — блок для дифузії/інверсної дифузії; `size` (`in`), `inverse` (`in`).
- **Значення, що повертається:** не повертає (`void`).

#### `diffusion_layer1`, `diffusion_layer2`, `apply_diffusion` (`wbc2_original_parallel.c`)
- **Призначення та умови використання:** формують дифузійний етап WBC2 (поширення впливу біта/байта по всьому блоку).
- **Загальний вигляд функції з перемінними:**
	- `void diffusion_layer1(uint8_t *block, int block_size_bytes)`;
	- `void diffusion_layer2(uint8_t *block, int block_size_bytes)`;
	- `void apply_diffusion(uint8_t *block, int block_size_bytes)`.
- **Вхідні та вихідні дані:** `block` (`in/out`) — оброблюваний блок; `block_size_bytes` (`in`) — розмір блока.
- **Значення, що повертається:** не повертають (`void`).

#### `inverse_diffusion_layer1`, `apply_inverse_diffusion` (`wbc2_original_parallel.c`)
- **Призначення та умови використання:** інверсні перетворення для коректного дешифрування WBC2.
- **Загальний вигляд функції з перемінними:**
	- `void inverse_diffusion_layer1(uint8_t *block, int block_size_bytes)`;
	- `void apply_inverse_diffusion(uint8_t *block, int block_size_bytes)`.
- **Вхідні та вихідні дані:** `block` (`in/out`), `block_size_bytes` (`in`).
- **Значення, що повертається:** не повертають (`void`).

### 7.4 S-box і пов’язані перетворення

#### `generate_sbox` (`wbc2_original_parallel.c`, `wbc1_parallel_cached.c`)
- **Призначення та умови використання:** генерує ключозалежну таблицю підстановки S-box.
- **Загальний вигляд функції з перемінними:**
	- `void generate_sbox(const uint8_t *key, int key_len, uint8_t sbox[256], uint8_t inv_sbox[256])` (WBC2);
	- `void generate_sbox(WBC1Cipher *cipher)` (WBC1 Cached).
- **Вхідні та вихідні дані:** ключ/контекст (`in`), `sbox`/`inv_sbox` (`out` або поля в `cipher`).
- **Значення, що повертається:** не повертає (`void`).

#### `apply_sbox`, `apply_inv_sbox` (`wbc2_original_parallel.c`)
- **Призначення та умови використання:** пряме та обернене байтове підстановлення при шифруванні/дешифруванні WBC2.
- **Загальний вигляд функції з перемінними:**
	- `void apply_sbox(uint8_t *block, int block_size_bytes, const uint8_t sbox[256])`;
	- `void apply_inv_sbox(uint8_t *block, int block_size_bytes, const uint8_t inv_sbox[256])`.
- **Вхідні та вихідні дані:** `block` (`in/out`), `block_size_bytes` (`in`), таблиця S-box (`in`).
- **Значення, що повертається:** не повертають (`void`).

#### `substitute_bytes` (`wbc1_parallel_cached.c`)
- **Призначення та умови використання:** виконує пряму/зворотну S-box заміну в cached-реалізації WBC1.
- **Загальний вигляд функції з перемінними:** `void substitute_bytes(WBC1Cipher *cipher, uint8_t *block, int inverse)`.
- **Вхідні та вихідні дані:** `cipher` (`in`) — містить S-box/InvS-box, `block` (`in/out`), `inverse` (`in`).
- **Значення, що повертається:** не повертає (`void`).

### 7.5 Застосування операцій (перестановок)

#### `apply_operation` (`wbc1_original_parallel.c`, `wbc2_original_parallel.c`)
- **Призначення та умови використання:** застосовує вибрану операцію таблиці (або її інверсію) до блока.
- **Загальний вигляд функції з перемінними:** `void apply_operation(..., uint8_t *block, int op_id, int inverse)`.
- **Вхідні та вихідні дані:** `cipher` (`in`), `block` (`in/out`), `op_id` (`in`), `inverse` (`in`).
- **Значення, що повертається:** не повертає (`void`).

#### `apply_operation_cached` (`wbc1_parallel_cached.c`)
- **Призначення та умови використання:** швидке застосування операції через предобчислений кеш прямої/оберненої перестановки.
- **Загальний вигляд функції з перемінними:** `void apply_operation_cached(WBC1Cipher *cipher, uint8_t *block, int op_id, int inverse)`.
- **Вхідні та вихідні дані:** `cipher` (`in`) — містить кеш; `block` (`in/out`); `op_id` (`in`); `inverse` (`in`).
- **Значення, що повертається:** не повертає (`void`).

#### `apply_operation_sized` (`wbc0_original_parallel.c`, `wbc0_original_parallel_cuda.cu`)
- **Призначення та умови використання:** застосовує складену операцію до підблока заданого розміру.
- **Загальний вигляд функції з перемінними:** `void apply_operation_sized(WBC1OriginalCipher *cipher, uint8_t *block, int size, int op_id, int inverse)`.
- **Вхідні та вихідні дані:** `cipher` (`in`), `block` (`in/out`), `size` (`in`), `op_id` (`in`), `inverse` (`in`).
- **Значення, що повертається:** не повертає (`void`).
