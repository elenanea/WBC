# Обзор программ и алгоритмов (WBC/PWBC)

## 1. Соответствие файлов и названий алгоритмов

| Название алгоритма | Файл | Параллелизм | Каскад |
|---|---|---|---|
| WBC1 | wbc1_cascade_new0.c | CPU (single-process) | SINGLE/DOUBLE |
| WBC2 | wbc2_cascade_8.c | CPU (single-process) | SINGLE/DOUBLE |
| PWBC1 | wbc1_nocascade_mpi_cli.c | MPI | NOCASCADE (single-pass) |
| PWBC1.1 | wbc1_cascade_mpi1.c | MPI | SINGLE/DOUBLE |
| PWBC2 | wbc2_original_parallel1_cli.c | MPI | WBC2 original parallel |
| PWBC2.1 | wbc1_parallel_cached.c | MPI | без каскада между проходами, кэш операций |
| PWBCCuda | wbc1_cascade_cuda.cu | CUDA + MPI | SINGLE + CPU fallback |

---

## 2. Математическая модель (ядро)

### 2.1 Общая блочная схема
Для блока $X_b$ и раунда $r$ используется композиция нелинейного и линейного преобразований:

$$
X_b^{(r+1)} = R_r\Big( S_r\big( L_r(P_r(X_b^{(r)}), K_r) \big) \Big)
$$

где:
- $P_r$ — перестановка (или композиция перестановок),
- $L_r$ — линейное/аффинное смешивание с ключом,
- $S_r$ — S-box (в WBC2-вариантах),
- $R_r$ — битовый циклический сдвиг.

### 2.2 Каскад между блоками
Каскадный ключ обновляется из зашифрованного блока:

$$
K_{b+1} = F\big(C_b, K_b\big)
$$

- SINGLE: один прямой проход по блокам.
- DOUBLE: второй проход (обычно обратный) с повторным каскадированием.
- NOCASCADE: $K_{b+1}=K_b$ (фиксированный мастер-ключ на всех блоках).

### 2.3 Для WBC2-CASCADE-8 (точная структура раунда)
Для $r=0..7$:

$$
X^{(r+1)} = \operatorname{Rot}_{\rho_r}\left(\operatorname{SBox}\left(X'^{(r)} \oplus RK_r\right)\right), \quad
X'^{(r)} = \Pi_r(X^{(r)})
$$

где $\Pi_r$ — composed-permutation (композиция 4 перестановок в одну таблицу),
$\rho_r = key[r\cdot4] \bmod 8$.

---

## 3. Детали по каждой программе

## WBC1 — wbc1_cascade_new0.c

### Идея
- Базовый каскадный WBC1 с режимами ECB/CBC/CFB/OFB/CTR/WBC-CTR-HMAC.
- Есть SINGLE/DOUBLE каскад.
- Есть self-tests, benchmark, fixed-key benchmark, avalanche/statistics.

### Компиляция
```bash
gcc -O3 -march=native -o wbc1_cascade_new0 wbc1_cascade_new0.c -lssl -lcrypto -lm
```

### Запуск
```bash
./wbc1_cascade_new0
./wbc1_cascade_new0 --single
./wbc1_cascade_new0 --double
```

### CLI значения
- `--single`: один каскадный проход.
- `--double`: двойной каскад (по умолчанию).
- `--help`: справка.

---

## WBC2 — wbc2_cascade_8.c

### Идея
- WBC2 с 8 раундами и composed-permutation (4 операции в 1 lookup на раунд).
- Полные режимы ECB/CBC/CFB/OFB/CTR/WBC-CTR-HMAC.
- SINGLE/DOUBLE.
- Есть named CLI и legacy menu.

### Компиляция
```bash
gcc -O3 -march=native -o wbc2_cascade_8 wbc2_cascade_8.c -lssl -lcrypto -lm
```

### Запуск (CLI)
```bash
./wbc2_cascade_8 --task-benchmark --mode ctr --single
./wbc2_cascade_8 --task-analysis --mode ecb --size 4 --double
./wbc2_cascade_8 --task-encrypt --mode wbc-ctr-hmac --text "hello"
```

### CLI значения
- `--task`:
  - `encrypt` / `analysis` / `selftest` / `benchmark` / `fixed`
- `--mode`:
  - `ecb`, `cbc`, `cfb`, `ofb`, `ctr`, `wbc-ctr-hmac`
- `--size`: размер данных для analysis (KB).
- `--text`: входной текст для encrypt-task.
- `--single`, `--once`: single cascade.
- `--double`: double cascade.

---

## PWBC1 — wbc1_nocascade_mpi_cli.c

### Идея
- MPI-версия WBC1 без каскада между блоками (fixed master key).
- Оптимизированные коллективные операции (Scatterv/Gatherv/Bcast).
- CLI ориентирован на batch-run и benchmark.

### Компиляция
```bash
mpicc -O2 -o wbc1_nocascade_mpi_cli wbc1_nocascade_mpi_cli.c -lssl -lcrypto -lm
```

### Запуск
```bash
mpirun -n 64 ./wbc1_nocascade_mpi_cli --single --task-benchmark --once
mpirun -n 32 ./wbc1_nocascade_mpi_cli --task-analysis --mode ctr --size 100
```

### CLI значения
- `--task`: `encrypt|selftest|benchmark|analysis`
- `--mode`: режим шифрования (в т.ч. `ctr`, `wbc-ctr-hmac`)
- `--size`: размер данных в KB
- `--text`: входной текст для encrypt
- `--single`, `--once`: совместимые флаги single-pass
- `--bench-1gb`: добавить точку 1 GiB в бенчмарк

---

## PWBC1.1 — wbc1_cascade_mpi1.c

### Идея
- MPI-версия WBC1 с cascade-within-chunks.
- Поддерживает SINGLE/DOUBLE каскад в параллельном контуре.
- Есть strict timing (`MPI_MAX`) и legacy timing.

### Компиляция
```bash
mpicc -O2 -o wbc1_cascade_mpi1 wbc1_cascade_mpi1.c -lssl -lcrypto -lm
```

### Запуск
```bash
mpirun -n 64 ./wbc1_cascade_mpi1 --task-benchmark --mode ctr --single
mpirun -n 64 ./wbc1_cascade_mpi1 --task-benchmark --mode ctr --double
```

### CLI значения
- `--task`: `encrypt|selftest|benchmark|analysis`
- `--mode`: режим шифрования
- `--size`: размер данных в KB
- `--text`: входной текст
- `--single` / `--double`: режим каскада
- `--once`: однократный запуск без меню

---

## PWBC2 — wbc2_original_parallel1_cli.c

### Идея
- MPI-реализация WBC2 original parallel.
- Разделены задачи encrypt/analysis/benchmark/table.
- Benchmark приведен к WBC-style таблице (KB/s, MB/s, Mbit/s, CPB).

### Компиляция
```bash
mpicc -O2 -o wbc2_original_parallel1_cli wbc2_original_parallel1_cli.c -lssl -lcrypto -lm
```

### Запуск
```bash
mpirun -n 32 ./wbc2_original_parallel1_cli --task-benchmark --once
mpirun -n 16 ./wbc2_original_parallel1_cli --task-analysis --mode random --size 100
```

### CLI значения
- `--task`: `encrypt|analysis|benchmark|table`
- `--task-benchmark`, `--benchmark`, `--bench`: benchmark-only
- `--mode`: `demo|random|simple|full`
- `--size`: объем данных в KB
- `--single`, `--once`: совместимые no-op флаги

---

## PWBC2.1 — wbc1_parallel_cached.c

### Идея
- MPI-вариант WBC1 с предвычисленным кэшем перестановок (operation cache).
- Ускорение за счет исключения повторных SHA/perm генераций в горячем цикле.
- Разделены encrypt/analysis/benchmark.

### Компиляция
```bash
mpicc -O2 -o wbc1_parallel_cached wbc1_parallel_cached.c -lssl -lcrypto -lm
```

### Запуск
```bash
mpirun -n 16 ./wbc1_parallel_cached --task-benchmark --mode full --key-size 256 --rounds 16
mpirun -n 8 ./wbc1_parallel_cached --task-analysis --size 64 --mode full
```

### CLI значения
- `--task`: `encrypt|analysis|benchmark`
- `--mode`: `full|simple|simplified`
- `--key-size`: размер ключа в битах
- `--rounds`: число раундов
- `--size`: размер данных в KB
- `--text`: текст для encrypt-task
- `--single`, `--once`: совместимость

---

## PWBCCuda — wbc1_cascade_cuda.cu

### Идея
- CUDA-ускоренный WBC1 cascade.
- MPI rank-to-GPU mapping, benchmark CUDA vs CPU.
- При отсутствии GPU: CPU fallback (без падения процесса).

### Компиляция
```bash
nvcc -O3 -ccbin mpicxx $(mpicxx --showme:compile) -o wbc1_cascade_cuda wbc1_cascade_cuda.cu $(mpicxx --showme:link) -lssl -lcrypto -lm
```

### Запуск
```bash
mpirun -np 1 ./wbc1_cascade_cuda --task-benchmark
mpirun -np 1 ./wbc1_cascade_cuda --task-encrypt --mode random --size 1024
mpirun -np 2 ./wbc1_cascade_cuda --task-analysis
```

### CLI значения
- `--task`: `encrypt|analysis|benchmark`
- `--task-test`/`--test`: self-tests
- `--mode`: `demo|random`
- `--size`: размер данных в KB
- `--text`: входной текст
- `--single`, `--once`: совместимость

---

## 4. Сводная таблица особенностей

| Алгоритм | Основа раунда | Каскад | Параллелизм | Ключевые особенности |
|---|---|---|---|---|
| WBC1 | perm + mix + rotate (+ режимная обвязка) | SINGLE/DOUBLE | CPU | полный набор режимов, HMAC-вариант |
| WBC2 | composed-perm + XOR + S-box + rotate | SINGLE/DOUBLE | CPU | 8 раундов, composed cache на раунд |
| PWBC1 | WBC1 NOCASCADE | single-pass | MPI | фиксированный master key между блоками |
| PWBC1.1 | WBC1 cascade-within-chunks | SINGLE/DOUBLE | MPI | строгий/legacy timing, масштабируемый benchmark |
| PWBC2 | WBC2 original parallel | зависит от task | MPI | benchmark в WBC-style, table/task split |
| PWBC2.1 | WBC1 cached operations | task-driven | MPI | предвычисленные операции, высокий throughput |
| PWBCCuda | WBC1 CUDA kernel + CPU ref | SINGLE (task-wise) | CUDA+MPI | rank→GPU, GPU/CPU сравнение, CPU fallback |

---

## 5. Интерпретация метрик benchmark

- `Enc (s)`: усредненное время шифрования.
- `Enc/Dec (KB/s)`: пропускная способность в KiB/s.
- `Enc/Dec (MB/s)`: пропускная способность в MB/s (десятичные).
- `Enc/Dec (Mbit/s)`: сетевые мегабиты в секунду.
- `CPB`: cycles per byte (оценка на основе CPU MHz).
- `E/D Cyc/blk`: cycles per block для encryption/decryption.
- `E/D B/cycle`: bytes per cycle.
- `Integrity`: проверка корректности расшифрования (`OK`/`FAIL`).

---

## 6. Практические рекомендации

1. Для криптостойкости и стабильной диффузии: предпочитать `DOUBLE` (кроме NOCASCADE-ветки, где это отключено дизайном).
2. Для больших объемов и масштабирования: использовать MPI benchmark c `repeats>=10` и trimmed mean.
3. Для GPU-версии: запускать только на узлах с доступным CUDA устройством; иначе получите корректный, но CPU fallback профиль.
4. Для корректного сравнения CPU/MPI/CUDA: использовать одинаковые размеры, одинаковый режим (`CTR`/`WBC-CTR-HMAC`) и одинаковый policy агрегации времени.
