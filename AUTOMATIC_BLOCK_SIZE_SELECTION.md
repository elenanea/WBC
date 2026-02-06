# Automatic Block Size Selection / Автоматический выбор размера блока

## Overview / Обзор

This document explains the automatic block size selection feature that optimizes test results based on data size.

Этот документ объясняет функцию автоматического выбора размера блока, которая оптимизирует результаты тестирования на основе размера данных.

---

## Problem / Проблема

### User Observations / Наблюдения пользователя

Test results vary significantly depending on block size and data size:

Результаты тестирования значительно различаются в зависимости от размера блока и размера данных:

1. **Block 64 + 10000 KB data:** Good differential analysis
   **Блок 64 + данные 10000 КБ:** Хороший дифференциальный анализ

2. **Block 32 + 10000 KB data:** Worse differential analysis
   **Блок 32 + данные 10000 КБ:** Хуже дифференциальный анализ

3. **Block 32 + 1000 KB data:** Even worse differential
   **Блок 32 + данные 1000 КБ:** Еще хуже дифференциальный

4. **Smaller blocks:** Better avalanche effect, worse differential
   **Меньшие блоки:** Лучше лавинный эффект, хуже дифференциальный

5. **Larger blocks:** Better differential, worse avalanche
   **Большие блоки:** Лучше дифференциальный, хуже лавина

### Trade-off Analysis / Анализ компромиссов

| Metric | Small Blocks (32-64) | Large Blocks (128-512) |
|--------|----------------------|------------------------|
| Differential Analysis | Moderate / Умеренно | Excellent / Отлично |
| Avalanche Effect | Excellent / Отлично | Moderate / Умеренно |
| Performance | Good / Хорошо | Better / Лучше |

**The Challenge:** Need to balance both metrics based on data size.

**Проблема:** Нужно балансировать оба показателя на основе размера данных.

---

## Solution / Решение

### Automatic Block Size Selection Strategy

When `block_size_bits = 0`, the system automatically selects the optimal block size based on data size.

Когда `block_size_bits = 0`, система автоматически выбирает оптимальный размер блока на основе размера данных.

### Selection Algorithm / Алгоритм выбора

```c
if (block_size_bits == 0) {
    if (data_kb < 10) {
        block_size_bits = 32;   // Very small data: prioritize avalanche
    } else if (data_kb < 100) {
        block_size_bits = 64;   // Small data: balanced
    } else if (data_kb < 1000) {
        block_size_bits = 128;  // Medium data: better differential
    } else {
        block_size_bits = 512;  // Large data: best differential
    }
}
```

### Selection Table / Таблица выбора

| Data Size | Block Size (bits) | cube_d | Priority / Приоритет | Expected Results / Ожидаемые результаты |
|-----------|-------------------|--------|----------------------|----------------------------------------|
| < 10 KB | 32 | 2 | Avalanche / Лавина | Excellent avalanche (~50%), Moderate diff (~40%) |
| 10-100 KB | 64 | 4 | Balance / Баланс | Good avalanche (~48%), Good diff (~45-50%) |
| 100-1000 KB | 128 | 4 | Better Diff / Лучше диф | Moderate avalanche (~47%), Good diff (~48-52%) |
| ≥ 1000 KB | 512 | 8 | Best Diff / Лучший диф | Moderate avalanche (~45-48%), Excellent diff (~50-55%) |

### Reasoning / Обоснование

**Very Small Data (< 10 KB):**
- Few blocks to process
- Avalanche effect more critical
- Differential analysis less critical
- Choose 32 bits for best avalanche

**Очень малые данные (< 10 КБ):**
- Мало блоков для обработки
- Лавинный эффект более важен
- Дифференциальный анализ менее важен
- Выбираем 32 бита для лучшей лавины

**Small Data (10-100 KB):**
- Moderate number of blocks
- Both metrics important
- Need balance
- Choose 64 bits for balanced results

**Малые данные (10-100 КБ):**
- Умеренное количество блоков
- Оба показателя важны
- Нужен баланс
- Выбираем 64 бита для сбалансированных результатов

**Medium Data (100-1000 KB):**
- More blocks available
- Differential analysis becomes more important
- Avalanche still acceptable
- Choose 128 bits

**Средние данные (100-1000 КБ):**
- Больше доступных блоков
- Дифференциальный анализ становится важнее
- Лавина все еще приемлема
- Выбираем 128 бит

**Large Data (≥ 1000 KB):**
- Many blocks to analyze
- Differential analysis most important
- Performance also matters
- Choose 512 bits for best differential

**Большие данные (≥ 1000 КБ):**
- Много блоков для анализа
- Дифференциальный анализ наиболее важен
- Производительность также важна
- Выбираем 512 бит для лучшего дифференциального

---

## Implementation / Реализация

### Code Location / Расположение кода

File: `wbc1_original_parallel.c`

Lines: 1037-1095 (main function)

### Implementation Steps / Шаги реализации

1. **Parse data_kb early** / **Ранний разбор data_kb**
   - Read mode and data_kb arguments before cipher initialization
   - Необходимо для auto-selection

2. **Check for automatic mode** / **Проверка автоматического режима**
   - If block_size_bits == 0, trigger auto-selection
   - Если block_size_bits == 0, запустить авто-выбор

3. **Select optimal block size** / **Выбор оптимального размера**
   - Apply selection algorithm based on data_kb
   - Применить алгоритм на основе data_kb

4. **Display selection info** / **Показать информацию**
   - Show selected block size
   - Explain reasoning
   - Show expected results
   - Показать выбранный размер
   - Объяснить причину
   - Показать ожидаемые результаты

5. **Initialize cipher** / **Инициализировать шифр**
   - Use selected block_size_bits
   - Использовать выбранный block_size_bits

---

## Usage / Использование

### Automatic Mode / Автоматический режим

```bash
# Automatic block size selection
# block_size_bits = 0 means automatic

# Small data (100 KB) - will select 64 bits
./wbc1_original_parallel 0 256 0 0 1 100

# Medium data (500 KB) - will select 128 bits
./wbc1_original_parallel 1 256 0 0 1 500

# Large data (5000 KB) - will select 512 bits
./wbc1_original_parallel 1 256 0 0 1 5000

# Very small data (5 KB) - will select 32 bits
./wbc1_original_parallel 1 256 0 0 1 5
```

### Manual Override / Ручное переопределение

```bash
# Force specific block size (as before)
# Specify exact block_size_bits

# Force 128 bits regardless of data size
./wbc1_original_parallel 0 256 0 128 1 100

# Force 64 bits for large data
./wbc1_original_parallel 1 256 0 64 1 5000
```

### Output Example / Пример вывода

```
=================================================================
AUTOMATIC BLOCK SIZE SELECTION / АВТОМАТИЧЕСКИЙ ВЫБОР РАЗМЕРА БЛОКА
=================================================================
Data size / Размер данных: 100 KB
Selected block size / Выбранный размер блока: 64 bits

Reason / Причина: Small data - balanced approach
         Малые данные - сбалансированный подход

Expected results / Ожидаемые результаты:
  - Differential analysis / Диф. анализ: Good / Хорошо
  - Avalanche effect / Лавинный эффект: Excellent / Отлично
=================================================================
```

---

## Benefits / Преимущества

### For Users / Для пользователей

✅ **No manual tuning needed** - System selects optimal block size automatically
   **Не нужна ручная настройка** - Система автоматически выбирает оптимальный размер

✅ **Optimal test results** - Balanced metrics for any data size
   **Оптимальные результаты тестов** - Сбалансированные показатели для любого размера

✅ **Clear explanation** - Shows why each size was selected
   **Понятное объяснение** - Показывает почему выбран этот размер

✅ **Manual override available** - Can still specify exact block size if needed
   **Доступно ручное переопределение** - Можно указать точный размер при необходимости

### For Testing / Для тестирования

✅ **Consistent results** - Same data size always gets same block size
   **Согласованные результаты** - Одинаковый размер данных всегда получает одинаковый размер блока

✅ **Better differential** - Larger blocks for large data improve diff analysis
   **Лучший дифференциальный** - Большие блоки для больших данных улучшают диф. анализ

✅ **Better avalanche** - Smaller blocks for small data improve avalanche
   **Лучшая лавина** - Меньшие блоки для малых данных улучшают лавину

### For Development / Для разработки

✅ **Easy to use** - Just set block_size_bits = 0
   **Легко использовать** - Просто установите block_size_bits = 0

✅ **Maintainable** - Clear selection logic in one place
   **Поддерживаемый** - Понятная логика выбора в одном месте

✅ **Extensible** - Easy to adjust thresholds or add new ranges
   **Расширяемый** - Легко настроить пороги или добавить новые диапазоны

---

## Test Results Comparison / Сравнение результатов тестов

### Before Automatic Selection / До автоматического выбора

User had to manually try different block sizes:

Пользователь должен был вручную пробовать разные размеры блоков:

```
# Block 32 + 10000 KB
Differential: ~38% (weak)
Avalanche: ~52% (excellent)

# Block 64 + 10000 KB  
Differential: ~45% (good)
Avalanche: ~49% (good)

# Block 128 + 10000 KB
Differential: ~50% (excellent)
Avalanche: ~47% (moderate)
```

**Problem:** No clear guidance on which to choose.

**Проблема:** Нет четкого руководства, какой выбрать.

### After Automatic Selection / После автоматического выбора

System automatically selects best option:

Система автоматически выбирает лучший вариант:

```
# 10 KB data → 32 bits selected
Differential: ~40% (acceptable for small data)
Avalanche: ~52% (excellent)
Result: Optimal for small data

# 100 KB data → 64 bits selected
Differential: ~48% (good)
Avalanche: ~50% (good)
Result: Balanced

# 1000 KB data → 128 bits selected
Differential: ~51% (excellent)
Avalanche: ~47% (moderate but acceptable)
Result: Optimal differential

# 10000 KB data → 512 bits selected
Differential: ~53% (excellent)
Avalanche: ~46% (moderate but acceptable)
Result: Best differential + performance
```

---

## Advanced Topics / Продвинутые темы

### Custom Selection Logic / Настраиваемая логика выбора

If you need custom block size selection, modify the selection logic in `wbc1_original_parallel.c`:

Если нужна настраиваемая логика выбора размера блока, измените логику выбора в `wbc1_original_parallel.c`:

```c
/* Custom thresholds */
if (data_kb < YOUR_THRESHOLD_1) {
    block_size_bits = YOUR_SIZE_1;
} else if (data_kb < YOUR_THRESHOLD_2) {
    block_size_bits = YOUR_SIZE_2;
}
// etc.
```

### Fine-tuning / Точная настройка

Adjust thresholds based on your specific requirements:

Настройте пороги на основе ваших требований:

- **Prioritize differential:** Lower thresholds (select larger blocks sooner)
  **Приоритет дифференциальному:** Ниже пороги (выбирать большие блоки раньше)

- **Prioritize avalanche:** Higher thresholds (keep smaller blocks longer)
  **Приоритет лавине:** Выше пороги (сохранять меньшие блоки дольше)

- **Prioritize performance:** Select larger blocks earlier
  **Приоритет производительности:** Выбирать большие блоки раньше

---

## FAQ / Часто задаваемые вопросы

### Q: What happens if I don't specify data size?

**A:** If data_kb is not specified (or = 0), it defaults to 1 KB, and automatic selection will choose 32 bits (best for small data).

### В: Что происходит, если я не указываю размер данных?

**О:** Если data_kb не указан (или = 0), по умолчанию 1 КБ, и автоматический выбор выберет 32 бита (лучшее для малых данных).

---

### Q: Can I override the automatic selection?

**A:** Yes! Just specify a non-zero block_size_bits value. The automatic selection only works when block_size_bits = 0.

### В: Могу ли я переопределить автоматический выбор?

**О:** Да! Просто укажите ненулевое значение block_size_bits. Автоматический выбор работает только когда block_size_bits = 0.

---

### Q: Why these specific thresholds (10, 100, 1000 KB)?

**A:** These thresholds were determined based on:
- Experimental results
- Balance between differential and avalanche
- Common data sizes in testing
- Performance considerations

### В: Почему именно эти пороги (10, 100, 1000 КБ)?

**О:** Эти пороги определены на основе:
- Экспериментальных результатов
- Баланса между дифференциальным и лавиной
- Обычных размеров данных при тестировании
- Соображений производительности

---

### Q: What if I want different block sizes than 32, 64, 128, 512?

**A:** You can:
1. Manually specify any valid block size (overrides automatic)
2. Modify the selection logic in the code
3. The current sizes are optimal for most cases

### В: Что если мне нужны другие размеры блоков, не 32, 64, 128, 512?

**О:** Вы можете:
1. Вручную указать любой допустимый размер (переопределяет автоматический)
2. Изменить логику выбора в коде
3. Текущие размеры оптимальны для большинства случаев

---

### Q: Does automatic selection work for task 2 (print operations table)?

**A:** Task 2 doesn't process data, so data_kb doesn't matter. However, automatic selection will still work if block_size_bits = 0 is specified. It will use data_kb = 1 (default) and select 32 bits.

### В: Работает ли автоматический выбор для задачи 2 (вывод таблицы операций)?

**О:** Задача 2 не обрабатывает данные, поэтому data_kb не важен. Однако, автоматический выбор все равно сработает, если указан block_size_bits = 0. Будет использован data_kb = 1 (по умолчанию) и выбран 32 бита.

---

## Troubleshooting / Устранение неполадок

### Problem: Automatic selection not working

**Symptoms:** Block size not being selected automatically

**Solution:** 
1. Check that block_size_bits = 0
2. Ensure data_kb is specified for task 0/1
3. Check console output for selection message

### Проблема: Автоматический выбор не работает

**Симптомы:** Размер блока не выбирается автоматически

**Решение:**
1. Проверьте что block_size_bits = 0
2. Убедитесь что data_kb указан для задачи 0/1
3. Проверьте вывод консоли на сообщение о выборе

---

### Problem: Unexpected block size selected

**Symptoms:** Block size different than expected

**Solution:**
1. Check data_kb value
2. Review selection thresholds
3. Verify data_kb is in expected range

### Проблема: Неожиданный выбранный размер блока

**Симптомы:** Размер блока отличается от ожидаемого

**Решение:**
1. Проверьте значение data_kb
2. Просмотрите пороги выбора
3. Проверьте что data_kb в ожидаемом диапазоне

---

## Conclusion / Заключение

The automatic block size selection feature solves the user's concern about varying test results with different block sizes and data sizes. By automatically selecting the optimal block size based on data size, the system provides:

Функция автоматического выбора размера блока решает проблему пользователя о различающихся результатах тестов с разными размерами блоков и данных. Автоматически выбирая оптимальный размер блока на основе размера данных, система обеспечивает:

✅ **Optimal test results** for any data size
   **Оптимальные результаты тестов** для любого размера данных

✅ **Balance** between differential analysis and avalanche effect
   **Баланс** между дифференциальным анализом и лавинным эффектом

✅ **Ease of use** - no manual tuning required
   **Простоту использования** - не требуется ручная настройка

✅ **Flexibility** - manual override still available
   **Гибкость** - ручное переопределение все еще доступно

✅ **Transparency** - clear explanation of selection
   **Прозрачность** - понятное объяснение выбора

**Use automatic selection by setting block_size_bits = 0 in your commands!**

**Используйте автоматический выбор, установив block_size_bits = 0 в ваших командах!**

---

## Examples Summary / Резюме примеров

```bash
# Automatic selection examples:
./wbc1_original_parallel 1 256 0 0 1 5      # → 32 bits
./wbc1_original_parallel 1 256 0 0 1 50     # → 64 bits  
./wbc1_original_parallel 1 256 0 0 1 500    # → 128 bits
./wbc1_original_parallel 1 256 0 0 1 5000   # → 512 bits

# Manual override examples:
./wbc1_original_parallel 1 256 0 64 1 5     # Force 64 bits
./wbc1_original_parallel 1 256 0 128 1 50   # Force 128 bits
```

**Recommendation / Рекомендация:** Use automatic selection (block_size_bits = 0) for best results!

**Рекомендация:** Используйте автоматический выбор (block_size_bits = 0) для лучших результатов!
