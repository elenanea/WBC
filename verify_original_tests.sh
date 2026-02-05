#!/bin/bash
# Verification script for wbc1_original_parallel.c tests
# This script verifies that all statistical tests are present in the file

echo "=========================================="
echo "Проверка wbc1_original_parallel.c"
echo "Verification of wbc1_original_parallel.c"
echo "=========================================="
echo ""

# Check if file exists
if [ ! -f "wbc1_original_parallel.c" ]; then
    echo "❌ ERROR: File wbc1_original_parallel.c not found!"
    echo "❌ ОШИБКА: Файл wbc1_original_parallel.c не найден!"
    echo ""
    echo "Make sure you are in the correct directory and have pulled the latest changes:"
    echo "Убедитесь, что вы в правильной директории и загрузили последние изменения:"
    echo "  git checkout copilot/parallel-wbc1-algorithm"
    echo "  git pull origin copilot/parallel-wbc1-algorithm"
    exit 1
fi

# Count lines
LINES=$(wc -l < wbc1_original_parallel.c)
echo "📄 File size / Размер файла: $LINES lines / строк"
echo ""

if [ "$LINES" -lt 800 ]; then
    echo "⚠️  WARNING: File has only $LINES lines, expected ~807"
    echo "⚠️  ВНИМАНИЕ: Файл содержит только $LINES строк, ожидается ~807"
    echo ""
    echo "Please update your local copy:"
    echo "Пожалуйста, обновите локальную копию:"
    echo "  git pull origin copilot/parallel-wbc1-algorithm"
    echo ""
fi

# Check for test functions
echo "🔍 Checking for test functions / Проверка функций тестов:"
echo ""

TESTS_FOUND=0

if grep -q "static double shannon_entropy" wbc1_original_parallel.c; then
    echo "✅ Shannon Entropy Test - FOUND / НАЙДЕН"
    TESTS_FOUND=$((TESTS_FOUND + 1))
else
    echo "❌ Shannon Entropy Test - NOT FOUND / НЕ НАЙДЕН"
fi

if grep -q "static void frequency_test" wbc1_original_parallel.c; then
    echo "✅ Frequency Test - FOUND / НАЙДЕН"
    TESTS_FOUND=$((TESTS_FOUND + 1))
else
    echo "❌ Frequency Test - NOT FOUND / НЕ НАЙДЕН"
fi

if grep -q "static void avalanche_test" wbc1_original_parallel.c; then
    echo "✅ Avalanche Effect Test - FOUND / НАЙДЕН"
    TESTS_FOUND=$((TESTS_FOUND + 1))
else
    echo "❌ Avalanche Effect Test - NOT FOUND / НЕ НАЙДЕН"
fi

if grep -q "static double correlation_test" wbc1_original_parallel.c; then
    echo "✅ Correlation Test - FOUND / НАЙДЕН"
    TESTS_FOUND=$((TESTS_FOUND + 1))
else
    echo "❌ Correlation Test - NOT FOUND / НЕ НАЙДЕН"
fi

if grep -q "static void differential_test" wbc1_original_parallel.c; then
    echo "✅ Differential Test - FOUND / НАЙДЕН"
    TESTS_FOUND=$((TESTS_FOUND + 1))
else
    echo "❌ Differential Test - NOT FOUND / НЕ НАЙДЕН"
fi

echo ""
echo "=========================================="
echo "Result / Результат: $TESTS_FOUND/5 tests found / тестов найдено"
echo "=========================================="
echo ""

if [ "$TESTS_FOUND" -eq 5 ] && [ "$LINES" -ge 700 ]; then
    echo "✅ SUCCESS! All tests are present in the file!"
    echo "✅ УСПЕХ! Все тесты присутствуют в файле!"
    echo ""
    echo "The file is fully updated with all statistical tests."
    echo "Файл полностью обновлен со всеми статистическими тестами."
    exit 0
else
    echo "❌ INCOMPLETE! File needs to be updated."
    echo "❌ НЕПОЛНЫЙ! Файл нужно обновить."
    echo ""
    echo "Please run these commands to update:"
    echo "Пожалуйста, выполните эти команды для обновления:"
    echo "  git checkout copilot/parallel-wbc1-algorithm"
    echo "  git pull origin copilot/parallel-wbc1-algorithm"
    exit 1
fi
