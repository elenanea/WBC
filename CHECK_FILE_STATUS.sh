#!/bin/bash

echo "============================================"
echo "Проверка статуса wbc1_original_parallel.c"
echo "============================================"
echo ""

echo "1. Текущая ветка:"
git branch --show-current
echo ""

echo "2. Последний коммит файла:"
git log --oneline -1 wbc1_original_parallel.c
echo ""

echo "3. Размер файла в текущей версии:"
wc -l wbc1_original_parallel.c
echo ""

echo "4. Размер файла в коммите e18e24f:"
git show e18e24f:wbc1_original_parallel.c | wc -l
echo ""

echo "5. Проверка наличия тестов:"
echo "   Shannon Entropy:"
grep -q "static double shannon_entropy" wbc1_original_parallel.c && echo "   ✅ Найден" || echo "   ❌ Не найден"

echo "   Frequency Test:"
grep -q "static void frequency_test" wbc1_original_parallel.c && echo "   ✅ Найден" || echo "   ❌ Не найден"

echo "   Avalanche Test:"
grep -q "static void avalanche_test" wbc1_original_parallel.c && echo "   ✅ Найден" || echo "   ❌ Не найден"

echo "   Correlation Test:"
grep -q "static double correlation_test" wbc1_original_parallel.c && echo "   ✅ Найден" || echo "   ❌ Не найден"

echo "   Differential Test:"
grep -q "static void differential_test" wbc1_original_parallel.c && echo "   ✅ Найден" || echo "   ❌ Не найден"

echo ""
echo "============================================"
echo "Если размер файла 490 строк, выполните:"
echo "  git pull origin copilot/parallel-wbc1-algorithm"
echo "============================================"
