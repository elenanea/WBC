#!/bin/bash
echo "Checking wbc1_original_parallel.c..."
LINES=$(wc -l < wbc1_original_parallel.c)
echo "Lines: $LINES"

TESTS=0
grep -q "shannon_entropy" wbc1_original_parallel.c && TESTS=$((TESTS+1))
grep -q "frequency_test" wbc1_original_parallel.c && TESTS=$((TESTS+1))
grep -q "avalanche_test" wbc1_original_parallel.c && TESTS=$((TESTS+1))
grep -q "correlation_test" wbc1_original_parallel.c && TESTS=$((TESTS+1))
grep -q "differential_test" wbc1_original_parallel.c && TESTS=$((TESTS+1))

echo "Tests found: $TESTS/5"

if [ $TESTS -eq 5 ]; then
    echo "✅ SUCCESS! All tests are present!"
    exit 0
else
    echo "❌ FAIL! Missing tests"
    exit 1
fi
