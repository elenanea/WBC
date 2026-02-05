# Решение проблемы с git pull

## Ваша ситуация

Вы получили ошибку:
```
error: Your local changes to the following files would be overwritten by merge:
        Makefile
        wbc1_parallel.c
        wbc1_parallel_cached.c
Please commit your changes or stash them before you merge.

error: The following untracked working tree files would be overwritten by merge:
        WBC1_ENHANCED_README.md
        wbc1_original_parallel.c
        ...
Please move or remove them before you merge.
```

## Важно понять

**Эта ошибка возникает в ВАШЕЙ локальной директории, где у вас:**
1. Есть локальные изменения в файлах (Makefile, wbc1_parallel.c, wbc1_parallel_cached.c)
2. Есть неотслеживаемые файлы, которые конфликтуют с файлами из ветки

**Текущее рабочее пространство (где я работаю) УЖЕ ОБНОВЛЕНО:**
- ✅ wbc1_original_parallel.c имеет 807 строк
- ✅ Все 5 тестов присутствуют
- ✅ Ветка copilot/parallel-wbc1-algorithm актуальна

## Решение для вашей локальной директории

### Вариант 1: Сохранить ваши изменения и получить обновления

```bash
# 1. Сохранить ваши локальные изменения во временное хранилище
git stash

# 2. Получить обновления
git pull origin copilot/parallel-wbc1-algorithm

# 3. Проверить файл
wc -l wbc1_original_parallel.c
# Должно показать: 807

# 4. Если нужно, восстановить ваши изменения
git stash pop
```

### Вариант 2: Удалить конфликтующие файлы и получить обновления

```bash
# 1. Создать резервную копию (если нужно)
mkdir backup
cp wbc1_original_parallel.c backup/ 2>/dev/null

# 2. Удалить конфликтующие неотслеживаемые файлы
rm -f WBC1_ENHANCED_README.md
rm -f wbc1_original_parallel.c
rm -f wbc1_parallel_cached_new.c
rm -f wbc1_parallel_cached_opti.c
rm -f wbc1_parallel_gen_cached.c
rm -f wbc1_parallel_minimal.c
rm -f wbc1_parallel_new.c

# 3. Сохранить изменения в отслеживаемых файлах
git stash

# 4. Получить обновления
git pull origin copilot/parallel-wbc1-algorithm

# 5. Проверить
wc -l wbc1_original_parallel.c
# Должно показать: 807
```

### Вариант 3: Полный reset (потеряете локальные изменения!)

```bash
# ВНИМАНИЕ: Это удалит все ваши локальные изменения!

# 1. Сбросить все изменения
git reset --hard HEAD

# 2. Удалить неотслеживаемые файлы
git clean -fd

# 3. Получить обновления
git pull origin copilot/parallel-wbc1-algorithm

# 4. Проверить
wc -l wbc1_original_parallel.c
# Должно показать: 807
```

## Проверка после обновления

После успешного pull выполните:

```bash
# Проверить размер файла
wc -l wbc1_original_parallel.c

# Проверить наличие тестов
grep -n "shannon_entropy\|frequency_test\|avalanche_test\|correlation_test\|differential_test" wbc1_original_parallel.c | head -5

# Запустить скрипт проверки
./verify_tests_simple.sh
```

## Ожидаемый результат

После успешного обновления вы должны увидеть:

```
$ wc -l wbc1_original_parallel.c
807 wbc1_original_parallel.c

$ ./verify_tests_simple.sh
Checking wbc1_original_parallel.c...
Lines: 807
Tests found: 5/5
✅ SUCCESS! All tests are present!
```

## Почему возникла проблема?

1. **У вас есть локальные изменения** в файлах Makefile, wbc1_parallel.c, wbc1_parallel_cached.c
2. **У вас есть неотслеживаемые файлы** с теми же именами, что и в обновляемой ветке
3. Git не может перезаписать эти файлы без вашего разрешения

## Как избежать в будущем?

1. Всегда делайте `git status` перед `git pull`
2. Используйте `git stash` для временного сохранения изменений
3. Коммитьте изменения регулярно
4. Работайте в отдельной ветке для своих экспериментов

## Нужна помощь?

Если проблема не решается, покажите результат команд:

```bash
git status
git branch
pwd
wc -l wbc1_original_parallel.c
```

Это поможет понять, в какой директории и ветке вы находитесь.
