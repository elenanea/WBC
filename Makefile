# Makefile for WBC1 Block Cipher - Parallel Implementation with MPI
#
# Targets:
#   all         - Build both basic and cached versions
#   basic       - Build basic parallel version (wbc1_parallel)
#   cached      - Build cached/optimized version (wbc1_parallel_cached)
#   clean       - Remove all compiled binaries
#   test        - Run tests for both versions
#   test-basic  - Run test for basic version
#   test-cached - Run test for cached version

# Compiler and MPI wrapper
MPICC = mpicc

# Compiler flags
CFLAGS = -O3 -Wall -Wextra -std=c99
LDFLAGS = -lssl -lcrypto -lm

# Number of MPI processes for testing
NUM_PROCS = 4

# Source files
SRC_BASIC = wbc1_parallel.c
SRC_CACHED = wbc1_parallel_cached.c
SRC_BASIC_NEW = wbc1_parallel_new.c
SRC_CACHED_NEW = wbc1_parallel_cached_new.c

# Output binaries
BIN_BASIC = wbc1_parallel
BIN_CACHED = wbc1_parallel_cached
BIN_BASIC_NEW = wbc1_parallel_new
BIN_CACHED_NEW = wbc1_parallel_cached_new

# Default target
all: basic cached

# Build all versions including new enhanced versions
all-new: basic cached new

# Build enhanced versions
new: basic-new cached-new

# Build basic version
basic: $(BIN_BASIC)

$(BIN_BASIC): $(SRC_BASIC)
	$(MPICC) $(CFLAGS) -o $(BIN_BASIC) $(SRC_BASIC) $(LDFLAGS)

# Build cached version
cached: $(BIN_CACHED)

$(BIN_CACHED): $(SRC_CACHED)
	$(MPICC) $(CFLAGS) -o $(BIN_CACHED) $(SRC_CACHED) $(LDFLAGS)

# Build enhanced basic version (Mode 0 improvements)
basic-new: $(BIN_BASIC_NEW)

$(BIN_BASIC_NEW): $(SRC_BASIC_NEW)
	$(MPICC) $(CFLAGS) -o $(BIN_BASIC_NEW) $(SRC_BASIC_NEW) $(LDFLAGS)

# Build enhanced cached version (Mode 0 improvements)
cached-new: $(BIN_CACHED_NEW)

$(BIN_CACHED_NEW): $(SRC_CACHED_NEW)
	$(MPICC) $(CFLAGS) -o $(BIN_CACHED_NEW) $(SRC_CACHED_NEW) $(LDFLAGS)

# Clean build artifacts
clean:
	rm -f $(BIN_BASIC) $(BIN_CACHED) $(BIN_BASIC_NEW) $(BIN_CACHED_NEW) *.o

# Run tests
test: test-basic test-cached

# Run tests for enhanced versions
test-new: test-basic-new test-cached-new

test-basic: $(BIN_BASIC)
	@echo "========================================"
	@echo "Testing Basic Parallel Version"
	@echo "========================================"
	@echo ""
	@echo "Test 1: Mode 1 (Full algorithm) with 16 rounds"
	mpirun -n $(NUM_PROCS) ./$(BIN_BASIC) 1 16
	@echo ""
	@echo "Test 2: Mode 0 (Simplified algorithm) with 16 rounds"
	mpirun -n $(NUM_PROCS) ./$(BIN_BASIC) 0 16
	@echo ""

test-cached: $(BIN_CACHED)
	@echo "========================================"
	@echo "Testing Cached/Optimized Version"
	@echo "========================================"
	@echo ""
	@echo "Test 1: Mode 1 (Full algorithm) with 16 rounds"
	mpirun -n $(NUM_PROCS) ./$(BIN_CACHED) 1 16
	@echo ""
	@echo "Test 2: Mode 0 (Simplified algorithm) with 16 rounds"
	mpirun -n $(NUM_PROCS) ./$(BIN_CACHED) 0 16
	@echo ""

test-basic-new: $(BIN_BASIC_NEW)
	@echo "========================================"
	@echo "Testing ENHANCED Basic Parallel Version"
	@echo "========================================"
	@echo ""
	@echo "Test 1: Mode 1 (Full algorithm) with 16 rounds"
	mpirun -n $(NUM_PROCS) ./$(BIN_BASIC_NEW) 1 16
	@echo ""
	@echo "Test 2: Mode 0 (ENHANCED Simplified - should show improved avalanche!) with 16 rounds"
	mpirun -n $(NUM_PROCS) ./$(BIN_BASIC_NEW) 0 16
	@echo ""

test-cached-new: $(BIN_CACHED_NEW)
	@echo "========================================"
	@echo "Testing ENHANCED Cached/Optimized Version"
	@echo "========================================"
	@echo ""
	@echo "Test 1: Mode 1 (Full algorithm) with 16 rounds"
	mpirun -n $(NUM_PROCS) ./$(BIN_CACHED_NEW) 1 16
	@echo ""
	@echo "Test 2: Mode 0 (ENHANCED Simplified - should show improved avalanche!) with 16 rounds"
	mpirun -n $(NUM_PROCS) ./$(BIN_CACHED_NEW) 0 16
	@echo ""

# Benchmark both versions
benchmark: $(BIN_BASIC) $(BIN_CACHED)
	@echo "========================================"
	@echo "Benchmarking WBC1 Implementations"
	@echo "========================================"
	@echo ""
	@echo "Basic version (Mode 1, 16 rounds):"
	time mpirun -n $(NUM_PROCS) ./$(BIN_BASIC) 1 16
	@echo ""
	@echo "Cached version (Mode 1, 16 rounds):"
	time mpirun -n $(NUM_PROCS) ./$(BIN_CACHED) 1 16
	@echo ""

# Help target
help:
	@echo "WBC1 Block Cipher - Makefile Help"
	@echo ""
	@echo "Available targets:"
	@echo "  all         - Build both basic and cached versions (default)"
	@echo "  basic       - Build basic parallel version"
	@echo "  cached      - Build cached/optimized version"
	@echo "  clean       - Remove all compiled binaries"
	@echo "  test        - Run tests for both versions"
	@echo "  test-basic  - Run test for basic version"
	@echo "  test-cached - Run test for cached version"
	@echo "  benchmark   - Compare performance of both versions"
	@echo "  help        - Show this help message"
	@echo ""
	@echo "Usage examples:"
	@echo "  make                           # Build both versions"
	@echo "  make cached                    # Build only cached version"
	@echo "  make test NUM_PROCS=8          # Test with 8 MPI processes"
	@echo "  mpirun -n 4 ./wbc1_parallel 1 16    # Run basic: mode=1, rounds=16"
	@echo "  mpirun -n 4 ./wbc1_parallel_cached 0 32  # Run cached: mode=0, rounds=32"
	@echo ""
	@echo "Algorithm modes:"
	@echo "  Mode 0: Simplified (2 operations: permutation + rotation)"
	@echo "  Mode 1: Full (5 operations: permutation + XOR + S-box + diffusion + rotation)"
	@echo ""

.PHONY: all basic cached clean test test-basic test-cached benchmark help
