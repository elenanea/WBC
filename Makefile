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
SRC_CACHED_OPTI = wbc1_parallel_cached_opti.c
SRC_GEN_CACHED = wbc1_parallel_gen_cached.c
SRC_MINIMAL = wbc1_parallel_minimal.c

# Output binaries
BIN_BASIC = wbc1_parallel
BIN_CACHED = wbc1_parallel_cached
BIN_BASIC_NEW = wbc1_parallel_new
BIN_CACHED_NEW = wbc1_parallel_cached_new
BIN_CACHED_OPTI = wbc1_parallel_cached_opti
BIN_GEN_CACHED = wbc1_parallel_gen_cached
BIN_MINIMAL = wbc1_parallel_minimal

# Default target
all: basic cached

# Build all versions including new enhanced versions
all-new: basic cached new

# Build enhanced versions
new: basic-new cached-new

# Build minimal enhanced version (Mode 0 with multi-axis rotations only)
minimal: $(BIN_MINIMAL)

$(BIN_MINIMAL): $(SRC_MINIMAL)
	$(MPICC) $(CFLAGS) -o $(BIN_MINIMAL) $(SRC_MINIMAL) $(LDFLAGS)

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

# Build ultra-optimized cached version (Advanced optimizations)
cached-opti: $(BIN_CACHED_OPTI)

$(BIN_CACHED_OPTI): $(SRC_CACHED_OPTI)
	$(MPICC) $(CFLAGS) -o $(BIN_CACHED_OPTI) $(SRC_CACHED_OPTI) $(LDFLAGS)

# Build parametric generative cached version (Key-dependent operations)
gen-cached: $(BIN_GEN_CACHED)

$(BIN_GEN_CACHED): $(SRC_GEN_CACHED)
	$(MPICC) $(CFLAGS) -o $(BIN_GEN_CACHED) $(SRC_GEN_CACHED) $(LDFLAGS)

# Clean build artifacts
clean:
	rm -f $(BIN_BASIC) $(BIN_CACHED) $(BIN_ORIGINAL) $(BIN_ORIGINAL_CACHED) $(BIN_BASIC_NEW) $(BIN_CACHED_NEW) $(BIN_CACHED_OPTI) $(BIN_GEN_CACHED) $(BIN_MINIMAL) $(BIN_WBC0_CUDA) *.o

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

test-gen-cached: $(BIN_GEN_CACHED)
	@echo "========================================"
	@echo "Testing PARAMETRIC GENERATIVE Cached Version"
	@echo "========================================"
	@echo ""
	@echo "Test 1: Mode 1 (Full algorithm with key-dependent operations) with 16 rounds"
	mpirun --oversubscribe -n $(NUM_PROCS) ./$(BIN_GEN_CACHED) 1 256 0 16 1 10
	@echo ""
	@echo "Test 2: Mode 0 (Parametric operations) with 16 rounds"
	mpirun --oversubscribe -n $(NUM_PROCS) ./$(BIN_GEN_CACHED) 0 256 0 16 1 10
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
	@echo "  cached-opti - Build ultra-optimized version with rotation cache"
	@echo "  gen-cached  - Build parametric generative version (key-dependent operations)"
	@echo "  wbc0-original - Build wbc0 original cascading-key version"
	@echo "  wbc0-cuda          - Build CUDA variant of wbc0 (requires nvcc)"
	@echo "  wbc1-cascade-cuda  - Build CUDA variant of wbc1_cascade (requires nvcc)"
	@echo "  clean       - Remove all compiled binaries"
	@echo "  test        - Run tests for both versions"
	@echo "  test-basic  - Run test for basic version"
	@echo "  test-cached - Run test for cached version"
	@echo "  test-gen-cached - Run test for generative parametric version"
	@echo "  test-wbc0-original - Run test for wbc0 original cascading-key version"
	@echo "  test-wbc0-cuda - Run test for wbc0 CUDA variant"
	@echo "  benchmark   - Compare performance of both versions"
	@echo "  help        - Show this help message"
	@echo ""
	@echo "Usage examples:"
	@echo "  make                           # Build both versions"
	@echo "  make gen-cached                # Build parametric generative version"
	@echo "  make test NUM_PROCS=8          # Test with 8 MPI processes"
	@echo "  mpirun -n 4 ./wbc1_parallel 1 16    # Run basic: mode=1, rounds=16"
	@echo "  mpirun -n 4 ./wbc1_parallel_gen_cached 1 256 0 16 1 10  # Run generative"
	@echo ""
	@echo "Algorithm modes:"
	@echo "  Mode 0: Simplified (2 operations: permutation + rotation)"
	@echo "  Mode 1: Full (5 operations: permutation + XOR + S-box + diffusion + rotation)"
	@echo ""
	@echo "Versions:"
	@echo "  wbc1_parallel              - Basic version (1 op/round)"
	@echo "  wbc1_parallel_new          - Enhanced (32 ops/round)"
	@echo "  wbc1_parallel_cached_new   - Cached enhanced (32 ops/round)"
	@echo "  wbc1_parallel_cached_opti  - Ultra-optimized (rotation cache)"
	@echo "  wbc1_parallel_gen_cached   - Parametric generative (key-dependent ops)"
	@echo ""

.PHONY: all basic cached clean test test-basic test-cached benchmark help wbc0-original wbc0_original rebuild-wbc0-original rebuild_wbc0_original test-wbc0-original test_wbc0_original wbc0-cuda test-wbc0-cuda wbc1-cascade-cuda test-wbc1-cascade-cuda original test-original original-cached test-original-cached wbc2 test-wbc2


# Build original algorithm version (bit-by-bit key processing)
SRC_ORIGINAL = wbc1_original_parallel.c
BIN_ORIGINAL = wbc1_original_parallel

# Build WBC0 original algorithm version (cascading round-key variant)
SRC_WBC0_ORIGINAL = wbc0_original_parallel.c
BIN_WBC0_ORIGINAL = wbc0_original_parallel

# Build WBC0 CUDA variant (GPU-accelerated cyclic shift with CPU fallback)
NVCC ?= nvcc
NVCCFLAGS ?= -O3 -Xcompiler -fopenmp
SRC_WBC0_CUDA = wbc0_original_parallel_cuda.cu
BIN_WBC0_CUDA = wbc0_original_parallel_cuda

wbc0-original: $(BIN_WBC0_ORIGINAL)

wbc0_original: wbc0-original

rebuild-wbc0-original:
	rm -f $(BIN_WBC0_ORIGINAL)
	$(MAKE) wbc0-original

rebuild_wbc0_original: rebuild-wbc0-original

$(BIN_WBC0_ORIGINAL): $(SRC_WBC0_ORIGINAL)
	$(MPICC) $(CFLAGS) -o $@ $< $(LDFLAGS)

wbc0-cuda: $(BIN_WBC0_CUDA)

$(BIN_WBC0_CUDA): $(SRC_WBC0_CUDA)
	$(NVCC) $(NVCCFLAGS) -o $@ $< $(LDFLAGS) -lmpi

# Build WBC1-Cascade CUDA variant
SRC_WBC1_CASCADE_CUDA = wbc1_cascade_cuda.cu
BIN_WBC1_CASCADE_CUDA = wbc1_cascade_cuda

wbc1-cascade-cuda: $(BIN_WBC1_CASCADE_CUDA)

$(BIN_WBC1_CASCADE_CUDA): $(SRC_WBC1_CASCADE_CUDA)
	$(NVCC) -O2 -arch=sm_70 -o $@ $< -lssl -lcrypto -lm

test-wbc1-cascade-cuda: $(BIN_WBC1_CASCADE_CUDA)
	@echo "========================================"
	@echo "Testing WBC1-Cascade CUDA Variant"
	@echo "========================================"
	./$(BIN_WBC1_CASCADE_CUDA) --test

test-wbc0-cuda: $(BIN_WBC0_CUDA)
	@echo "========================================"
	@echo "Testing WBC0 CUDA Variant"
	@echo "========================================"
	@echo ""
	@echo "Test 1: Statistical test with auto block size, 1000KB"
	mpirun --oversubscribe -n 1 ./$(BIN_WBC0_CUDA) 1 256 0 0 1 1000 42 300
	@echo ""
	@echo "Test 2: Quick encrypt/decrypt demo"
	mpirun --oversubscribe -n 1 ./$(BIN_WBC0_CUDA) 0 256 0 128
	@echo ""

# Quick verification run for WBC0 original variant
test-wbc0-original: $(BIN_WBC0_ORIGINAL)
	@echo "========================================"
	@echo "Testing WBC0 ORIGINAL (Cascading Round-Key)"
	@echo "========================================"
	@echo ""
	@echo "Test 1: Statistical test with 128-bit blocks, 256-bit key, 1000KB data"
	mpirun --oversubscribe -n $(NUM_PROCS) ./$(BIN_WBC0_ORIGINAL) 1 256 0 128 1 1000
	@echo ""
	@echo "Test 2: Quick encrypt/decrypt demo"
	mpirun --oversubscribe -n 1 ./$(BIN_WBC0_ORIGINAL) 0 256 0 128
	@echo ""

test_wbc0_original: test-wbc0-original

original: $(BIN_ORIGINAL)

$(BIN_ORIGINAL): $(SRC_ORIGINAL)
	$(MPICC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Test original version
test-original: $(BIN_ORIGINAL)
	@echo "========================================"
	@echo "Testing ORIGINAL Algorithm Version"
	@echo "========================================"
	@echo ""
	@echo "Test 1: Text encryption with 32-bit blocks"
	mpirun --oversubscribe -n $(NUM_PROCS) ./$(BIN_ORIGINAL) 0 256 0 32
	@echo ""
	@echo "Test 2: Text encryption with 128-bit blocks"
	mpirun --oversubscribe -n $(NUM_PROCS) ./$(BIN_ORIGINAL) 0 256 0 128
	@echo ""

# Build original algorithm CACHED version (with operation caching)
SRC_ORIGINAL_CACHED = wbc1_original_cached.c
BIN_ORIGINAL_CACHED = wbc1_original_cached

original-cached: $(BIN_ORIGINAL_CACHED)

$(BIN_ORIGINAL_CACHED): $(SRC_ORIGINAL_CACHED)
	$(MPICC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Test original cached version
test-original-cached: $(BIN_ORIGINAL_CACHED)
	@echo "========================================"
	@echo "Testing ORIGINAL CACHED Algorithm Version"
	@echo "========================================"
	@echo ""
	@echo "Test 1: Text encryption with 32-bit blocks (cached)"
	mpirun --oversubscribe -n $(NUM_PROCS) ./$(BIN_ORIGINAL_CACHED) 0 256 0 32
	@echo ""
	@echo "Test 2: Text encryption with 128-bit blocks (cached)"
	mpirun --oversubscribe -n $(NUM_PROCS) ./$(BIN_ORIGINAL_CACHED) 0 256 0 128
	@echo ""
	@echo "Test 3: Print operations table"
	mpirun --oversubscribe -n 1 ./$(BIN_ORIGINAL_CACHED) 2 256 0 128
	@echo ""

# Build WBC2 enhanced algorithm version (with XOR, S-box, diffusion)
SRC_WBC2 = wbc2_original_parallel.c
BIN_WBC2 = wbc2_original_parallel

wbc2: $(BIN_WBC2)

$(BIN_WBC2): $(SRC_WBC2)
	$(MPICC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Test WBC2 version
test-wbc2: $(BIN_WBC2)
	@echo "========================================"
	@echo "Testing WBC2 ENHANCED Algorithm Version"
	@echo "========================================"
	@echo ""
	@echo "Test 1: Text encryption with 32-bit blocks"
	mpirun --oversubscribe -n $(NUM_PROCS) ./$(BIN_WBC2) 0 256 0 32 1 10
	@echo ""
	@echo "Test 2: Differential analysis with 128-bit blocks"
	mpirun --oversubscribe -n $(NUM_PROCS) ./$(BIN_WBC2) 1 256 0 128 1 100
	@echo ""
	@echo "Test 3: Operations table"
	mpirun --oversubscribe -n 1 ./$(BIN_WBC2) 2 256 0 64
	@echo ""
