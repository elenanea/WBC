#!/bin/bash
# Compilation test script for WBC1 C implementations
# This script verifies the C code can be compiled

echo "================================================"
echo "WBC1 C Implementation - Compilation Verification"
echo "================================================"
echo ""

# Check for required tools
echo "Checking for required tools..."

# Check for C compiler
if command -v gcc &> /dev/null; then
    echo "✓ GCC found: $(gcc --version | head -1)"
else
    echo "✗ GCC not found - please install gcc"
    exit 1
fi

# Check for OpenSSL
if command -v openssl &> /dev/null; then
    echo "✓ OpenSSL found: $(openssl version)"
else
    echo "✗ OpenSSL not found - please install openssl"
    exit 1
fi

# Check for OpenSSL development headers
if [ -f /usr/include/openssl/sha.h ] || [ -f /usr/local/include/openssl/sha.h ]; then
    echo "✓ OpenSSL headers found"
else
    echo "⚠ OpenSSL development headers not found"
    echo "  Install with: sudo apt-get install libssl-dev"
fi

# Check for MPI
if command -v mpicc &> /dev/null; then
    echo "✓ MPI compiler found: $(mpicc --version | head -1)"
    MPI_AVAILABLE=1
elif command -v mpicc.openmpi &> /dev/null; then
    echo "✓ MPI compiler found (OpenMPI)"
    MPI_AVAILABLE=1
elif command -v mpicc.mpich &> /dev/null; then
    echo "✓ MPI compiler found (MPICH)"
    MPI_AVAILABLE=1
else
    echo "⚠ MPI compiler not found"
    echo "  Install with: sudo apt-get install libopenmpi-dev"
    echo "  or:           sudo apt-get install mpich"
    MPI_AVAILABLE=0
fi

echo ""
echo "================================================"

if [ $MPI_AVAILABLE -eq 1 ]; then
    echo "All requirements met - ready to compile"
    echo ""
    echo "To compile:"
    echo "  make                    # Build both versions"
    echo "  make basic              # Build basic version"
    echo "  make cached             # Build cached version"
    echo ""
    echo "To run:"
    echo "  mpirun -n 4 ./wbc1_parallel 1 16"
    echo "  mpirun -n 4 ./wbc1_parallel_cached 1 16"
else
    echo "MPI not available - cannot compile parallel versions"
    echo ""
    echo "Please install MPI:"
    echo "  Ubuntu/Debian: sudo apt-get install libopenmpi-dev"
    echo "  RHEL/CentOS:   sudo yum install openmpi-devel"
    echo "  macOS:         brew install open-mpi"
fi

echo "================================================"
