import sys

def get_block(lines, start_idx, end_idx):
    return "".join([f"{i+1:4}  {lines[i]}" for i in range(start_idx, end_idx)])

with open('wbc1_cascade_mpi.c', 'r') as f:
    lines = f.readlines()

# parallel_cascade_encrypt starts at line 632
# parallel_cascade_decrypt starts at line 838

print("=== parallel_cascade_encrypt (around line 632) ===")
print(get_block(lines, 632 - 60, 632 + 60))

print("\n=== parallel_cascade_decrypt (around line 838) ===")
print(get_block(lines, 838 - 60, 838 + 60))
