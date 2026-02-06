# WBC1 Operations Table Reference

## Overview

The WBC1 cipher uses 127 permutation operations based on Rubik's Cube movements. This document explains how to view and understand the operations table.

## Quick Start

### View Operations Table

```bash
# Basic view (first 20 operations)
python3 show_operations_table.py

# Detailed view (all 127 operations with nested details)
python3 show_operations_table.py --detailed
```

## Operations Structure

### Total: 127 Operations

1. **Base Operations (87)**
2. **Dynamic Patterns (20)** - Operations 98-117
3. **Dynamic ASCII Operations (20)** - Operations 118-127

## Base Operations (IDs 0-97)

### Face Rotations (24 operations, IDs 0-23)
- **6 faces:** U (Up), D (Down), L (Left), R (Right), F (Front), B (Back)
- **4 directions:** ` ` (clockwise), `'` (counterclockwise), `2` (180°), `3` (270°)

Examples:
```
 0: 0x00  ('face', 'U', '', 'Rotate U face clockwise')
 1: 0x01  ('face', 'U', "'", 'Rotate U face counterclockwise')
 2: 0x02  ('face', 'U', '2', 'Rotate U face 180°')
```

### Slice Moves (12 operations, IDs 24-35)
- **3 slices:** M (Middle), E (Equator), S (Standing)
- **4 directions:** ` ` (standard), `'` (reverse), `2` (180°), `3` (270°)

Examples:
```
24: 0x18  ('slice', 'M', '', 'Rotate M slice')
25: 0x19  ('slice', 'M', "'", 'Rotate M slice reverse')
```

### Wide Moves (24 operations, IDs 36-59)
- **6 wide moves:** u, d, l, r, f, b
- **4 directions each**

Examples:
```
36: $ 0x24  ('wide', 'u', '', 'Wide move u')
37: % 0x25  ('wide', 'u', "'", 'Wide move u'')
```

### Cube Rotations (9 operations, IDs 60-68)
- **3 axes:** x, y, z
- **3 directions:** ` ` (standard), `'` (reverse), `2` (180°)

Examples:
```
60: < 0x3C  ('cube', 'x', '', 'Cube rotation x')
61: = 0x3D  ('cube', 'x', "'", 'Cube rotation x'')
```

### PLL Algorithms (12 operations, IDs 69-80)
Permutation of Last Layer algorithms:
- T-Perm, Y-Perm, J-Perm, F-Perm
- A-Perm, E-Perm, R-Perm, U-Perm
- V-Perm, N-Perm, Z-Perm, H-Perm

Examples:
```
69: E 0x45  ('alg', 'T-Perm', "R U R' U' R' F R2 U' R' U' R U R' F'", 'Algorithm: T-Perm')
74: J 0x4A  ('alg', 'E-Perm', "x' R U' R' D R U R' D' R U R' D R U' R' D' x", 'Algorithm: E-Perm')
```

### Patterns (8 operations, IDs 81-88)
Famous Rubik's Cube patterns:
- Checkerboard, Cube-in-Cube, Superflip
- Six-Spot, Tetris, Anaconda, Python, Black Mamba

Examples:
```
81: Q 0x51  ('pattern', 'Checkerboard', 'M2 E2 S2', 'Pattern: Checkerboard')
83: S 0x53  ('pattern', 'Superflip', 'U R2 F B R B2 R U2 L B2 R U' D' R2 F R' L B2 U2 F2', 'Pattern: Superflip')
```

### Swap Operations (6 operations, IDs 89-94)
Axis-based swaps:
- Axes 0, 1, 2
- Offsets 2, 3

Examples:
```
89: Y 0x59  ('swap', '0', '2', 'Swap axis=0, offset=2')
94: ^ 0x5E  ('swap', '2', '3', 'Swap axis=2, offset=3')
```

### Diagonal Flips (3 operations, IDs 95-97)
One per axis:

```
95: _ 0x5F  ('diagflip', '0', '', 'Diagonal flip on axis 0')
96: ` 0x60  ('diagflip', '1', '', 'Diagonal flip on axis 1')
97: a 0x61  ('diagflip', '2', '', 'Diagonal flip on axis 2')
```

## Dynamic Operations (IDs 98-127)

### Dynamic Patterns (20 operations, IDs 98-117)
Chains of 3-6 sub-operations from base operations.

Example - Operation 98 (ASCII 'b'):
```
98: b 0x62  ('dynamic', 6, [
    ('diagflip', '2', '', 'Diagonal flip on axis 2'),
    ('wide', 'f', "'", 'Wide move f''),
    ('face', 'D', "'", 'Rotate D face counterclockwise'),
    ('slice', 'S', "'", 'Rotate S slice reverse'),
    ('cube', 'y', '2', 'Cube rotation y2'),
    ('cube', 'x', '2', 'Cube rotation x2')
], 'Dynamic pattern 0')
```

### Dynamic ASCII Operations (20 operations, IDs 118-127)
Composed operations for printable characters v-~:

```
118: v 0x76  ('dynamic', 4, [...], 'Dynamic ASCII op 119')
...
126: ~ 0x7E  ('dynamic', 4, [
    ('face', 'D', '3', 'Rotate D face 270°'),
    ('alg', 'A-Perm', ..., 'Algorithm: A-Perm'),
    ('alg', 'U-Perm', ..., 'Algorithm: U-Perm'),
    ('wide', 'b', '2', 'Wide move b2')
], 'Dynamic ASCII op 127')
```

## Operation Types

| Type | Description | Count | IDs |
|------|-------------|-------|-----|
| face | Face rotations | 24 | 0-23 |
| slice | Slice moves | 12 | 24-35 |
| wide | Wide moves | 24 | 36-59 |
| cube | Cube rotations | 9 | 60-68 |
| alg | PLL Algorithms | 12 | 69-80 |
| pattern | Famous patterns | 8 | 81-88 |
| swap | Axis swaps | 6 | 89-94 |
| diagflip | Diagonal flips | 3 | 95-97 |
| dynamic | Composed operations | 40 | 98-127 |

## ASCII Mapping

Each operation ID (0-126) corresponds to an ASCII character:

- IDs 0-31: Non-printable (shown as space)
- IDs 32-126: Printable ASCII characters
- ID 127: DEL (not used, total is 127 operations)

Examples:
```
32: ' ' (space)
33: '!'
65: 'A'
97: 'a'
126: '~'
```

## Usage in WBC1 Cipher

### Original Algorithm
- Uses key bits to select operations
- Each key bit i: operation = operations[i % 127]
- 256 bits → 256 operation selections per block

### Enhanced Algorithm
- Uses round keys to select operations
- Each round: 32 operations from round key
- 16 rounds × 32 operations = 512 selections per block

## Output Format

The operations table uses Python tuple format:

```python
(type, param1, param2, description)
```

For dynamic operations:
```python
('dynamic', chain_length, [sub_operations...], description)
```

## Examples

### Simple Operation
```
0: 0x00 ('face', 'U', '', 'Rotate U face clockwise')
```

### Algorithm Operation
```
74: J 0x4A ('alg', 'E-Perm', "x' R U' R' D R U R' D' R U R' D R U' R' D' x", 'Algorithm: E-Perm')
```

### Dynamic Operation
```
98: b 0x62 ('dynamic', 6, [
    ('diagflip', '2', '', 'Diagonal flip on axis 2'),
    ('wide', 'f', "'", 'Wide move f''),
    ...
], 'Dynamic pattern 0')
```

## See Also

- `show_operations_table.py` - Script to display the table
- `WBC1_MATHEMATICAL_DESCRIPTION.md` - Mathematical formulation
- `WBC1_DETAILED_ALGORITHM_STEPS.md` - Algorithm step-by-step guide
- `operations_table_output.txt` - Sample output

## Notes

1. Operations are deterministic - same for all WBC1 instances
2. Operations can be applied in forward or reverse
3. Dynamic operations add complexity through composition
4. Total space: 127 unique operations for high entropy
