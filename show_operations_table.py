#!/usr/bin/env python3
"""
Display WBC1 Operations Table

This script displays the complete operations table used in WBC1 cipher
in the format: (id, ascii, hex, type, args, description)
"""

def build_operations_table():
    """
    Build the complete table of 127 operations used in WBC1 cipher.
    Returns a list of tuples: (id, ascii_char, hex_code, operation_details)
    """
    
    faces = ['U', 'D', 'L', 'R', 'F', 'B']
    directions = ['', "'", '2', '3']
    slices = ['M', 'E', 'S']
    wide_moves = ['u', 'd', 'l', 'r', 'f', 'b']
    cube_rot = ['x', 'y', 'z']
    
    # PLL Algorithms
    algs = [
        ("T-Perm", "R U R' U' R' F R2 U' R' U' R U R' F'"),
        ("Y-Perm", "F R U' R' U' R U R' F' R U R' U' R' F R F'"),
        ("J-Perm", "R U R' F' R U R' U' R' F R2 U' R' U'"),
        ("F-Perm", "R' U' F' R U R' U' R' F R2 U' R' U' R U R' U R"),
        ("A-Perm", "x' R2 D2 R' U' R D2 R' U R' x"),
        ("E-Perm", "x' R U' R' D R U R' D' R U R' D R U' R' D' x"),
        ("R-Perm", "R U' R' U' R U R D R' U' R D' R' U2 R'"),
        ("U-Perm", "R U' R U R U R U' R' U' R2"),
        ("V-Perm", "R' U R' U' y R' F' R2 U' R' U R' F R F"),
        ("N-Perm", "R U R' U R U R' F' R U R' U' R' F R2 U' R' U2 R U' R'"),
        ("Z-Perm", "M2 U M2 U M' U2 M2 U2 M' U2"),
        ("H-Perm", "M2 U M2 U2 M2 U M2")
    ]
    
    # Patterns
    patterns = [
        ("Checkerboard", "M2 E2 S2"),
        ("Cube-in-Cube", "F L F U' R U F2 L2 U' L' B D' B' L2 U"),
        ("Superflip", "U R2 F B R B2 R U2 L B2 R U' D' R2 F R' L B2 U2 F2"),
        ("Six-Spot", "U D' R L' F B' U D'"),
        ("Tetris", "L R F B U' D' L' R'"),
        ("Anaconda", "L U B' U' R L' B R' F B' D R D' F'"),
        ("Python", "F2 R' B' U R' L F' L F' B D' R B L2"),
        ("Black Mamba", "R D L F' R U' R' F L' D' R' U")
    ]
    
    # Build base operations list
    base_ops = []
    
    # Face rotations (24 operations: 6 faces × 4 directions)
    for face in faces:
        for dir in directions:
            if dir == '':
                desc = f"Rotate {face} face clockwise"
            elif dir == "'":
                desc = f"Rotate {face} face counterclockwise"
            elif dir == '2':
                desc = f"Rotate {face} face 180°"
            else:  # '3'
                desc = f"Rotate {face} face 270°"
            base_ops.append(('face', face, dir, desc))
    
    # Slice moves (12 operations: 3 slices × 4 directions)
    for sl in slices:
        for dir in directions:
            if dir == '':
                desc = f"Rotate {sl} slice"
            elif dir == "'":
                desc = f"Rotate {sl} slice reverse"
            elif dir == '2':
                desc = f"Rotate {sl} slice 180°"
            else:
                desc = f"Rotate {sl} slice 270°"
            base_ops.append(('slice', sl, dir, desc))
    
    # Wide moves (24 operations: 6 wide × 4 directions)
    for wide in wide_moves:
        for dir in directions:
            desc = f"Wide move {wide}{dir}"
            base_ops.append(('wide', wide, dir, desc))
    
    # Cube rotations (9 operations: 3 axes × 3 directions, excluding identity)
    for rot in cube_rot:
        for dir in ['', "'", '2']:
            desc = f"Cube rotation {rot}{dir}"
            base_ops.append(('cube', rot, dir, desc))
    
    # Algorithms (12 operations)
    for alg_name, moves in algs:
        base_ops.append(('alg', alg_name, moves, f"Algorithm: {alg_name}"))
    
    # Patterns (8 operations)
    for pattern_name, moves in patterns:
        base_ops.append(('pattern', pattern_name, moves, f"Pattern: {pattern_name}"))
    
    # Swap operations (6 operations)
    for axis in range(3):
        for offset in [2, 3]:
            base_ops.append(('swap', str(axis), str(offset), f"Swap axis={axis}, offset={offset}"))
    
    # Diagonal flip (3 operations)
    for axis in range(3):
        base_ops.append(('diagflip', str(axis), '', f"Diagonal flip on axis {axis}"))
    
    # Dynamic patterns with sub-operations
    dynamic_patterns = []
    for i in range(20):
        # Create chains of 3-6 random operations
        import random
        random.seed(i)  # Deterministic
        chain_length = random.randint(3, 6)
        chain_indices = [random.randint(0, len(base_ops)-1) for _ in range(chain_length)]
        dynamic_patterns.append(('dynamic', str(i), chain_indices, f"Dynamic pattern {i}"))
    
    base_ops.extend(dynamic_patterns)
    
    # Now create final 127 operations (base_ops should be 107, we'll compose to get 127)
    # For simplicity, we'll use first 127 operations or pad with compositions
    operations = []
    
    for i in range(127):
        if i < len(base_ops):
            op = base_ops[i]
        else:
            # Create composed operations
            import random
            random.seed(i)
            chain_length = random.randint(2, 4)
            chain = [random.randint(0, len(base_ops)-1) for _ in range(chain_length)]
            op = ('dynamic', f'ascii_{i}', chain, f'Dynamic ASCII op {i+1}')
        
        # ASCII character
        if i >= 32 and i < 127:
            ascii_char = chr(i)
        else:
            ascii_char = '.'
        
        # Hex code
        hex_code = f"0x{i:02X}"
        
        operations.append((i, ascii_char, hex_code, op))
    
    return operations


def format_operation_detail(op_tuple):
    """
    Format operation detail as Python tuple string.
    op_tuple is (type, param1, param2, desc) or (type, param1, chain_list, desc)
    """
    op_type, param1, param2, desc = op_tuple
    
    if op_type == 'dynamic' and isinstance(param2, list):
        # Dynamic operation with chain
        chain_str = ', '.join(str(x) for x in param2[:6])  # Show first 6
        return f"('{op_type}', {len(param2)}, [{chain_str}...], '{desc}')"
    else:
        # Regular operation
        if param2:
            return f"('{op_type}', '{param1}', '{param2}', '{desc}')"
        else:
            return f"('{op_type}', '{param1}', '{desc}')"


def print_operations_table():
    """
    Print the operations table in the requested format.
    """
    operations = build_operations_table()
    
    print("=" * 100)
    print("WBC1 ROTATION OPERATIONS TABLE / ТАБЛИЦА ОПЕРАЦИЙ ПЕРЕСТАНОВОК WBC1")
    print("=" * 100)
    print(f"{'ID':<5} {'ASCII':<7} {'Hex':<8} {'Operation Details'}")
    print("-" * 100)
    
    for op_id, ascii_char, hex_code, op_details in operations[:20]:  # Show first 20
        op_type, param1, param2, desc = op_details
        
        # Format the operation display
        if op_type == 'dynamic' and isinstance(param2, list):
            # Show dynamic with chain
            detail_str = f"('{op_type}', {len(param2)}, [chain...], '{desc}')"
        else:
            if param2:
                detail_str = f"('{op_type}', '{param1}', '{param2}', '{desc}')"
            else:
                detail_str = f"('{op_type}', '{param1}', '{desc}')"
        
        # Handle multi-line for long descriptions
        if len(detail_str) > 80:
            detail_str = detail_str[:77] + "..."
        
        print(f"{op_id:<5} {ascii_char:<7} {hex_code:<8} {detail_str}")
    
    print(f"\n... (showing first 20 of 127 operations) ...")
    print("\n" + "=" * 100)
    print(f"Total operations: {len(operations)}")
    print("=" * 100)


def print_detailed_operations_table():
    """
    Print the operations table with full nested details in the requested format.
    Format: ID: ASCII HEX (type, args, description)
    """
    operations = build_operations_table()
    
    print("=" * 140)
    print("WBC1 ROTATION OPERATIONS TABLE / ТАБЛИЦА ОПЕРАЦИЙ ПЕРЕСТАНОВОК")
    print("Format: ID, ASCII, Hex, (type, args, description)")
    print("=" * 140)
    
    for op_id, ascii_char, hex_code, op_details in operations:
        op_type, param1, param2, desc = op_details
        
        # Format: ID: ASCII HEX (type, params...)
        if ascii_char in ['\'', '"', '\\']:
            ascii_display = f"'{ascii_char}'"
        else:
            ascii_display = ascii_char if ascii_char != '.' else ' '
        
        print(f"{op_id:3d}: {ascii_display:>3s} {hex_code:6s} ", end="")
        
        if op_type == 'dynamic' and isinstance(param2, list):
            # Dynamic operation with sub-operations
            print(f"('{op_type}', {len(param2)}, [", end="")
            
            # Show chain details
            base_ops = build_operations_table()
            chain_details = []
            for idx in param2[:6]:  # Limit to first 6
                if idx < len(base_ops):
                    _, _, _, sub_op = base_ops[idx]
                    sub_type, sub_p1, sub_p2, sub_desc = sub_op
                    if sub_p2 and not isinstance(sub_p2, list):
                        chain_details.append(f"('{sub_type}', '{sub_p1}', '{sub_p2}', '{sub_desc}')")
                    else:
                        chain_details.append(f"('{sub_type}', '{sub_p1}', '{sub_desc}')")
            
            print(", ".join(chain_details), end="")
            if len(param2) > 6:
                print(", ...", end="")
            print(f"], '{desc}')")
        else:
            # Regular operation
            if param2:
                print(f"('{op_type}', '{param1}', '{param2}', '{desc}')")
            else:
                print(f"('{op_type}', '{param1}', '{desc}')")
    
    print("=" * 140)
    print(f"Total operations: {len(operations)}")
    print("Base operations (face, slice, wide, cube, alg, pattern, swap, diagflip): 87")
    print("Dynamic patterns with sub-operation chains: 20")
    print("Dynamic ASCII operations (composed): 20")
    print("=" * 140)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--detailed':
        print_detailed_operations_table()
    else:
        print_operations_table()
        print("\nUse --detailed flag to see full nested operation details")
        print(f"Example: {sys.argv[0]} --detailed")
