#!/usr/bin/env python3
import json
import os
import re
import subprocess
import time

ALGOS = [
    ("wbc0_original_parallel", ["mpirun", "--oversubscribe", "-n", "8", "./wbc0_original_parallel", "0", "256", "0", "128", "1", "{size}"]),
    ("wbc1_original_parallel", ["mpirun", "--oversubscribe", "-n", "8", "./wbc1_original_parallel", "0", "256", "0", "128", "1", "{size}"]),
    ("wbc1_parallel", ["mpirun", "--oversubscribe", "-n", "8", "./wbc1_parallel", "1", "256", "0", "16", "1", "{size}"]),
    ("wbc1_parallel_cached", ["mpirun", "--oversubscribe", "-n", "8", "./wbc1_parallel_cached", "1", "256", "0", "16", "1", "{size}"]),
    ("wbc1_parallel_new", ["mpirun", "--oversubscribe", "-n", "8", "./wbc1_parallel_new", "1", "256", "0", "16", "1", "{size}"]),
    ("wbc1_parallel_cached_new", ["mpirun", "--oversubscribe", "-n", "8", "./wbc1_parallel_cached_new", "1", "256", "0", "16", "1", "{size}"]),
    ("wbc1_parallel_cached_opti", ["mpirun", "--oversubscribe", "-n", "8", "./wbc1_parallel_cached_opti", "1", "256", "0", "16", "1", "{size}"]),
    ("wbc1_parallel_gen_cached", ["mpirun", "--oversubscribe", "-n", "8", "./wbc1_parallel_gen_cached", "1", "256", "0", "16", "1", "{size}"]),
    ("wbc1_parallel_minimal", ["mpirun", "--oversubscribe", "-n", "8", "./wbc1_parallel_minimal", "1", "256", "0", "16", "1", "{size}"]),
    ("wbc2_original_parallel", ["mpirun", "--oversubscribe", "-n", "8", "./wbc2_original_parallel", "0", "256", "0", "128", "1", "{size}", "10"]),
]

if os.path.exists("./wbc0_original_parallel_cuda"):
    ALGOS.append(("wbc0_original_parallel_cuda", ["mpirun", "--oversubscribe", "-n", "1", "./wbc0_original_parallel_cuda", "1", "256", "0", "0", "1", "{size}", "42", "100"]))

ENC_PATTERNS = [
    r"Encryption time:\s*([0-9]+(?:\.[0-9]+)?)\s*seconds",
    r"Encryption time:\s*([0-9]+(?:\.[0-9]+)?)\s*sec",
]
DEC_PATTERNS = [
    r"Decryption time:\s*([0-9]+(?:\.[0-9]+)?)\s*seconds",
    r"Decryption time:\s*([0-9]+(?:\.[0-9]+)?)\s*sec",
]


def pick_value(text, patterns):
    for pattern in patterns:
        m = re.search(pattern, text, flags=re.IGNORECASE)
        if m:
            return float(m.group(1))
    return None


def _to_text(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def run_suite(sizes, timeout_s=180):
    results = []
    for size in sizes:
        for algo_name, cmd_tpl in ALGOS:
            cmd = [part.format(size=size) for part in cmd_tpl]
            started = time.time()
            try:
                cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
                output = (cp.stdout or "") + "\n" + (cp.stderr or "")
                enc_s = pick_value(output, ENC_PATTERNS)
                dec_s = pick_value(output, DEC_PATTERNS)
                record = {
                    "algorithm": algo_name,
                    "size_kb": size,
                    "command": " ".join(cmd),
                    "returncode": cp.returncode,
                    "enc_s": enc_s,
                    "dec_s": dec_s,
                    "enc_kbs": (size / enc_s) if enc_s else None,
                    "dec_kbs": (size / dec_s) if dec_s else None,
                    "ok": cp.returncode == 0 and enc_s is not None and dec_s is not None,
                    "elapsed_wall_s": round(time.time() - started, 3),
                    "tail": output[-1200:],
                }
                print(f"{algo_name} size={size}KB rc={cp.returncode} enc={enc_s} dec={dec_s}")
            except subprocess.TimeoutExpired as e:
                tail = (_to_text(e.stdout) + "\n" + _to_text(e.stderr))[-1200:]
                record = {
                    "algorithm": algo_name,
                    "size_kb": size,
                    "command": " ".join(cmd),
                    "returncode": -1,
                    "enc_s": None,
                    "dec_s": None,
                    "enc_kbs": None,
                    "dec_kbs": None,
                    "ok": False,
                    "timeout": True,
                    "elapsed_wall_s": round(time.time() - started, 3),
                    "tail": tail,
                }
                print(f"{algo_name} size={size}KB TIMEOUT")
            results.append(record)
    return results


if __name__ == "__main__":
    sizes = [1000]
    out_path = "benchmark_results_1000kb_8proc.json"
    data = run_suite(sizes=sizes, timeout_s=180)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    ok_count = sum(1 for item in data if item.get("ok"))
    print(f"Saved: {out_path}")
    print(f"OK: {ok_count}/{len(data)}")
