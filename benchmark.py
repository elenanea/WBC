import subprocess
import re

def run_benchmark(n):
    results = []
    for i in range(1, 5):
        try:
            # Using printf '3\n1\n6\n' as specified in the prompt
            cmd = f"printf '3\\n1\\n6\\n' | timeout 120 mpirun --allow-run-as-root -n {n} ./wbc1_cascade_mpi --single 2>/dev/null"
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            
            for line in stdout.splitlines():
                line = line.strip()
                if line.startswith('9765.62'):
                    parts = line.split()
                    if len(parts) >= 7:
                        # size, enc_s, enc_kbs, dec_kbs, enc_mbps, dec_mbps, status
                        res = {
                            'n': n,
                            'r': i,
                            'enc_kbs': float(parts[2]),
                            'dec_kbs': float(parts[3]),
                            'enc_mbps': float(parts[4]),
                            'dec_mbps': float(parts[5]),
                            'status': parts[6]
                        }
                        results.append(res)
                        print(f"n{n} R{i} {res['enc_kbs']} {res['dec_kbs']} {res['enc_mbps']} {res['dec_mbps']} {res['status']}")
                        break
        except Exception as e:
            print(f"Error in n={n} R{i}: {e}")
    return results

res_n1 = run_benchmark(1)
res_n2 = run_benchmark(2)

if res_n1:
    avg_n1 = sum(r['enc_kbs'] for r in res_n1) / len(res_n1)
    print(f"Average enc_kbs for n=1: {avg_n1:.2f}")
else:
    print("No data for n=1")

if res_n2:
    avg_n2 = sum(r['enc_kbs'] for r in res_n2) / len(res_n2)
    print(f"Average enc_kbs for n=2: {avg_n2:.2f}")
else:
    print("No data for n=2")
