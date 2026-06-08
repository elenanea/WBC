"""
RubikCrypt — Web Application
Algorithms: PWBC1, PWBC1.1, PWBC2, PWBC2.1, WBC1, WBC1.0, WBC1.1
"""
# WBC1  = wbc1_cascade_no_mix_FIXED.c (без перемешивания)
# WBC1.0 = wbc1_fixed_cascade.c (с перемешиванием)

import sys
import os
import subprocess
import secrets
import io
import base64
from pathlib import Path
from flask import Flask, request, jsonify, render_template, send_file

# ── Paths ────────────────────────────────────────────────────────────────────
WEBAPP_DIR = Path(__file__).parent

CLI_WBC1       = str(WEBAPP_DIR / "cli_wbc1_nomix")      # WBC1  = wbc1_cascade_no_mix_FIXED.c
CLI_WBC10      = str(WEBAPP_DIR / "cli_wbc1_casc")       # WBC1.0 = wbc1_fixed_cascade.c
CLI_WBC11      = str(WEBAPP_DIR / "cli_wbc1_casc2")      # WBC1.1 = wbc1_fixed_cascade2.c
CLI_WBC2S      = str(WEBAPP_DIR / "cli_wbc2_serial")     # WBC2 = wbc2_serial.c (sequential)
CLI_PWBC0      = str(WEBAPP_DIR / "cli_pwbc0")        # PWBC1.1 = wbc0_original_parallel.c
CLI_PWBC1      = str(WEBAPP_DIR / "cli_pwbc1")        # PWBC1   = wbc1_original_parallel.c
CLI_PWBC2      = str(WEBAPP_DIR / "cli_pwbc2")        # PWBC2  = wbc2_original_parallel.c
CLI_PWBC21     = str(WEBAPP_DIR / "cli_pwbc21")       # PWBC2.1 = wbc1_parallel_cached.c

# ── Algorithm registry ────────────────────────────────────────────────────────
# enc_modes: list of accepted mode strings for this algorithm
# algo_modes: list of algorithm-level modes (PWBC2.1 only)
# parallel: True → uses mpirun
ALGORITHMS = {
    # ── Sequential ────────────────────────────────────────────────────────────
    "WBC1": {
        "label": "WBC1 (wbc1_cascade_no_mix_FIXED)",
        "desc":  "Cascade WBC1 WITHOUT mixing — simplified key evolution",
        "backend": "c_wbc1",
        "parallel": False,
        "enc_modes": ["CTR_HMAC", "ECB", "CBC", "CTR", "OFB", "CFB"],
        "algo_modes": [],
        "has_num_rounds": False,
    },
    "WBC2": {
        "label": "WBC2 (wbc2_serial)",
        "desc":  "WBC2: 127 Rubik's cube ops + S-box + XOR + cumulative diffusion (32 rounds, 16-byte block)",
        "backend": "c_wbc2s",
        "parallel": False,
        "enc_modes": ["CTR_HMAC", "ECB", "CBC", "CTR", "OFB", "CFB"],
        "algo_modes": [],
        "has_num_rounds": False,
    },
    "WBC1.0": {
        "label": "WBC1.0 (wbc1_fixed_cascade)",
        "desc":  "Cascade WBC1 with mixing — key evolves after each block",
        "backend": "c_wbc10",
        "parallel": False,
        "enc_modes": ["CTR_HMAC", "ECB", "CBC", "CTR", "OFB", "CFB"],
        "algo_modes": [],
        "has_num_rounds": False,
    },
    "WBC1.1": {
        "label": "WBC1.1 (wbc1_fixed_cascade2)",
        "desc":  "Dual cascade WBC1 — Pass 1: forward cascade with key evolution; Pass 2: reverse ECB cascade",
        "backend": "c_wbc11",
        "parallel": False,
        "enc_modes": ["CTR_HMAC", "ECB", "CBC", "CTR", "OFB", "CFB"],
        "algo_modes": [],
        "has_num_rounds": False,
    },
    # ── Parallel ──────────────────────────────────────────────────────────────
    "PWBC1": {
        "label": "PWBC1 (wbc1_original_parallel)",
        "desc":  "Enhanced parallel WBC1 — 32 rounds, sub-block optimisation",
        "backend": "c_pwbc1",
        "parallel": True,
        "enc_modes": ["—"],
        "algo_modes": [],
        "has_num_rounds": False,
    },
    "PWBC1.1": {
        "label": "PWBC1.1 (wbc0_original_parallel)",
        "desc":  "Original parallel WBC1 — 16 rounds, 3D cubic block",
        "backend": "c_pwbc0",
        "parallel": True,
        "enc_modes": ["—"],
        "algo_modes": ["0", "1", "2"],  # shift_mode: 0=baseline,1=uniform,2=alpha+beta
        "has_num_rounds": False,
    },
    "PWBC2": {
        "label": "PWBC2 (wbc2_original_parallel)",
        "desc":  "WBC2: key-dependent S-box + XOR rounds + two-layer diffusion",
        "backend": "c_pwbc2",
        "parallel": True,
        "enc_modes": ["—"],
        "algo_modes": [],
        "has_num_rounds": True,   # num_rounds 1-100, default 10
    },
    "PWBC2.1": {
        "label": "PWBC2.1 (wbc1_parallel_cached)",
        "desc":  "WBC1 with operation caching — two algorithm modes: Simplified/Full",
        "backend": "c_pwbc21",
        "parallel": True,
        "enc_modes": ["—"],
        "algo_modes": ["FULL", "SIMPLIFIED"],
        "has_num_rounds": False,
    },
}

# ── Serial CLI runner ─────────────────────────────────────────────────────────
def _run_serial(binary: str, key_hex: str, op: str,
                enc_mode: str, data: bytes) -> bytes:
    """op='e'|'d', enc_mode passed as argv[1] e.g. 'CTR_HMAC'|'ECB'|'CBC'…"""
    header = f"{key_hex}\n{op}\n".encode()
    r = subprocess.run([binary, enc_mode or "CTR_HMAC"], input=header + data,
                       capture_output=True, timeout=120)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.decode(errors='replace').strip())
    return r.stdout


# ── MPI CLI runner ────────────────────────────────────────────────────────────
def _run_mpi(binary: str, key_hex: str, op: str,
             extra_line: str, data: bytes, nprocs: int) -> bytes:
    """extra_line: algo_mode for PWBC2.1, empty for others."""
    header = f"{key_hex}\n{op}\n"
    if extra_line:
        header += f"{extra_line}\n"
    r = subprocess.run(
        ["mpirun", "--allow-run-as-root", "--oversubscribe",
         "-n", str(max(1, min(nprocs, 8))), binary],
        input=header.encode() + data,
        capture_output=True, timeout=300,
    )
    if r.returncode != 0:
        raise RuntimeError(r.stderr.decode(errors='replace').strip())
    return r.stdout


# ── Dispatch ──────────────────────────────────────────────────────────────────
_SERIAL_BINARIES = {
    "c_wbc1":  CLI_WBC1,
    "c_wbc10": CLI_WBC10,
    "c_wbc11": CLI_WBC11,
    "c_wbc2s": CLI_WBC2S,
}
_MPI_BINARIES = {
    "c_pwbc0":  CLI_PWBC0,
    "c_pwbc1":  CLI_PWBC1,
    "c_pwbc2":  CLI_PWBC2,
    "c_pwbc21": CLI_PWBC21,
}


def do_op(algo_id: str, key_hex: str, op: str,
          enc_mode: str, algo_mode: str, nprocs: int,
          data: bytes, num_rounds: int = 10) -> bytes:
    alg = ALGORITHMS[algo_id]
    be  = alg["backend"]
    if be in _SERIAL_BINARIES:
        return _run_serial(_SERIAL_BINARIES[be], key_hex, op, enc_mode or "CTR_HMAC", data)
    if be in _MPI_BINARIES:
        if be == "c_pwbc21":
            extra = algo_mode or "FULL"
        elif be == "c_pwbc0":
            extra = algo_mode or "0"   # shift_mode
        elif be == "c_pwbc2":
            extra = str(max(1, min(100, num_rounds)))  # num_rounds
        else:
            extra = ""
        return _run_mpi(_MPI_BINARIES[be], key_hex, op, extra, data, nprocs)
    raise RuntimeError(f"Unknown backend: {be!r}")


# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__, template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024


@app.route("/")
def index():
    algos = [
        {
            "id": k,
            "label": v["label"],
            "desc": v["desc"],
            "parallel": v["parallel"],
            "enc_modes": v["enc_modes"],
            "algo_modes": v["algo_modes"],
            "has_num_rounds": v.get("has_num_rounds", False),
        }
        for k, v in ALGORITHMS.items()
    ]
    return render_template("index.html", algorithms=algos)


@app.route("/api/generate-key")
def generate_key():
    return jsonify({"key": secrets.token_bytes(32).hex()})


@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    return _handle_op("encrypt")


@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    return _handle_op("decrypt")


def _handle_op(op: str):
    algo_id    = request.form.get("algorithm", "WBC1")
    key_hex    = (request.form.get("key", "") or "").strip().lower()
    input_type = request.form.get("input_type", "text")
    enc_mode   = (request.form.get("enc_mode", "CTR_HMAC") or "CTR_HMAC").strip()
    algo_mode  = (request.form.get("algo_mode", "0") or "0").strip()
    try:
        nprocs = int(request.form.get("nprocs", "4"))
    except ValueError:
        nprocs = 4
    try:
        num_rounds = int(request.form.get("num_rounds", "10"))
        num_rounds = max(1, min(100, num_rounds))
    except ValueError:
        num_rounds = 10

    if algo_id not in ALGORITHMS:
        return jsonify({"error": f"Неизвестный алгоритм: {algo_id}"}), 400
    if len(key_hex) != 64:
        return jsonify({"error": "Ключ должен быть 64 hex-символа (256 бит)"}), 400
    try:
        bytes.fromhex(key_hex)
    except ValueError:
        return jsonify({"error": "Неверный HEX-ключ"}), 400

    # ── read data ─────────────────────────────────────────────────────────
    original_filename = None
    if input_type == "text":
        text = request.form.get("text_input", "")
        if not text:
            return jsonify({"error": "Введите текст"}), 400
        data = text.encode("utf-8")
    elif input_type in ("file", "file_text_decrypt"):
        f = request.files.get("file_input")
        if not f or not f.filename:
            return jsonify({"error": "Файл не выбран"}), 400
        data = f.read()
        if not data:
            return jsonify({"error": "Файл пустой"}), 400
        original_filename = f.filename
    else:
        return jsonify({"error": "Неизвестный input_type"}), 400

    # ── run cipher ────────────────────────────────────────────────────────
    try:
        result = do_op(algo_id, key_hex,
                       'e' if op == "encrypt" else 'd',
                       enc_mode, algo_mode, nprocs, data, num_rounds)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    # ── return result ─────────────────────────────────────────────────────
    if input_type == "text":
        if op == "encrypt":
            return jsonify({
                "hex":    result.hex(),
                "base64": base64.b64encode(result).decode(),
                "length": len(result),
            })
        else:
            try:
                decoded = result.decode("utf-8")
            except UnicodeDecodeError:
                decoded = result.decode("latin-1")
            return jsonify({"text": decoded, "length": len(result)})
    else:
        # file_text_decrypt → return raw bytes
        if input_type == "file_text_decrypt":
            buf = io.BytesIO(result); buf.seek(0)
            return send_file(buf, as_attachment=False,
                             mimetype="application/octet-stream")
        if op == "encrypt":
            out_name = (original_filename or "data") + ".rubikcrypt"
        else:
            out_name = original_filename or "decrypted"
            if out_name.endswith(".rubikcrypt"):
                out_name = out_name[:-11]
        buf = io.BytesIO(result); buf.seek(0)
        return send_file(buf, as_attachment=True,
                         download_name=out_name,
                         mimetype="application/octet-stream")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=False)
