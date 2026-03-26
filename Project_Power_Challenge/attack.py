import socket
import base64
import numpy as np
import os
import time
from collections import Counter

HOST = "X.X.X.X"
PORT = X

NUM_TRACES = 500
DELAY_BETWEEN_TRACES = 0.03
TRACE_DTYPE = np.float64

AES_SBOX = np.array([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
], dtype=np.uint8)

HW = np.array([bin(x).count("1") for x in range(256)], dtype=np.uint8)


def recv_all(sock, chunk_size=8192):
    data = b""
    while True:
        chunk = sock.recv(chunk_size)
        if not chunk:
            break
        data += chunk
    return data


def connect_option1(plaintext: bytes, debug: bool = False) -> bytes:
    if len(plaintext) != 16:
        raise ValueError("plaintext must be exactly 16 bytes")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        banner = s.recv(1024)
        s.sendall(b"1")

        prompt = s.recv(1024)
        s.sendall(plaintext + b"\n")

        leakage = recv_all(s)

    if debug:
        print("[DEBUG] banner:")
        print(banner.decode(errors="ignore"))
        print("[DEBUG] prompt:")
        print(prompt.decode(errors="ignore"))
        print("[DEBUG] leakage len:", len(leakage))
        print("[DEBUG] leakage preview:", leakage[:120])

    return leakage


def connect_option2(key_hex_ascii: bytes, debug: bool = False) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        banner = s.recv(1024)
        s.sendall(b"2")

        prompt = s.recv(1024)
        s.sendall(key_hex_ascii)

        response = recv_all(s)

    if debug:
        print("[DEBUG] banner:")
        print(banner.decode(errors="ignore"))
        print("[DEBUG] prompt:")
        print(prompt.decode(errors="ignore"))
        print("[DEBUG] response:", response)

    return response


def decode_trace(leakage_b64: bytes, debug: bool = False) -> np.ndarray:
    raw = base64.b64decode(leakage_b64)

    if debug:
        print(f"[DEBUG] raw decoded bytes length: {len(raw)}")

        for dtype in (np.float32, np.float64, np.int16):
            try:
                if len(raw) % np.dtype(dtype).itemsize != 0:
                    print(f"[DEBUG] {dtype}: incompatible length")
                    continue

                arr = np.frombuffer(raw, dtype=dtype)
                finite = np.isfinite(arr)
                finite_ratio = finite.mean() if len(arr) else 0

                print(
                    f"[DEBUG] {dtype}: len={len(arr)}, "
                    f"finite_ratio={finite_ratio:.4f}, "
                    f"min={np.nanmin(arr):.6g}, max={np.nanmax(arr):.6g}, "
                    f"first10={arr[:10]}"
                )
            except Exception as e:
                print(f"[DEBUG] {dtype}: error {e}")

    return np.frombuffer(raw, dtype=TRACE_DTYPE)


def verify_protocol():
    print("[*] Verifying option 1...")
    leakage = connect_option1(b"0123456789ABCDEF", debug=True)
    if not leakage:
        raise RuntimeError("Option 1 returned empty data.")

    trace = decode_trace(leakage, debug=True)
    print("[+] Decoded trace length:", len(trace))
    print("[+] First 10 samples:", trace[:10])

    print("[*] Verifying option 2...")
    resp = connect_option2(b"00112233445566778899AABBCCDDEEFF", debug=True)
    print("[+] Option 2 sample response:", resp.decode(errors="ignore").strip())


def collect_traces(num_traces=1000, delay=0.02):
    plaintexts = []
    traces = []

    for i in range(num_traces):
        pt = os.urandom(16)

        try:
            leakage = connect_option1(pt, debug=(i == 0))
            if not leakage:
                print(f"[-] Empty leakage at trace {i}")
                continue

            trace = decode_trace(leakage, debug=(i == 0))

            if len(trace) == 0:
                print(f"[-] Empty decoded trace at trace {i}")
                continue

            if not np.all(np.isfinite(trace)):
                print(f"[-] Non-finite values in trace {i}")
                continue

            plaintexts.append(np.frombuffer(pt, dtype=np.uint8))
            traces.append(trace)

        except Exception as e:
            print(f"[-] Trace {i} failed: {e}")
            continue

        if (i + 1) % 50 == 0:
            print(f"[+] Collected {i+1}/{num_traces} traces")

        time.sleep(delay)

    if not traces:
        raise RuntimeError("No valid traces collected.")

    lengths = [len(t) for t in traces]
    print("[+] Min trace length:", min(lengths))
    print("[+] Max trace length:", max(lengths))
    print("[+] Most common lengths:", Counter(lengths).most_common(10))

    common_len = Counter(lengths).most_common(1)[0][0]
    print("[+] Keeping only traces of most common length:", common_len)

    filt_pts = []
    filt_traces = []
    for pt, tr in zip(plaintexts, traces):
        if len(tr) == common_len:
            filt_pts.append(pt)
            filt_traces.append(tr)

    plaintexts = np.array(filt_pts, dtype=np.uint8)
    traces = np.array(filt_traces, dtype=np.float64)

    print("[+] plaintexts shape:", plaintexts.shape)
    print("[+] traces shape:", traces.shape)

    return plaintexts, traces


def cpa_recover_key_byte(plaintext_bytes: np.ndarray, traces: np.ndarray):
    traces_centered = traces - np.mean(traces, axis=0)
    traces_std = np.std(traces_centered, axis=0)
    traces_std[traces_std == 0] = 1e-12

    best_guess = 0
    best_corr = -1.0
    best_time_idx = 0
    scores = []

    for k in range(256):
        hyp = HW[AES_SBOX[np.bitwise_xor(plaintext_bytes, k)]].astype(np.float64)
        hyp_centered = hyp - np.mean(hyp)
        hyp_std = np.std(hyp_centered)
        if hyp_std == 0:
            continue

        corr = np.dot(hyp_centered, traces_centered) / (len(hyp) * hyp_std * traces_std)
        corr = np.nan_to_num(corr, nan=0.0, posinf=0.0, neginf=0.0)

        abs_corr = np.abs(corr)
        max_corr = float(np.max(abs_corr))
        time_idx = int(np.argmax(abs_corr))

        scores.append((k, max_corr, time_idx))

        if max_corr > best_corr:
            best_corr = max_corr
            best_guess = k
            best_time_idx = time_idx

    scores.sort(key=lambda x: x[1], reverse=True)
    return best_guess, best_corr, best_time_idx, scores[:5]


def recover_full_key(plaintexts: np.ndarray, traces: np.ndarray) -> bytes:
    key = []

    for byte_idx in range(16):
        guess, corr, t, top5 = cpa_recover_key_byte(plaintexts[:, byte_idx], traces)
        key.append(guess)

        print(f"[+] Byte {byte_idx:02d}: 0x{guess:02X}  corr={corr:.6f}  t={t}")
        print("    Top5:", " | ".join([f"{k:02X}:{c:.5f}@{ti}" for k, c, ti in top5]))

    return bytes(key)


def verify_key(key: bytes):
    key_hex_ascii = key.hex().upper().encode()
    resp = connect_option2(key_hex_ascii, debug=True)
    print("[+] Verification response:")
    print(resp.decode(errors="ignore"))


def save_session(plaintexts: np.ndarray, traces: np.ndarray, prefix="session"):
    np.save(f"{prefix}_plaintexts.npy", plaintexts)
    np.save(f"{prefix}_traces.npy", traces)
    print(f"[+] Saved {prefix}_plaintexts.npy and {prefix}_traces.npy")


def main():
    print(f"[*] Target: {HOST}:{PORT}")
    print(f"[*] TRACE_DTYPE: {TRACE_DTYPE}")
    print(f"[*] NUM_TRACES: {NUM_TRACES}")

    verify_protocol()

    plaintexts, traces = collect_traces(
        num_traces=NUM_TRACES,
        delay=DELAY_BETWEEN_TRACES
    )

    save_session(plaintexts, traces)

    traces = np.nan_to_num(traces, nan=0.0, posinf=0.0, neginf=0.0)
    traces = (traces - np.mean(traces, axis=0)) / (np.std(traces, axis=0) + 1e-9)

    print("[*] Running CPA...")
    key = recover_full_key(plaintexts, traces)

    print("[+] Recovered key:", key.hex().upper())

    print("[*] Verifying recovered key...")
    verify_key(key)


if __name__ == "__main__":
    main()
