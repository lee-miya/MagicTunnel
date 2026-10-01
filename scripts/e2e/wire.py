#!/usr/bin/env python3
"""Wire-level checks for the XOR obfuscation layer.

    wire.py sniff IFACE PORT OUT      # capture UDP payloads to/from PORT until SIGTERM
    wire.py analyze OUT XOR_KEY [--marker M]... [--sni S] [--alpn A]
    wire.py flows OUT                 # distinct "src>dst" address pairs, sorted
    wire.py grep OUT NEEDLE [--key K] # datagrams containing NEEDLE (after removing XOR with K)

`sniff` uses an AF_PACKET socket (needs CAP_NET_RAW in the interface's netns) and writes one
JSON line per UDP datagram; IFACE `any` captures every interface of the netns, so a datagram
crossing a bridge is recorded once per port it passes. `analyze` asserts that the raw capture carries no recognisable
QUIC, then removes the XOR layer with the shared key (mirroring crates/transport/src/obfs.rs)
and shows that what is underneath is QUIC v1 whose Initial packet a DPI box could decrypt to
read SNI and ALPN, i.e. what the obfuscation is hiding. Exits non-zero if a check fails.
"""

import argparse
import json
import signal
import socket
import struct
import sys

NONCE_LEN = 4
OFFSETS = 1 << 16
TABLE_LEN = OFFSETS + (1 << 16)
MASK64 = (1 << 64) - 1
QUIC_V1 = 0x00000001
QUIC_V1_INITIAL_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")


# --- capture -----------------------------------------------------------------------------


def sniff(iface: str, port: int, out: str) -> None:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    if iface != "any":
        sock.bind((iface, 0))
    stop = False

    def on_term(*_):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    sock.settimeout(0.2)
    with open(out, "w") as f:
        while not stop:
            try:
                frame = sock.recv(1 << 17)
            except socket.timeout:
                continue
            except InterruptedError:
                continue
            rec = parse_udp(frame)
            if rec and port in (rec["sport"], rec["dport"]):
                f.write(json.dumps(rec) + "\n")
                f.flush()


def parse_udp(frame: bytes):
    if len(frame) < 14 + 20 + 8 or frame[12:14] != b"\x08\x00":
        return None
    ip = frame[14:]
    ihl = (ip[0] & 0x0F) * 4
    if ip[9] != 17:
        return None
    total = struct.unpack("!H", ip[2:4])[0]
    udp = ip[ihl:total]
    sport, dport, ulen = struct.unpack("!HHH", udp[:6])
    return {
        "src": socket.inet_ntoa(ip[12:16]),
        "dst": socket.inet_ntoa(ip[16:20]),
        "sport": sport,
        "dport": dport,
        "payload": udp[8:ulen].hex(),
    }


# --- XOR layer (keep in sync with crates/transport/src/obfs.rs) ---------------------------


def fnv1a(data: bytes) -> int:
    h = 0xCBF29CE484222325
    for b in data:
        h = ((h ^ b) * 0x100000001B3) & MASK64
    return h


def keystream_table(key: bytes) -> bytes:
    state = fnv1a(key)
    words = bytearray()
    for _ in range(TABLE_LEN // 8):
        state = (state + 0x9E3779B97F4A7C15) & MASK64
        z = state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
        words += (z ^ (z >> 31)).to_bytes(8, "little")
    rep = (key * (TABLE_LEN // len(key) + 1))[:TABLE_LEN]
    return xor(bytes(words), rep)


def xor(a: bytes, b: bytes) -> bytes:
    n = min(len(a), len(b))
    return (int.from_bytes(a[:n], "little") ^ int.from_bytes(b[:n], "little")).to_bytes(
        n, "little"
    )


def deobfuscate(table: bytes, wire: bytes) -> bytes:
    nonce = int.from_bytes(wire[:NONCE_LEN], "little")
    offset = (nonce ^ (nonce >> 16)) & (OFFSETS - 1)
    payload = wire[NONCE_LEN:]
    return xor(payload, table[offset : offset + len(payload)])


# --- QUIC v1 (RFC 9000 / 9001) -----------------------------------------------------------


def looks_like_quic_v1_long(p: bytes) -> bool:
    return len(p) >= 5 and p[0] & 0xC0 == 0xC0 and int.from_bytes(p[1:5], "big") == QUIC_V1


def varint(buf: bytes, i: int):
    first = buf[i]
    n = 1 << (first >> 6)
    return int.from_bytes(bytes([first & 0x3F]) + buf[i + 1 : i + n], "big"), i + n


def hkdf_expand_label(secret: bytes, label: str, length: int) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

    full = b"tls13 " + label.encode()
    info = struct.pack("!HB", length, len(full)) + full + b"\x00"
    return HKDFExpand(hashes.SHA256(), length, info).derive(secret)


def decrypt_client_initial(pkt: bytes) -> bytes:
    """Returns the CRYPTO frame bytes of a client Initial, using only public information."""
    import hmac

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if pkt[0] & 0x30 != 0x00:
        raise ValueError("not an Initial packet")
    i = 5
    dcid = pkt[i + 1 : i + 1 + pkt[i]]
    i += 1 + len(dcid)
    i += 1 + pkt[i]  # scid
    token_len, i = varint(pkt, i)
    i += token_len
    length, pn_off = varint(pkt, i)

    initial = hmac.new(QUIC_V1_INITIAL_SALT, dcid, "sha256").digest()
    client = hkdf_expand_label(initial, "client in", 32)
    key = hkdf_expand_label(client, "quic key", 16)
    iv = hkdf_expand_label(client, "quic iv", 12)
    hp = hkdf_expand_label(client, "quic hp", 16)

    sample = pkt[pn_off + 4 : pn_off + 20]
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(sample) + enc.finalize()
    header = bytearray(pkt[: pn_off + 4])
    header[0] ^= mask[0] & 0x0F
    pn_len = (header[0] & 0x03) + 1
    for k in range(pn_len):
        header[pn_off + k] ^= mask[1 + k]
    header = bytes(header[: pn_off + pn_len])
    pn = int.from_bytes(header[pn_off:], "big")
    nonce = xor(iv, pn.to_bytes(12, "big"))
    plain = AESGCM(key).decrypt(nonce, pkt[pn_off + pn_len : pn_off + length], header)

    crypto, j = bytearray(), 0
    while j < len(plain):
        ftype = plain[j]
        if ftype in (0x00, 0x01):  # PADDING, PING
            j += 1
        elif ftype == 0x06:  # CRYPTO
            _, j = varint(plain, j + 1)
            n, j = varint(plain, j)
            crypto += plain[j : j + n]
            j += n
        else:
            break
    return bytes(crypto)


# --- analysis ----------------------------------------------------------------------------


def analyze(args) -> int:
    recs = [json.loads(line) for line in open(args.capture)]
    raws = [bytes.fromhex(r["payload"]) for r in recs]
    table = keystream_table(args.key.encode())
    plains = [deobfuscate(table, w) for w in raws if len(w) > NONCE_LEN]
    to_server = [r for r in recs if r["dport"] == args.port]

    failures = 0

    def check(ok: bool, msg: str) -> None:
        nonlocal failures
        print(f"  [{'PASS' if ok else 'FAIL'}] {msg}")
        failures += not ok

    print(f"  captured {len(raws)} UDP datagrams ({len(to_server)} towards the server)")
    check(len(raws) >= 20, "enough traffic captured to judge")

    raw_quic = sum(looks_like_quic_v1_long(w) for w in raws)
    check(raw_quic == 0, f"raw wire: {raw_quic} datagrams parse as a QUIC v1 long header")
    raw_fixed = sum(len(w) > 0 and w[0] & 0x40 != 0 for w in raws) / max(len(raws), 1)
    print(f"  raw wire: QUIC fixed bit set in {raw_fixed:.0%} of first bytes (QUIC: ~100%)")
    nonces = {w[:NONCE_LEN] for w in raws}
    check(len(nonces) >= 0.98 * len(raws), f"{len(nonces)}/{len(raws)} distinct nonces")

    leaks = [s for s in (args.sni, args.alpn, *args.marker) if s]
    for s in leaks:
        hit = sum(s.encode() in w for w in raws)
        check(hit == 0, f"raw wire: {s!r} found in {hit} datagrams")

    long_v1 = sum(looks_like_quic_v1_long(p) for p in plains)
    check(long_v1 > 0, f"after removing XOR: {long_v1} QUIC v1 long-header packets")
    first = next(
        (deobfuscate(table, bytes.fromhex(r["payload"])) for r in to_server), b""
    )
    check(looks_like_quic_v1_long(first), "after removing XOR: first datagram is QUIC v1")
    if looks_like_quic_v1_long(first):
        try:
            hello = decrypt_client_initial(first)
        except Exception as e:  # noqa: BLE001
            check(False, f"decrypting the client Initial failed: {e}")
        else:
            for s in (args.sni, args.alpn):
                if s:
                    check(
                        s.encode() in hello,
                        f"DPI view without XOR: {s!r} readable in the decrypted ClientHello",
                    )
    for m in args.marker:
        hit = sum(m.encode() in p for p in plains)
        check(hit == 0, f"after removing XOR: {m!r} still hidden by TLS")
    return 1 if failures else 0


def flows(args) -> int:
    pairs = {(r["src"], r["dst"]) for r in map(json.loads, open(args.capture))}
    for src, dst in sorted(pairs):
        print(f"{src}>{dst}")
    return 0


def grep(args) -> int:
    raws = [bytes.fromhex(json.loads(line)["payload"]) for line in open(args.capture)]
    if args.key:
        table = keystream_table(args.key.encode())
        raws = [deobfuscate(table, w) for w in raws if len(w) > NONCE_LEN]
    print(sum(args.needle.encode() in w for w in raws))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sniff")
    s.add_argument("iface")
    s.add_argument("port", type=int)
    s.add_argument("out")
    a = sub.add_parser("analyze")
    a.add_argument("capture")
    a.add_argument("key")
    a.add_argument("--port", type=int, default=4433)
    a.add_argument("--marker", action="append", default=[])
    a.add_argument("--sni")
    a.add_argument("--alpn")
    f = sub.add_parser("flows")
    f.add_argument("capture")
    g = sub.add_parser("grep")
    g.add_argument("capture")
    g.add_argument("needle")
    g.add_argument("--key")
    args = ap.parse_args()
    if args.cmd == "sniff":
        sniff(args.iface, args.port, args.out)
        return 0
    return {"analyze": analyze, "flows": flows, "grep": grep}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
