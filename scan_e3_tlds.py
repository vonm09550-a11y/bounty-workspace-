#!/usr/bin/env python3
"""Scan all IANA TLDs for e=3 RSA DNSKEY records via Google DNS API."""

import urllib.request
import json
import base64
import struct
import time
import sys

def parse_rsa_exponent(data_field):
    """Parse DNSKEY RDATA string, return dict with key details."""
    parts = data_field.split(None, 3)
    if len(parts) < 4:
        return None
    flags = int(parts[0])
    protocol = int(parts[1])
    algorithm = int(parts[2])
    key_b64 = parts[3].replace(" ", "")
    key_type = "KSK" if flags & 0x0001 else "ZSK"

    if algorithm not in [5, 7, 8, 10]:
        return {"flags": flags, "algorithm": algorithm, "key_type": key_type, "algo_type": "non-RSA"}

    try:
        key_bytes = base64.b64decode(key_b64)
    except Exception:
        return None

    if len(key_bytes) < 3:
        return None

    exp_len_byte = key_bytes[0]
    if exp_len_byte != 0:
        exp_len = exp_len_byte
        if len(key_bytes) < 1 + exp_len:
            return None
        exponent_bytes = key_bytes[1:1 + exp_len]
        mod_start = 1 + exp_len
    else:
        if len(key_bytes) < 3:
            return None
        exp_len = struct.unpack('!H', key_bytes[1:3])[0]
        if len(key_bytes) < 3 + exp_len:
            return None
        exponent_bytes = key_bytes[3:3 + exp_len]
        mod_start = 3 + exp_len

    exponent = int.from_bytes(exponent_bytes, 'big')
    modulus_bits = (len(key_bytes) - mod_start) * 8

    return {
        "flags": flags,
        "algorithm": algorithm,
        "exponent": exponent,
        "modulus_bits": modulus_bits,
        "key_type": key_type,
        "algo_type": "RSA",
    }


def query_dnskey(tld):
    """Query Google DNS API for DNSKEY records."""
    url = "https://dns.google/resolve?name={}&type=DNSKEY".format(tld)
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            if "Answer" in data:
                return data["Answer"]
    except Exception:
        return None
    return None


def main():
    with open("/home/user/bounty-workspace-/all_tlds.txt") as f:
        tlds = [line.strip() for line in f if line.strip()]

    e3_results = []
    rsa_results = []
    ecdsa_count = 0
    no_answer = 0
    error_count = 0
    total = len(tlds)

    for i, tld in enumerate(tlds):
        if (i + 1) % 50 == 0:
            sys.stderr.write("Progress: {}/{} (e=3 found so far: {})\n".format(i + 1, total, len(e3_results)))
            sys.stderr.flush()

        answers = query_dnskey(tld)
        if answers is None:
            error_count += 1
            time.sleep(0.15)
            continue

        if len(answers) == 0:
            no_answer += 1
            time.sleep(0.05)
            continue

        for ans in answers:
            data = ans.get("data", "")
            result = parse_rsa_exponent(data)
            if result is None:
                continue

            if result["algo_type"] == "non-RSA":
                ecdsa_count += 1
                break

            rsa_results.append((tld, result))
            if result["exponent"] == 3:
                e3_results.append((tld, result))

        time.sleep(0.05)

    # Output results
    print("=" * 70)
    print("FULL TLD SCAN RESULTS: e=3 RSA DNSKEY RECORDS")
    print("=" * 70)
    print()
    print("TLDs scanned: {}".format(total))
    print("TLDs with RSA DNSKEY: {}".format(len(set(t for t, _ in rsa_results))))
    print("TLDs with ECDSA: {}".format(ecdsa_count))
    print("TLDs with no DNSKEY: {}".format(no_answer))
    print("TLDs with errors: {}".format(error_count))
    print()
    print("=" * 70)
    print("TLDs WITH e=3 RSA KEYS")
    print("=" * 70)

    seen = set()
    for tld, r in e3_results:
        key = (tld, r["key_type"])
        if key not in seen:
            seen.add(key)
            print("  .{:15s} {:3s}  alg={}  mod={}-bit".format(
                tld, r["key_type"], r["algorithm"], r["modulus_bits"]))

    print()
    print("Total unique TLDs with e=3: {}".format(len(set(t for t, _ in e3_results))))
    print()

    # Also show exponent distribution
    print("=" * 70)
    print("RSA EXPONENT DISTRIBUTION")
    print("=" * 70)
    exp_counts = {}
    for tld, r in rsa_results:
        e = r["exponent"]
        exp_counts[e] = exp_counts.get(e, 0) + 1
    for exp in sorted(exp_counts.keys()):
        print("  e={}: {} keys".format(exp, exp_counts[exp]))


if __name__ == "__main__":
    main()
