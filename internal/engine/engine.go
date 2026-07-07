// Package engine wires the data plane together: TUN ⇄ scheduler ⇄ paths ⇄
// reorder buffer, plus the control plane (handshakes, rekey, probes, path
// lifecycle). It is the only package that knows both the client and
// server roles; everything else is role-agnostic.
package engine

import (
	"crypto/rand"
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/TKYcraft/amane/internal/config"
	"github.com/TKYcraft/amane/internal/keys"
	"github.com/TKYcraft/amane/internal/noiseio"
	"github.com/TKYcraft/amane/internal/pktbuf"
	"github.com/TKYcraft/amane/internal/tundev"
)

// Role selects client or server behavior.
type Role int

const (
	RoleClient Role = iota
	RoleServer
)

// Engine is one running daemon instance.
type Engine struct {
	log    *slog.Logger
	role   Role
	tun    *tundev.Device
	mtu    int
	tuning config.Tuning
	fecCfg config.FEC

	base time.Time // monotonic clock anchor

	// tunOut carries decrypted inner packets to the TUN writer.
	tunOut chan rxPkt

	// client
	ccfg       *config.Client
	serverAddr netip.AddrPort
	sess       *session // the client's single session
	hsRespCh   chan hsResp
	rekeyNow   chan struct{}
	linksMu    sync.Mutex // guards ccfg.Links and setupLinks reconciliation

	// server
	scfg    *config.Server
	conn    *net.UDPConn // listen socket
	peersMu sync.RWMutex
	peers   map[keys.Key]*session
	byIP    map[netip.Addr]*session
	byRxID  map[uint32]epochRef
	hsGate  *tokenBucket

	cleanups []func()

	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

type epochRef struct {
	sess  *session
	epoch *noiseio.Epoch
}

type rxPkt struct {
	buf *pktbuf.Buf
	pkt []byte // inner IP packet, aliases buf at pktbuf.RxIPOffset
}

type hsResp struct {
	rxID uint32
	msg  []byte // copied Noise message
}

// nowUs is the engine's monotonic clock in microseconds.
func (e *Engine) nowUs() int64 {
	return time.Since(e.base).Microseconds()
}

// Stop shuts the engine down and waits for all goroutines.
func (e *Engine) Stop() {
	e.stopOnce.Do(func() {
		close(e.stop)
		if e.sess != nil {
			e.sess.sendCloseAll()
		}
		if e.tun != nil {
			e.tun.Close()
		}
		if e.conn != nil {
			e.conn.Close()
		}
		if e.sess != nil {
			e.sess.closeConns()
		}
		e.wg.Wait()
		for i := len(e.cleanups) - 1; i >= 0; i-- {
			e.cleanups[i]()
		}
	})
}

// Wait blocks until the engine has been stopped.
func (e *Engine) Wait() {
	<-e.stop
	e.wg.Wait()
}

func (e *Engine) goRun(name string, f func()) {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		f()
	}()
}

// tunWriter drains decrypted packets into the TUN device in batches.
func (e *Engine) tunWriter() {
	batch := e.tun.BatchSize()
	bufs := make([][]byte, 0, batch)
	owners := make([]*pktbuf.Buf, 0, batch)
	for {
		var first rxPkt
		select {
		case <-e.stop:
			return
		case first = <-e.tunOut:
		}
		bufs = append(bufs[:0], first.buf[:pktbuf.RxIPOffset+len(first.pkt)])
		owners = append(owners[:0], first.buf)
	fill:
		for len(bufs) < batch {
			select {
			case p := <-e.tunOut:
				bufs = append(bufs, p.buf[:pktbuf.RxIPOffset+len(p.pkt)])
				owners = append(owners, p.buf)
			default:
				break fill
			}
		}
		if _, err := e.tun.Write(bufs, pktbuf.RxIPOffset); err != nil {
			e.log.Warn("tun write", "err", err)
		}
		for _, b := range owners {
			pktbuf.Put(b)
		}
	}
}

// tunReader pulls outbound packets off the TUN and hands them to the
// owning session.
func (e *Engine) tunReader() {
	batch := e.tun.BatchSize()
	bufs := make([][]byte, batch)
	owners := make([]*pktbuf.Buf, batch)
	views := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		owners[i] = pktbuf.Get()
		views[i] = owners[i][:]
	}
	scratch := pktbuf.Get() // for redundant-mode copies
	defer pktbuf.Put(scratch)
	for {
		copy(bufs, views)
		n, err := e.tun.Read(bufs, sizes, pktbuf.TunOffset)
		if err != nil {
			select {
			case <-e.stop:
				return
			default:
				e.log.Error("tun read", "err", err)
				return
			}
		}
		for i := 0; i < n; i++ {
			if sizes[i] == 0 {
				continue
			}
			ip := owners[i][pktbuf.TunOffset : pktbuf.TunOffset+sizes[i]]
			s := e.routeSession(ip)
			if s == nil {
				continue
			}
			s.sendData(owners[i], sizes[i], scratch)
		}
	}
}

// routeSession finds the session for an outbound inner packet.
func (e *Engine) routeSession(ip []byte) *session {
	if e.role == RoleClient {
		return e.sess
	}
	dst, ok := innerDst(ip)
	if !ok {
		return nil
	}
	e.peersMu.RLock()
	s := e.byIP[dst]
	e.peersMu.RUnlock()
	return s
}

// innerDst extracts the destination address of an IP packet.
func innerDst(ip []byte) (netip.Addr, bool) {
	if len(ip) < 1 {
		return netip.Addr{}, false
	}
	switch ip[0] >> 4 {
	case 4:
		if len(ip) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(ip[16:20])), true
	case 6:
		if len(ip) < 40 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(ip[24:40])).Unmap(), true
	}
	return netip.Addr{}, false
}

// randUint32 returns a cryptographically random nonzero uint32.
func randUint32() uint32 {
	var b [4]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			panic(err)
		}
		if v := binary.LittleEndian.Uint32(b[:]); v != 0 {
			return v
		}
	}
}

// tokenBucket rate-limits handshake processing (DoS guard).
type tokenBucket struct {
	mu     sync.Mutex
	tokens float64
	max    float64
	rate   float64 // tokens per second
	last   time.Time
}

func newTokenBucket(max, perSecond float64) *tokenBucket {
	return &tokenBucket{tokens: max, max: max, rate: perSecond, last: time.Now()}
}

func (t *tokenBucket) allow() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	t.tokens += now.Sub(t.last).Seconds() * t.rate
	if t.tokens > t.max {
		t.tokens = t.max
	}
	t.last = now
	if t.tokens < 1 {
		return false
	}
	t.tokens--
	return true
}
