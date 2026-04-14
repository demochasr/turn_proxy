package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cacggghp/vk-turn-proxy/bootstrap"
	"github.com/cacggghp/vk-turn-proxy/tcputil"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/xtaci/smux"
)

const (
	modeUDPWireGuard = "wireguard_udp_turn"
	modeTCPVLESS     = "vless_tcp_turn"
)

type streamEntry struct {
	id   byte
	conn net.Conn
	done chan struct{}
}

type sessionDatagramConn struct {
	session       *UserSession
	deadlineMu    sync.RWMutex
	readDeadline  time.Time
	writeDeadline time.Time
	addrMu        sync.RWMutex
	lastLocalAddr net.Addr
	lastPeerAddr  net.Addr
}

type UserSession struct {
	ID          string
	Mode        string
	ConnectAddr string
	Conns       []streamEntry
	BackendConn net.Conn
	PacketConn  *sessionDatagramConn
	Lock        sync.RWMutex
	Ctx         context.Context
	Cancel      context.CancelFunc
	Manager     *SessionManager
	RecvCh      chan receivedPacket
	WriteSeq    atomic.Uint64
	CleanupOnce sync.Once
}

type receivedPacket struct {
	payload    []byte
	localAddr  net.Addr
	remoteAddr net.Addr
}

type SessionManager struct {
	Sessions map[string]*UserSession
	Lock     sync.RWMutex
}

func (m *SessionManager) GetOrCreate(ctx context.Context, id, connectAddr, mode string) (*UserSession, error) {
	m.Lock.Lock()
	defer m.Lock.Unlock()

	if session, ok := m.Sessions[id]; ok {
		if session.Mode != mode {
			return nil, fmt.Errorf("session %s mode mismatch: have=%s want=%s", id, session.Mode, mode)
		}
		return session, nil
	}

	sessionCtx, cancel := context.WithCancel(ctx)
	session := &UserSession{
		ID:          id,
		Mode:        mode,
		ConnectAddr: connectAddr,
		Conns:       make([]streamEntry, 0),
		Ctx:         sessionCtx,
		Cancel:      cancel,
		Manager:     m,
		RecvCh:      make(chan receivedPacket, 1024),
	}

	switch mode {
	case modeUDPWireGuard:
		backendConn, err := net.Dial("udp", connectAddr)
		if err != nil {
			cancel()
			return nil, err
		}
		session.BackendConn = backendConn
		go session.backendReaderLoop()
	case modeTCPVLESS:
		session.PacketConn = &sessionDatagramConn{session: session}
		go session.tcpBackendLoop()
	default:
		cancel()
		return nil, fmt.Errorf("unsupported session mode: %s", mode)
	}

	m.Sessions[id] = session
	return session, nil
}

func (s *UserSession) AddConn(id byte, conn net.Conn) <-chan struct{} {
	done := make(chan struct{})

	s.Lock.Lock()
	for i, entry := range s.Conns {
		if entry.id == id {
			_ = entry.conn.Close()
			s.Conns[i] = streamEntry{id: id, conn: conn, done: done}
			s.Lock.Unlock()
			if s.Mode == modeTCPVLESS {
				go s.connReadLoop(id, conn, done)
			}
			return done
		}
	}
	s.Conns = append(s.Conns, streamEntry{id: id, conn: conn, done: done})
	s.Lock.Unlock()

	if s.Mode == modeTCPVLESS {
		go s.connReadLoop(id, conn, done)
	}
	return done
}

func (s *UserSession) RemoveConn(id byte, conn net.Conn) {
	s.Lock.Lock()
	for i, entry := range s.Conns {
		if entry.id == id && entry.conn == conn {
			s.Conns = append(s.Conns[:i], s.Conns[i+1:]...)
			break
		}
	}
	noConns := len(s.Conns) == 0
	s.Lock.Unlock()

	if noConns {
		s.Cleanup()
	}
}

func (s *UserSession) Cleanup() {
	s.CleanupOnce.Do(func() {
		s.Cancel()

		if s.BackendConn != nil {
			_ = s.BackendConn.Close()
		}
		if s.PacketConn != nil {
			_ = s.PacketConn.closeOnly()
		}

		s.Manager.Lock.Lock()
		delete(s.Manager.Sessions, s.ID)
		s.Manager.Lock.Unlock()

		s.Lock.Lock()
		for _, entry := range s.Conns {
			_ = entry.conn.Close()
		}
		s.Conns = nil
		s.Lock.Unlock()
	})
}

func (s *UserSession) backendReaderLoop() {
	defer s.Cleanup()

	buf := make([]byte, 1600)
	var lastUsed uint32
	for {
		select {
		case <-s.Ctx.Done():
			return
		default:
		}

		if err := s.BackendConn.SetReadDeadline(time.Now().Add(5 * time.Minute)); err != nil {
			log.Printf("Session %s backend deadline error: %v", s.ID, err)
			return
		}
		n, err := s.BackendConn.Read(buf)
		if err != nil {
			log.Printf("Session %s backend read error: %v", s.ID, err)
			return
		}

		s.Lock.RLock()
		nConns := uint32(len(s.Conns))
		if nConns == 0 {
			s.Lock.RUnlock()
			continue
		}

		lastUsed = (lastUsed + 1) % nConns
		conn := s.Conns[lastUsed].conn
		s.Lock.RUnlock()

		if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
			log.Printf("Session %s write deadline error: %v", s.ID, err)
			_ = conn.Close()
			continue
		}
		if _, err := conn.Write(buf[:n]); err != nil {
			log.Printf("Session %s DTLS write error: %v", s.ID, err)
			_ = conn.Close()
		}
	}
}

func (s *UserSession) tcpBackendLoop() {
	defer s.Cleanup()

	kcpSess, err := tcputil.NewKCPOverDTLS(s.PacketConn, true)
	if err != nil {
		log.Printf("Session %s KCP session error: %s", s.ID, err)
		return
	}
	defer kcpSess.Close()
	log.Printf("Session %s KCP session established (server)", s.ID)

	smuxSess, err := smux.Server(kcpSess, tcputil.DefaultSmuxConfig())
	if err != nil {
		log.Printf("Session %s smux server error: %s", s.ID, err)
		return
	}
	defer smuxSess.Close()
	log.Printf("Session %s smux session established (server)", s.ID)

	var wg sync.WaitGroup
	for {
		stream, err := smuxSess.AcceptStream()
		if err != nil {
			select {
			case <-s.Ctx.Done():
			default:
				log.Printf("Session %s smux accept error: %s", s.ID, err)
			}
			break
		}

		wg.Add(1)
		go func(st *smux.Stream) {
			defer wg.Done()
			defer st.Close()

			backendConn, err := net.DialTimeout("tcp", s.ConnectAddr, 10*time.Second)
			if err != nil {
				log.Printf("Session %s backend dial error: %s", s.ID, err)
				return
			}
			defer backendConn.Close()

			pipeConn(s.Ctx, st, backendConn)
		}(stream)
	}
	wg.Wait()
}

func (s *UserSession) connReadLoop(id byte, conn net.Conn, done chan struct{}) {
	defer close(done)
	defer s.RemoveConn(id, conn)

	buf := make([]byte, 2048)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Minute)); err != nil {
			log.Printf("Session %s stream %d read deadline error: %v", s.ID, id, err)
			return
		}
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("Session %s stream %d closed: %v", s.ID, id, err)
			return
		}

		packet := receivedPacket{
			payload:    append([]byte(nil), buf[:n]...),
			localAddr:  conn.LocalAddr(),
			remoteAddr: conn.RemoteAddr(),
		}
		select {
		case <-s.Ctx.Done():
			return
		case s.RecvCh <- packet:
		}
	}
}

func (s *UserSession) pickConn() (net.Conn, error) {
	s.Lock.RLock()
	defer s.Lock.RUnlock()

	if len(s.Conns) == 0 {
		return nil, errors.New("no active DTLS connections")
	}

	idx := int(s.WriteSeq.Add(1)-1) % len(s.Conns)
	return s.Conns[idx].conn, nil
}

func (c *sessionDatagramConn) Read(b []byte) (int, error) {
	for {
		var deadline <-chan time.Time
		if d := c.getReadDeadline(); !d.IsZero() {
			timer := time.NewTimer(time.Until(d))
			defer timer.Stop()
			deadline = timer.C
		}

		select {
		case <-c.session.Ctx.Done():
			return 0, net.ErrClosed
		case <-deadline:
			return 0, os.ErrDeadlineExceeded
		case packet := <-c.session.RecvCh:
			c.setLastReadAddrs(packet.localAddr, packet.remoteAddr)
			n := copy(b, packet.payload)
			return n, nil
		}
	}
}

func (c *sessionDatagramConn) Write(b []byte) (int, error) {
	conn, err := c.session.pickConn()
	if err != nil {
		return 0, err
	}

	if deadline := c.getWriteDeadline(); !deadline.IsZero() {
		if err := conn.SetWriteDeadline(deadline); err != nil {
			return 0, err
		}
	}
	return conn.Write(b)
}

func (c *sessionDatagramConn) Close() error {
	c.session.Cleanup()
	return nil
}

func (c *sessionDatagramConn) closeOnly() error {
	c.deadlineMu.Lock()
	c.readDeadline = time.Time{}
	c.writeDeadline = time.Time{}
	c.deadlineMu.Unlock()
	return nil
}

func (c *sessionDatagramConn) LocalAddr() net.Addr {
	if addr := c.getLastLocalAddr(); addr != nil {
		return addr
	}
	if conn, err := c.session.pickConn(); err == nil {
		return conn.LocalAddr()
	}
	return dummyAddr("session-local")
}

func (c *sessionDatagramConn) RemoteAddr() net.Addr {
	if addr := c.getLastPeerAddr(); addr != nil {
		return addr
	}
	if conn, err := c.session.pickConn(); err == nil {
		return conn.RemoteAddr()
	}
	return dummyAddr("session-remote")
}

func (c *sessionDatagramConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	return nil
}

func (c *sessionDatagramConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.deadlineMu.Unlock()
	return nil
}

func (c *sessionDatagramConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	return nil
}

func (c *sessionDatagramConn) getReadDeadline() time.Time {
	c.deadlineMu.RLock()
	defer c.deadlineMu.RUnlock()
	return c.readDeadline
}

func (c *sessionDatagramConn) getWriteDeadline() time.Time {
	c.deadlineMu.RLock()
	defer c.deadlineMu.RUnlock()
	return c.writeDeadline
}

func (c *sessionDatagramConn) setLastReadAddrs(localAddr, peerAddr net.Addr) {
	c.addrMu.Lock()
	c.lastLocalAddr = localAddr
	c.lastPeerAddr = peerAddr
	c.addrMu.Unlock()
}

func (c *sessionDatagramConn) getLastLocalAddr() net.Addr {
	c.addrMu.RLock()
	defer c.addrMu.RUnlock()
	return c.lastLocalAddr
}

func (c *sessionDatagramConn) getLastPeerAddr() net.Addr {
	c.addrMu.RLock()
	defer c.addrMu.RUnlock()
	return c.lastPeerAddr
}

type dummyAddr string

func (d dummyAddr) Network() string { return "session" }
func (d dummyAddr) String() string  { return string(d) }

func readBootstrapToken(conn net.Conn, secret, publicKey, proxyID, mode string) error {
	if secret == "" && publicKey == "" {
		return nil
	}

	token, err := bootstrap.Read(conn)
	if err != nil {
		return err
	}
	claims, err := bootstrap.Verify(token, secret, publicKey, proxyID, mode)
	if err != nil {
		return err
	}
	log.Printf(
		"Bootstrap ok: sub=%s proxy=%s server=%s mode=%s",
		claims.Subject,
		claims.ProxyID,
		claims.ServerID,
		claims.Mode,
	)
	return nil
}

func readSessionHeader(conn net.Conn) (string, byte, error) {
	idBuf := make([]byte, 17)
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return "", 0, err
	}
	if _, err := io.ReadFull(conn, idBuf); err != nil {
		return "", 0, err
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return "", 0, err
	}
	return fmt.Sprintf("%x", idBuf[:16]), idBuf[16], nil
}

func handleUDPConnection(ctx context.Context, conn net.Conn, connectAddr string, manager *SessionManager) {
	sessionID, streamID, err := readSessionHeader(conn)
	if err != nil {
		log.Printf("Failed to read session header: %v", err)
		return
	}

	session, err := manager.GetOrCreate(ctx, sessionID, connectAddr, modeUDPWireGuard)
	if err != nil {
		log.Printf("Failed to get/create session: %v", err)
		return
	}

	session.AddConn(streamID, conn)
	defer session.RemoveConn(streamID, conn)
	log.Printf("New UDP stream %d for session %s from %s", streamID, sessionID, conn.RemoteAddr())

	buf := make([]byte, 1600)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Minute)); err != nil {
			log.Printf("Stream %s read deadline error: %v", sessionID, err)
			return
		}
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("Stream %s closed: %v", sessionID, err)
			return
		}
		if err := session.BackendConn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
			log.Printf("Session %s backend deadline error: %v", sessionID, err)
			return
		}
		if _, err := session.BackendConn.Write(buf[:n]); err != nil {
			log.Printf("Session %s backend write error: %v", sessionID, err)
			return
		}
	}
}

func handleTCPConnection(ctx context.Context, conn net.Conn, connectAddr string, manager *SessionManager) {
	sessionID, streamID, err := readSessionHeader(conn)
	if err != nil {
		log.Printf("Failed to read TCP session header: %v", err)
		return
	}

	session, err := manager.GetOrCreate(ctx, sessionID, connectAddr, modeTCPVLESS)
	if err != nil {
		log.Printf("Failed to get/create TCP session: %v", err)
		return
	}

	done := session.AddConn(streamID, conn)
	log.Printf("New TCP stream %d for session %s from %s", streamID, sessionID, conn.RemoteAddr())

	select {
	case <-ctx.Done():
	case <-session.Ctx.Done():
	case <-done:
	}
}

func pipeConn(ctx context.Context, c1, c2 net.Conn) {
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()

	context.AfterFunc(ctx2, func() {
		_ = c1.SetDeadline(time.Now())
		_ = c2.SetDeadline(time.Now())
	})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer cancel()
		_, _ = io.Copy(c1, c2)
	}()
	go func() {
		defer wg.Done()
		defer cancel()
		_, _ = io.Copy(c2, c1)
	}()
	wg.Wait()
	_ = c1.SetDeadline(time.Time{})
	_ = c2.SetDeadline(time.Time{})
}

func main() {
	listen := flag.String("listen", "0.0.0.0:56000", "listen on ip:port")
	connect := flag.String("connect", "", "connect to ip:port")
	tcpMode := flag.Bool("tcp", false, "TCP mode: forward TCP connections (for VLESS) instead of UDP packets")
	proxyID := flag.String("proxy-id", "", "proxy identifier expected in bootstrap token")
	bootstrapSecret := flag.String("bootstrap-secret", "", "legacy TURN bootstrap token shared secret")
	bootstrapPublicKey := flag.String("bootstrap-public-key", "", "TURN bootstrap token verification public key (PEM)")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signalChan
		log.Printf("Terminating...\n")
		cancel()
		<-signalChan
		log.Fatalf("Exit...\n")
	}()

	addr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		panic(err)
	}
	if *connect == "" {
		log.Panicf("server address is required")
	}

	certificate, genErr := selfsign.GenerateSelfSigned()
	if genErr != nil {
		panic(genErr)
	}
	config := &dtls.Config{
		Certificates:          []tls.Certificate{certificate},
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.RandomCIDGenerator(8),
	}

	listener, err := dtls.Listen("udp", addr, config)
	if err != nil {
		panic(err)
	}
	context.AfterFunc(ctx, func() {
		if closeErr := listener.Close(); closeErr != nil {
			log.Printf("failed to close listener: %v", closeErr)
		}
	})

	mode := modeUDPWireGuard
	if *tcpMode {
		mode = modeTCPVLESS
	}
	manager := &SessionManager{Sessions: make(map[string]*UserSession)}
	log.Printf("Listening on %s, forwarding to %s, mode=%s", *listen, *connect, mode)

	var wg sync.WaitGroup
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				continue
			default:
				log.Println(err)
				continue
			}
		}

		wg.Add(1)
		go func(conn net.Conn) {
			defer wg.Done()
			defer conn.Close()

			log.Printf("Connection from %s", conn.RemoteAddr())
			dtlsConn, ok := conn.(*dtls.Conn)
			if !ok {
				log.Println("Type error")
				return
			}

			ctx1, cancel1 := context.WithTimeout(ctx, 30*time.Second)
			defer cancel1()
			log.Println("Start handshake")
			if err := dtlsConn.HandshakeContext(ctx1); err != nil {
				log.Println(err)
				return
			}
			log.Println("Handshake done")

			if *bootstrapSecret != "" || *bootstrapPublicKey != "" {
				if err := readBootstrapToken(dtlsConn, *bootstrapSecret, *bootstrapPublicKey, *proxyID, mode); err != nil {
					log.Printf("Bootstrap handshake failed: %v", err)
					return
				}
				if err := dtlsConn.SetDeadline(time.Time{}); err != nil {
					log.Printf("failed to clear bootstrap deadline: %v", err)
				}
			}

			if *tcpMode {
				handleTCPConnection(ctx, dtlsConn, *connect, manager)
			} else {
				handleUDPConnection(ctx, dtlsConn, *connect, manager)
			}
			log.Printf("Connection closed: %s", conn.RemoteAddr())
		}(conn)
	}
}
