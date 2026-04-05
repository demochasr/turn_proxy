package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
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
}

type UserSession struct {
	ID          string
	Conns       []streamEntry
	BackendConn net.Conn
	Lock        sync.RWMutex
	Ctx         context.Context
	Cancel      context.CancelFunc
	Manager     *SessionManager
}

type SessionManager struct {
	Sessions map[string]*UserSession
	Lock     sync.RWMutex
}

func (s *SessionManager) GetOrCreate(ctx context.Context, id string, connectAddr string) (*UserSession, error) {
	s.Lock.Lock()
	defer s.Lock.Unlock()

	if session, ok := s.Sessions[id]; ok {
		return session, nil
	}

	backendConn, err := net.Dial("udp", connectAddr)
	if err != nil {
		return nil, err
	}

	sessionCtx, cancel := context.WithCancel(ctx)
	session := &UserSession{
		ID:          id,
		Conns:       make([]streamEntry, 0),
		BackendConn: backendConn,
		Manager:     s,
		Ctx:         sessionCtx,
		Cancel:      cancel,
	}
	s.Sessions[id] = session
	go session.backendReaderLoop()

	return session, nil
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
			conn.Close()
			continue
		}
		if _, err := conn.Write(buf[:n]); err != nil {
			log.Printf("Session %s DTLS write error: %v", s.ID, err)
			conn.Close()
		}
	}
}

func (s *UserSession) AddConn(id byte, conn net.Conn) {
	s.Lock.Lock()
	defer s.Lock.Unlock()

	for i, entry := range s.Conns {
		if entry.id == id {
			entry.conn.Close()
			s.Conns[i].conn = conn
			return
		}
	}
	s.Conns = append(s.Conns, streamEntry{id: id, conn: conn})
}

func (s *UserSession) RemoveConn(id byte, conn net.Conn) {
	s.Lock.Lock()
	defer s.Lock.Unlock()
	for i, entry := range s.Conns {
		if entry.id == id && entry.conn == conn {
			s.Conns = append(s.Conns[:i], s.Conns[i+1:]...)
			break
		}
	}
}

func (s *UserSession) Cleanup() {
	s.Cancel()
	s.BackendConn.Close()

	s.Manager.Lock.Lock()
	delete(s.Manager.Sessions, s.ID)
	s.Manager.Lock.Unlock()

	s.Lock.Lock()
	for _, entry := range s.Conns {
		entry.conn.Close()
	}
	s.Conns = nil
	s.Lock.Unlock()
}

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

func handleUDPConnection(ctx context.Context, conn net.Conn, connectAddr string, manager *SessionManager) {
	idBuf := make([]byte, 17)
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Printf("Failed to set session header deadline: %v", err)
		return
	}
	if _, err := io.ReadFull(conn, idBuf); err != nil {
		log.Printf("Failed to read session header: %v", err)
		return
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		log.Printf("Failed to clear session header deadline: %v", err)
		return
	}

	sessionID := fmt.Sprintf("%x", idBuf[:16])
	streamID := idBuf[16]
	session, err := manager.GetOrCreate(ctx, sessionID, connectAddr)
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

func handleTCPConnection(ctx context.Context, dtlsConn net.Conn, connectAddr string) {
	kcpSess, err := tcputil.NewKCPOverDTLS(dtlsConn, true)
	if err != nil {
		log.Printf("KCP session error: %s", err)
		return
	}
	defer kcpSess.Close()
	log.Printf("KCP session established (server)")

	smuxSess, err := smux.Server(kcpSess, tcputil.DefaultSmuxConfig())
	if err != nil {
		log.Printf("smux server error: %s", err)
		return
	}
	defer smuxSess.Close()
	log.Printf("smux session established (server)")

	var wg sync.WaitGroup
	for {
		stream, err := smuxSess.AcceptStream()
		if err != nil {
			select {
			case <-ctx.Done():
			default:
				log.Printf("smux accept error: %s", err)
			}
			break
		}

		wg.Add(1)
		go func(s *smux.Stream) {
			defer wg.Done()
			defer s.Close()

			backendConn, err := net.DialTimeout("tcp", connectAddr, 10*time.Second)
			if err != nil {
				log.Printf("backend dial error: %s", err)
				return
			}
			defer backendConn.Close()

			pipeConn(ctx, s, backendConn)
		}(stream)
	}
	wg.Wait()
}

func pipeConn(ctx context.Context, c1, c2 net.Conn) {
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()
	context.AfterFunc(ctx2, func() {
		c1.SetDeadline(time.Now())
		c2.SetDeadline(time.Now())
	})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer cancel()
		io.Copy(c1, c2)
	}()
	go func() {
		defer wg.Done()
		defer cancel()
		io.Copy(c2, c1)
	}()
	wg.Wait()
	c1.SetDeadline(time.Time{})
	c2.SetDeadline(time.Time{})
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
	if len(*connect) == 0 {
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
				handleTCPConnection(ctx, dtlsConn, *connect)
			} else {
				handleUDPConnection(ctx, dtlsConn, *connect, manager)
			}
			log.Printf("Connection closed: %s", conn.RemoteAddr())
		}(conn)
	}
}
