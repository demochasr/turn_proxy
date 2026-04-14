// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bschaatsbergen/dnsdialer"
	"github.com/cacggghp/vk-turn-proxy/bootstrap"
	"github.com/cacggghp/vk-turn-proxy/tcputil"
	"github.com/cbeuw/connutil"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
	"github.com/xtaci/smux"
)

type getCredsFunc func(string) (string, string, string, error)

func getVkCreds(link string, dialer *dnsdialer.Dialer) (string, string, string, error) {

	doRequest := func(data string, url string) (resp map[string]interface{}, err error) {

		client := &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
				DialContext:         dialer.DialContext,
			},
		}
		defer client.CloseIdleConnections()
		req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, err
		}

		req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0")
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() {
			if closeErr := httpResp.Body.Close(); closeErr != nil {
				log.Printf("close response body: %s", closeErr)
			}
		}()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(body, &resp)
		if err != nil {
			return nil, err
		}

		return resp, nil
	}

	var resp map[string]interface{}
	defer func() {
		if r := recover(); r != nil {
			log.Panicf("get TURN creds error: %v\n\n", resp)
		}
	}()

	data := "client_id=6287487&token_type=messages&client_secret=QbYic1K3lEV5kTGiqlq2&version=1&app_id=6287487"
	url := "https://login.vk.ru/?act=get_anonym_token"

	resp, err := doRequest(data, url)
	if err != nil {
		return "", "", "", fmt.Errorf("request error:%s", err)
	}

	token1 := resp["data"].(map[string]interface{})["access_token"].(string)

	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=123&access_token=%s", link, token1)
	url = "https://api.vk.ru/method/calls.getAnonymousToken?v=5.274&client_id=6287487"

	resp, err = doRequest(data, url)
	if err != nil {
		return "", "", "", fmt.Errorf("request error:%s", err)
	}

	token2 := resp["response"].(map[string]interface{})["token"].(string)

	data = fmt.Sprintf("%s%s%s", "session_data=%7B%22version%22%3A2%2C%22device_id%22%3A%22", uuid.New(), "%22%2C%22client_version%22%3A1.1%2C%22client_type%22%3A%22SDK_JS%22%7D&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA")
	url = "https://calls.okcdn.ru/fb.do"

	resp, err = doRequest(data, url)
	if err != nil {
		return "", "", "", fmt.Errorf("request error:%s", err)
	}

	token3 := resp["session_key"].(string)

	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", link, token2, token3)
	url = "https://calls.okcdn.ru/fb.do"

	resp, err = doRequest(data, url)
	if err != nil {
		return "", "", "", fmt.Errorf("request error:%s", err)
	}

	user := resp["turn_server"].(map[string]interface{})["username"].(string)
	pass := resp["turn_server"].(map[string]interface{})["credential"].(string)
	turn := resp["turn_server"].(map[string]interface{})["urls"].([]interface{})[0].(string)

	clean := strings.Split(turn, "?")[0]
	address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")

	return user, pass, address, nil
}

func getYandexCreds(link string) (string, string, string, error) {
	const debug = false
	const telemostConfHost = "cloud-api.yandex.ru"
	telemostConfPath := fmt.Sprintf("%s%s%s", "/telemost_front/v2/telemost/conferences/https%3A%2F%2Ftelemost.yandex.ru%2Fj%2F", link, "/connection?next_gen_media_platform_allowed=false")
	const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0"

	type ConferenceResponse struct {
		URI                 string `json:"uri"`
		RoomID              string `json:"room_id"`
		PeerID              string `json:"peer_id"`
		ClientConfiguration struct {
			MediaServerURL string `json:"media_server_url"`
		} `json:"client_configuration"`
		Credentials string `json:"credentials"`
	}

	type PartMeta struct {
		Name        string `json:"name"`
		Role        string `json:"role"`
		Description string `json:"description"`
		SendAudio   bool   `json:"sendAudio"`
		SendVideo   bool   `json:"sendVideo"`
	}

	type PartAttrs struct {
		Name        string `json:"name"`
		Role        string `json:"role"`
		Description string `json:"description"`
	}

	type SdkInfo struct {
		Implementation string `json:"implementation"`
		Version        string `json:"version"`
		UserAgent      string `json:"userAgent"`
		HwConcurrency  int    `json:"hwConcurrency"`
	}

	type Capabilities struct {
		OfferAnswerMode             []string `json:"offerAnswerMode"`
		InitialSubscriberOffer      []string `json:"initialSubscriberOffer"`
		SlotsMode                   []string `json:"slotsMode"`
		SimulcastMode               []string `json:"simulcastMode"`
		SelfVadStatus               []string `json:"selfVadStatus"`
		DataChannelSharing          []string `json:"dataChannelSharing"`
		VideoEncoderConfig          []string `json:"videoEncoderConfig"`
		DataChannelVideoCodec       []string `json:"dataChannelVideoCodec"`
		BandwidthLimitationReason   []string `json:"bandwidthLimitationReason"`
		SdkDefaultDeviceManagement  []string `json:"sdkDefaultDeviceManagement"`
		JoinOrderLayout             []string `json:"joinOrderLayout"`
		PinLayout                   []string `json:"pinLayout"`
		SendSelfViewVideoSlot       []string `json:"sendSelfViewVideoSlot"`
		ServerLayoutTransition      []string `json:"serverLayoutTransition"`
		SdkPublisherOptimizeBitrate []string `json:"sdkPublisherOptimizeBitrate"`
		SdkNetworkLostDetection     []string `json:"sdkNetworkLostDetection"`
		SdkNetworkPathMonitor       []string `json:"sdkNetworkPathMonitor"`
		PublisherVp9                []string `json:"publisherVp9"`
		SvcMode                     []string `json:"svcMode"`
		SubscriberOfferAsyncAck     []string `json:"subscriberOfferAsyncAck"`
		SvcModes                    []string `json:"svcModes"`
		ReportTelemetryModes        []string `json:"reportTelemetryModes"`
		KeepDefaultDevicesModes     []string `json:"keepDefaultDevicesModes"`
	}

	type HelloPayload struct {
		ParticipantMeta        PartMeta     `json:"participantMeta"`
		ParticipantAttributes  PartAttrs    `json:"participantAttributes"`
		SendAudio              bool         `json:"sendAudio"`
		SendVideo              bool         `json:"sendVideo"`
		SendSharing            bool         `json:"sendSharing"`
		ParticipantID          string       `json:"participantId"`
		RoomID                 string       `json:"roomId"`
		ServiceName            string       `json:"serviceName"`
		Credentials            string       `json:"credentials"`
		CapabilitiesOffer      Capabilities `json:"capabilitiesOffer"`
		SdkInfo                SdkInfo      `json:"sdkInfo"`
		SdkInitializationID    string       `json:"sdkInitializationId"`
		DisablePublisher       bool         `json:"disablePublisher"`
		DisableSubscriber      bool         `json:"disableSubscriber"`
		DisableSubscriberAudio bool         `json:"disableSubscriberAudio"`
	}

	type HelloRequest struct {
		UID   string       `json:"uid"`
		Hello HelloPayload `json:"hello"`
	}

	type FlexUrls []string

	type WSSResponse struct {
		UID         string `json:"uid"`
		ServerHello struct {
			RtcConfiguration struct {
				IceServers []struct {
					Urls       FlexUrls `json:"urls"`
					Username   string   `json:"username,omitempty"`
					Credential string   `json:"credential,omitempty"`
				} `json:"iceServers"`
			} `json:"rtcConfiguration"`
		} `json:"serverHello"`
	}

	type WSSAck struct {
		Uid string `json:"uid"`
		Ack struct {
			Status struct {
				Code string `json:"code"`
			} `json:"status"`
		} `json:"ack"`
	}

	type WSSData struct {
		ParticipantId string
		RoomId        string
		Credentials   string
		Wss           string
	}

	endpoint := "https://" + telemostConfHost + telemostConfPath
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", "https://telemost.yandex.ru/")
	req.Header.Set("Origin", "https://telemost.yandex.ru")
	req.Header.Set("Client-Instance-Id", uuid.New().String())

	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("close response body: %s", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", "", "", fmt.Errorf("GetConference: status=%s body=%s", resp.Status, string(body))
	}

	var result ConferenceResponse
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", "", fmt.Errorf("decode conf: %v", err)
	}
	data := WSSData{
		ParticipantId: result.PeerID,
		RoomId:        result.RoomID,
		Credentials:   result.Credentials,
		Wss:           result.ClientConfiguration.MediaServerURL,
	}
	h := http.Header{}
	h.Set("Origin", "https://telemost.yandex.ru")
	h.Set("User-Agent", userAgent)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dialer := websocket.Dialer{}
	conn, _, err := dialer.DialContext(ctx, data.Wss, h)
	if err != nil {
		return "", "", "", fmt.Errorf("ws dial: %w", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			log.Printf("close websocket: %s", closeErr)
		}
	}()

	req1 := HelloRequest{
		UID: uuid.New().String(),
		Hello: HelloPayload{
			ParticipantMeta: PartMeta{
				Name:        "Гость",
				Role:        "SPEAKER",
				Description: "",
				SendAudio:   false,
				SendVideo:   false,
			},
			ParticipantAttributes: PartAttrs{
				Name:        "Гость",
				Role:        "SPEAKER",
				Description: "",
			},
			SendAudio:   false,
			SendVideo:   false,
			SendSharing: false,

			ParticipantID: data.ParticipantId,
			RoomID:        data.RoomId,
			ServiceName:   "telemost",
			Credentials:   data.Credentials,
			SdkInfo: SdkInfo{
				Implementation: "browser",
				Version:        "5.15.0",
				UserAgent:      userAgent,
				HwConcurrency:  4,
			},
			SdkInitializationID:    uuid.New().String(),
			DisablePublisher:       false,
			DisableSubscriber:      false,
			DisableSubscriberAudio: false,
			CapabilitiesOffer: Capabilities{
				OfferAnswerMode:             []string{"SEPARATE"},
				InitialSubscriberOffer:      []string{"ON_HELLO"},
				SlotsMode:                   []string{"FROM_CONTROLLER"},
				SimulcastMode:               []string{"DISABLED"},
				SelfVadStatus:               []string{"FROM_SERVER"},
				DataChannelSharing:          []string{"TO_RTP"},
				VideoEncoderConfig:          []string{"NO_CONFIG"},
				DataChannelVideoCodec:       []string{"VP8"},
				BandwidthLimitationReason:   []string{"BANDWIDTH_REASON_DISABLED"},
				SdkDefaultDeviceManagement:  []string{"SDK_DEFAULT_DEVICE_MANAGEMENT_DISABLED"},
				JoinOrderLayout:             []string{"JOIN_ORDER_LAYOUT_DISABLED"},
				PinLayout:                   []string{"PIN_LAYOUT_DISABLED"},
				SendSelfViewVideoSlot:       []string{"SEND_SELF_VIEW_VIDEO_SLOT_DISABLED"},
				ServerLayoutTransition:      []string{"SERVER_LAYOUT_TRANSITION_DISABLED"},
				SdkPublisherOptimizeBitrate: []string{"SDK_PUBLISHER_OPTIMIZE_BITRATE_DISABLED"},
				SdkNetworkLostDetection:     []string{"SDK_NETWORK_LOST_DETECTION_DISABLED"},
				SdkNetworkPathMonitor:       []string{"SDK_NETWORK_PATH_MONITOR_DISABLED"},
				PublisherVp9:                []string{"PUBLISH_VP9_DISABLED"},
				SvcMode:                     []string{"SVC_MODE_DISABLED"},
				SubscriberOfferAsyncAck:     []string{"SUBSCRIBER_OFFER_ASYNC_ACK_DISABLED"},
				SvcModes:                    []string{"FALSE"},
				ReportTelemetryModes:        []string{"TRUE"},
				KeepDefaultDevicesModes:     []string{"TRUE"},
			},
		},
	}

	if debug {
		b, _ := json.MarshalIndent(req1, "", "  ")
		log.Printf("Sending HELLO:\n%s", string(b))
	}

	if err := conn.WriteJSON(req1); err != nil {
		return "", "", "", fmt.Errorf("ws write: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return "", "", "", fmt.Errorf("ws set read deadline: %w", err)
	}

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return "", "", "", fmt.Errorf("ws read: %w", err)
		}
		if debug {
			s := string(msg)
			if len(s) > 800 {
				s = s[:800] + "...(truncated)"
			}
			log.Printf("WSS recv: %s", s)
		}

		var ack WSSAck
		if err := json.Unmarshal(msg, &ack); err == nil && ack.Ack.Status.Code != "" {
			continue
		}

		var resp WSSResponse
		if err := json.Unmarshal(msg, &resp); err == nil {
			ice := resp.ServerHello.RtcConfiguration.IceServers
			for _, s := range ice {
				for _, u := range s.Urls {
					if !strings.HasPrefix(u, "turn:") && !strings.HasPrefix(u, "turns:") {
						continue
					}
					if strings.Contains(u, "transport=tcp") {
						continue
					}
					clean := strings.Split(u, "?")[0]
					address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")

					return s.Username, s.Credential, address, nil
				}
			}
		}
	}
}

func dtlsFunc(ctx context.Context, conn net.PacketConn, peer *net.UDPAddr) (net.Conn, error) {
	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, err
	}
	config := &dtls.Config{
		Certificates:          []tls.Certificate{certificate},
		InsecureSkipVerify:    true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
	}
	ctx1, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	dtlsConn, err := dtls.Client(conn, peer, config)
	if err != nil {
		return nil, err
	}

	if err := dtlsConn.HandshakeContext(ctx1); err != nil {
		return nil, err
	}
	return dtlsConn, nil
}

func oneDtlsConnection(ctx context.Context, peer *net.UDPAddr, listenConn net.PacketConn, connchan chan<- net.PacketConn, okchan chan<- struct{}, c chan<- error, sessionID []byte, streamID byte, bootstrapToken string) {
	var err error = nil
	defer func() { c <- err }()
	dtlsctx, dtlscancel := context.WithCancel(ctx)
	defer dtlscancel()
	var conn1, conn2 net.PacketConn
	conn1, conn2 = connutil.AsyncPacketPipe()
	go func() {
		for {
			select {
			case <-dtlsctx.Done():
				return
			case connchan <- conn2:
			}
		}
	}()
	dtlsConn, err1 := dtlsFunc(dtlsctx, conn1, peer)
	if err1 != nil {
		err = fmt.Errorf("failed to connect DTLS: %s", err1)
		return
	}
	defer func() {
		if closeErr := dtlsConn.Close(); closeErr != nil {
			err = fmt.Errorf("failed to close DTLS connection: %s", closeErr)
			return
		}
		log.Printf("Closed DTLS connection\n")
	}()
	log.Printf("Established DTLS connection!\n")
	if bootstrapToken != "" {
		if err1 := bootstrap.Write(dtlsConn, bootstrapToken); err1 != nil {
			err = fmt.Errorf("failed to write bootstrap token: %s", err1)
			return
		}
	}
	if len(sessionID) == 16 {
		header := append(append([]byte{}, sessionID...), streamID)
		if _, err1 := dtlsConn.Write(header); err1 != nil {
			err = fmt.Errorf("failed to write session header: %s", err1)
			return
		}
	}
	go func() {
		for {
			select {
			case <-dtlsctx.Done():
				return
			case okchan <- struct{}{}:
			}
		}
	}()

	wg := sync.WaitGroup{}
	wg.Add(2)
	context.AfterFunc(dtlsctx, func() {
		if err := listenConn.SetDeadline(time.Now()); err != nil {
			log.Printf("Failed to set listener deadline: %s", err)
		}
		if err := dtlsConn.SetDeadline(time.Now()); err != nil {
			log.Printf("Failed to set DTLS deadline: %s", err)
		}
	})
	var addr atomic.Value
	// Start read-loop on listenConn
	go func() {
		defer wg.Done()
		defer dtlscancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-dtlsctx.Done():
				return
			default:
			}
			n, addr1, err1 := listenConn.ReadFrom(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}

			addr.Store(addr1) // store peer

			_, err1 = dtlsConn.Write(buf[:n])
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()

	// Start read-loop on dtlsConn
	go func() {
		defer wg.Done()
		defer dtlscancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-dtlsctx.Done():
				return
			default:
			}
			n, err1 := dtlsConn.Read(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			addr1, ok := addr.Load().(net.Addr)
			if !ok {
				log.Printf("Failed: no listener ip")
				return
			}

			_, err1 = listenConn.WriteTo(buf[:n], addr1)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()

	wg.Wait()
	if err := listenConn.SetDeadline(time.Time{}); err != nil {
		log.Printf("Failed to clear listener deadline: %s", err)
	}
	if err := dtlsConn.SetDeadline(time.Time{}); err != nil {
		log.Printf("Failed to clear DTLS deadline: %s", err)
	}
}

type connectedUDPConn struct {
	*net.UDPConn
}

func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Write(p)
}

type turnParams struct {
	host           string
	port           string
	link           string
	udp            bool
	bootstrapToken string
	turnUser       string
	turnPass       string
	turnAddr       string
	getCreds       getCredsFunc
}

func resolveTurnCredentials(turnParams *turnParams) (string, string, string, error) {
	if turnParams.turnUser != "" || turnParams.turnPass != "" || turnParams.turnAddr != "" {
		if turnParams.turnUser == "" || turnParams.turnPass == "" || turnParams.turnAddr == "" {
			return "", "", "", fmt.Errorf("static TURN override requires turn-user, turn-pass, and turn-addr")
		}
		return turnParams.turnUser, turnParams.turnPass, turnParams.turnAddr, nil
	}

	user, pass, url, err := turnParams.getCreds(turnParams.link)
	if err != nil {
		return "", "", "", err
	}
	return user, pass, url, nil
}

func resolveTurnServerAddr(turnParams *turnParams) (string, string, string, *net.UDPAddr, error) {
	user, pass, url, err := resolveTurnCredentials(turnParams)
	if err != nil {
		return "", "", "", nil, err
	}

	urlhost, urlport, err := net.SplitHostPort(url)
	if err != nil {
		return "", "", "", nil, fmt.Errorf("failed to parse TURN server address: %w", err)
	}
	if turnParams.host != "" {
		urlhost = turnParams.host
	}
	if turnParams.port != "" {
		urlport = turnParams.port
	}
	turnServerAddr := net.JoinHostPort(urlhost, urlport)
	turnServerUDPAddr, err := net.ResolveUDPAddr("udp", turnServerAddr)
	if err != nil {
		return "", "", "", nil, fmt.Errorf("failed to resolve TURN server address: %w", err)
	}
	return user, pass, turnServerUDPAddr.String(), turnServerUDPAddr, nil
}

func oneTurnConnection(ctx context.Context, turnParams *turnParams, peer *net.UDPAddr, conn2 net.PacketConn, c chan<- error) {
	var err error = nil
	defer func() { c <- err }()
	user, pass, turnServerAddr, turnServerUDPAddr, err1 := resolveTurnServerAddr(turnParams)
	if err1 != nil {
		err = fmt.Errorf("failed to get TURN credentials: %s", err1)
		return
	}
	fmt.Println(turnServerUDPAddr.IP)
	// Dial TURN Server
	var cfg *turn.ClientConfig
	var turnConn net.PacketConn
	var d net.Dialer
	ctx1, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if turnParams.udp {
		conn, err2 := net.DialUDP("udp", nil, turnServerUDPAddr) // nolint: noctx
		if err2 != nil {
			err = fmt.Errorf("failed to connect to TURN server: %s", err2)
			return
		}
		defer func() {
			if err1 = conn.Close(); err1 != nil {
				err = fmt.Errorf("failed to close TURN server connection: %s", err1)
				return
			}
		}()
		turnConn = &connectedUDPConn{conn}
	} else {
		conn, err2 := d.DialContext(ctx1, "tcp", turnServerAddr) // nolint: noctx
		if err2 != nil {
			err = fmt.Errorf("failed to connect to TURN server: %s", err2)
			return
		}
		defer func() {
			if err1 = conn.Close(); err1 != nil {
				err = fmt.Errorf("failed to close TURN server connection: %s", err1)
				return
			}
		}()
		turnConn = turn.NewSTUNConn(conn)
	}
	var addrFamily turn.RequestedAddressFamily
	if peer.IP.To4() != nil {
		addrFamily = turn.RequestedAddressFamilyIPv4
	} else {
		addrFamily = turn.RequestedAddressFamilyIPv6
	}
	// Start a new TURN Client and wrap our net.Conn in a STUNConn
	// This allows us to simulate datagram based communication over a net.Conn
	cfg = &turn.ClientConfig{
		STUNServerAddr:         turnServerAddr,
		TURNServerAddr:         turnServerAddr,
		Conn:                   turnConn,
		Username:               user,
		Password:               pass,
		RequestedAddressFamily: addrFamily,
		LoggerFactory:          logging.NewDefaultLoggerFactory(),
	}

	client, err1 := turn.NewClient(cfg)
	if err1 != nil {
		err = fmt.Errorf("failed to create TURN client: %s", err1)
		return
	}
	defer client.Close()

	// Start listening on the conn provided.
	err1 = client.Listen()
	if err1 != nil {
		err = fmt.Errorf("failed to listen: %s", err1)
		return
	}

	// Allocate a relay socket on the TURN server. On success, it
	// will return a net.PacketConn which represents the remote
	// socket.
	relayConn, err1 := client.Allocate()
	if err1 != nil {
		err = fmt.Errorf("failed to allocate: %s", err1)
		return
	}
	defer func() {
		if err1 := relayConn.Close(); err1 != nil {
			err = fmt.Errorf("failed to close TURN allocated connection: %s", err1)
		}
	}()

	// The relayConn's local address is actually the transport
	// address assigned on the TURN server.
	log.Printf("relayed-address=%s", relayConn.LocalAddr().String())

	wg := sync.WaitGroup{}
	wg.Add(2)
	turnctx, turncancel := context.WithCancel(context.Background())
	context.AfterFunc(turnctx, func() {
		if err := relayConn.SetDeadline(time.Now()); err != nil {
			log.Printf("Failed to set relay deadline: %s", err)
		}
		if err := conn2.SetDeadline(time.Now()); err != nil {
			log.Printf("Failed to set upstream deadline: %s", err)
		}
	})
	var addr atomic.Value
	// Start read-loop on conn2 (output of DTLS)
	go func() {
		defer wg.Done()
		defer turncancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-turnctx.Done():
				return
			default:
			}
			n, addr1, err1 := conn2.ReadFrom(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}

			addr.Store(addr1) // store peer

			_, err1 = relayConn.WriteTo(buf[:n], peer)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()

	// Start read-loop on relayConn
	go func() {
		defer wg.Done()
		defer turncancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-turnctx.Done():
				return
			default:
			}
			n, _, err1 := relayConn.ReadFrom(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			addr1, ok := addr.Load().(net.Addr)
			if !ok {
				log.Printf("Failed: no listener ip")
				return
			}

			_, err1 = conn2.WriteTo(buf[:n], addr1)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()

	wg.Wait()
	if err := relayConn.SetDeadline(time.Time{}); err != nil {
		log.Printf("Failed to clear relay deadline: %s", err)
	}
	if err := conn2.SetDeadline(time.Time{}); err != nil {
		log.Printf("Failed to clear upstream deadline: %s", err)
	}
}

func oneDtlsConnectionLoop(ctx context.Context, peer *net.UDPAddr, listenConnChan <-chan net.PacketConn, connchan chan<- net.PacketConn, okchan chan<- struct{}, sessionID []byte, streamID byte, bootstrapToken string) {
	for {
		select {
		case <-ctx.Done():
			return
		case listenConn := <-listenConnChan:
			c := make(chan error)
			go oneDtlsConnection(ctx, peer, listenConn, connchan, okchan, c, sessionID, streamID, bootstrapToken)
			if err := <-c; err != nil {
				log.Printf("%s", err)
			}
		}
	}
}

func oneTurnConnectionLoop(ctx context.Context, turnParams *turnParams, peer *net.UDPAddr, connchan <-chan net.PacketConn, t <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case conn2 := <-connchan:
			select {
			case <-t:
				c := make(chan error)
				go oneTurnConnection(ctx, turnParams, peer, conn2, c)
				if err := <-c; err != nil {
					log.Printf("%s", err)
				}
			default:
			}
		}
	}
}

func main() { //nolint:cyclop
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signalChan
		log.Printf("Terminating...\n")
		cancel()
		select {
		case <-signalChan:
		case <-time.After(5 * time.Second):
		}
		log.Fatalf("Exit...\n")
	}()

	host := flag.String("turn", "", "override TURN server ip")
	port := flag.String("port", "", "override TURN port")
	listen := flag.String("listen", "127.0.0.1:9000", "listen on ip:port")
	vklink := flag.String("vk-link", "", "VK calls invite link \"https://vk.com/call/join/...\"")
	yalink := flag.String("yandex-link", "", "Yandex telemost invite link \"https://telemost.yandex.ru/j/...\"")
	peerAddr := flag.String("peer", "", "peer server address (host:port)")
	n := flag.Int("n", 0, "connections to TURN (default 16 for VK, 1 for Yandex)")
	udp := flag.Bool("udp", false, "connect to TURN with UDP")
	direct := flag.Bool("no-dtls", false, "connect without obfuscation. DO NOT USE")
	tcpMode := flag.Bool("tcp", false, "TCP mode: forward TCP connections (for VLESS) instead of UDP packets")
	sessionIDFlag := flag.String("session-id", "", "override session ID (hex, 32 chars)")
	bootstrapToken := flag.String("bootstrap-token", "", "short-lived TURN bootstrap token from API")
	turnUser := flag.String("turn-user", "", "static TURN username override")
	turnPass := flag.String("turn-pass", "", "static TURN password override")
	turnAddr := flag.String("turn-addr", "", "static TURN server address override (host:port)")
	flag.Parse()
	if *peerAddr == "" {
		log.Panicf("Need peer address!")
	}
	peer, err := net.ResolveUDPAddr("udp", *peerAddr)
	if err != nil {
		panic(err)
	}
	staticTurn := *turnUser != "" || *turnPass != "" || *turnAddr != ""
	if staticTurn && (*turnUser == "" || *turnPass == "" || *turnAddr == "") {
		log.Panicf("Need turn-user, turn-pass and turn-addr together")
	}
	if !staticTurn && (*vklink == "") == (*yalink == "") {
		log.Panicf("Need either vk-link or yandex-link!")
	}

	var link string
	var getCreds getCredsFunc
	if staticTurn {
		if *n <= 0 {
			*n = 1
		}
		getCreds = func(string) (string, string, string, error) {
			return *turnUser, *turnPass, *turnAddr, nil
		}
	} else if *vklink != "" {
		parts := strings.Split(*vklink, "join/")
		link = parts[len(parts)-1]

		dialer := dnsdialer.New(
			dnsdialer.WithResolvers("77.88.8.8:53", "77.88.8.1:53", "8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53"),
			dnsdialer.WithStrategy(dnsdialer.Fallback{}),
			dnsdialer.WithCache(100, 10*time.Hour, 10*time.Hour),
		)

		getCreds = func(s string) (string, string, string, error) {
			return getVkCreds(s, dialer)
		}
		if *n <= 0 {
			*n = 16
		}
	} else {
		parts := strings.Split(*yalink, "j/")
		link = parts[len(parts)-1]
		getCreds = getYandexCreds
		if *n <= 0 {
			*n = 1
		}
	}
	if idx := strings.IndexAny(link, "/?#"); idx != -1 {
		link = link[:idx]
	}
	params := &turnParams{
		host:           *host,
		port:           *port,
		link:           link,
		udp:            *udp,
		bootstrapToken: *bootstrapToken,
		turnUser:       *turnUser,
		turnPass:       *turnPass,
		turnAddr:       *turnAddr,
		getCreds:       getCreds,
	}

	var sessionID []byte
	if *sessionIDFlag != "" {
		sessionID = make([]byte, 16)
		if _, err := fmt.Sscanf(*sessionIDFlag, "%x", &sessionID); err != nil {
			log.Panicf("Invalid session ID: %v", err)
		}
	} else {
		sessionID, _ = uuid.New().MarshalBinary()
	}
	log.Printf("Session ID: %x", sessionID)

	if *tcpMode {
		runVLESSMode(ctx, params, peer, *listen, *n, sessionID)
		return
	}

	listenConnChan := make(chan net.PacketConn)
	listenConn, err := net.ListenPacket("udp", *listen) // nolint: noctx
	if err != nil {
		log.Panicf("Failed to listen: %s", err)
	}
	context.AfterFunc(ctx, func() {
		if closeErr := listenConn.Close(); closeErr != nil {
			log.Panicf("Failed to close local connection: %s", closeErr)
		}
	})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case listenConnChan <- listenConn:
			}
		}
	}()

	wg1 := sync.WaitGroup{}
	t := time.Tick(200 * time.Millisecond)
	if *direct {
		for i := 0; i < *n; i++ {
			wg1.Go(func() {
				oneTurnConnectionLoop(ctx, params, peer, listenConnChan, t)
			})
		}
	} else {
		okchan := make(chan struct{})
		connchan := make(chan net.PacketConn)

		wg1.Go(func() {
			oneDtlsConnectionLoop(ctx, peer, listenConnChan, connchan, okchan, sessionID, 0, *bootstrapToken)
		})

		wg1.Go(func() {
			oneTurnConnectionLoop(ctx, params, peer, connchan, t)
		})

		select {
		case <-okchan:
		case <-ctx.Done():
		}
		for i := 0; i < *n-1; i++ {
			connchan := make(chan net.PacketConn)
			streamID := byte(i + 1)
			wg1.Go(func() {
				oneDtlsConnectionLoop(ctx, peer, listenConnChan, connchan, nil, sessionID, streamID, *bootstrapToken)
			})
			wg1.Go(func() {
				oneTurnConnectionLoop(ctx, params, peer, connchan, t)
			})
		}
	}

	wg1.Wait()
}

type dtlsStreamEntry struct {
	id   byte
	conn net.Conn
	done chan struct{}
}

type multipathDTLSConn struct {
	ctx           context.Context
	cancel        context.CancelFunc
	mu            sync.RWMutex
	conns         []dtlsStreamEntry
	recvCh        chan receivedPacket
	writeSeq      atomic.Uint64
	readyCh       chan struct{}
	readyOnce     sync.Once
	deadlineMu    sync.RWMutex
	readDeadline  time.Time
	writeDeadline time.Time
	addrMu        sync.RWMutex
	lastLocalAddr net.Addr
	lastPeerAddr  net.Addr
}

type receivedPacket struct {
	payload    []byte
	localAddr  net.Addr
	remoteAddr net.Addr
}

func newMultipathDTLSConn(ctx context.Context) *multipathDTLSConn {
	sessionCtx, cancel := context.WithCancel(ctx)
	return &multipathDTLSConn{
		ctx:     sessionCtx,
		cancel:  cancel,
		conns:   make([]dtlsStreamEntry, 0),
		recvCh:  make(chan receivedPacket, 1024),
		readyCh: make(chan struct{}),
	}
}

func (m *multipathDTLSConn) AddConn(id byte, conn net.Conn) <-chan struct{} {
	done := make(chan struct{})

	m.mu.Lock()
	for i, entry := range m.conns {
		if entry.id == id {
			_ = entry.conn.Close()
			m.conns[i] = dtlsStreamEntry{id: id, conn: conn, done: done}
			m.mu.Unlock()
			m.readyOnce.Do(func() { close(m.readyCh) })
			go m.connReadLoop(id, conn, done)
			return done
		}
	}
	m.conns = append(m.conns, dtlsStreamEntry{id: id, conn: conn, done: done})
	m.mu.Unlock()

	m.readyOnce.Do(func() { close(m.readyCh) })
	go m.connReadLoop(id, conn, done)
	return done
}

func (m *multipathDTLSConn) RemoveConn(id byte, conn net.Conn) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, entry := range m.conns {
		if entry.id == id && entry.conn == conn {
			m.conns = append(m.conns[:i], m.conns[i+1:]...)
			return
		}
	}
}

func (m *multipathDTLSConn) connReadLoop(id byte, conn net.Conn, done chan struct{}) {
	defer close(done)
	defer m.RemoveConn(id, conn)

	buf := make([]byte, 2048)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Minute)); err != nil {
			log.Printf("[stream %d] read deadline error: %v", id, err)
			return
		}
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("[stream %d] closed: %v", id, err)
			return
		}

		packet := receivedPacket{
			payload:    append([]byte(nil), buf[:n]...),
			localAddr:  conn.LocalAddr(),
			remoteAddr: conn.RemoteAddr(),
		}
		select {
		case <-m.ctx.Done():
			return
		case m.recvCh <- packet:
		}
	}
}

func (m *multipathDTLSConn) waitReady(ctx context.Context) bool {
	if m.activeCount() > 0 {
		return true
	}
	select {
	case <-ctx.Done():
		return false
	case <-m.ctx.Done():
		return false
	case <-m.readyCh:
		return true
	}
}

func (m *multipathDTLSConn) activeCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.conns)
}

func (m *multipathDTLSConn) pickConn() (net.Conn, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.conns) == 0 {
		return nil, fmt.Errorf("no active DTLS connections")
	}
	idx := int(m.writeSeq.Add(1)-1) % len(m.conns)
	return m.conns[idx].conn, nil
}

func (m *multipathDTLSConn) Read(b []byte) (int, error) {
	for {
		var deadline <-chan time.Time
		if d := m.getReadDeadline(); !d.IsZero() {
			timer := time.NewTimer(time.Until(d))
			defer timer.Stop()
			deadline = timer.C
		}

		select {
		case <-m.ctx.Done():
			return 0, net.ErrClosed
		case <-deadline:
			return 0, os.ErrDeadlineExceeded
		case packet := <-m.recvCh:
			m.setLastReadAddrs(packet.localAddr, packet.remoteAddr)
			n := copy(b, packet.payload)
			return n, nil
		}
	}
}

func (m *multipathDTLSConn) Write(b []byte) (int, error) {
	conn, err := m.pickConn()
	if err != nil {
		return 0, err
	}
	if deadline := m.getWriteDeadline(); !deadline.IsZero() {
		if err := conn.SetWriteDeadline(deadline); err != nil {
			return 0, err
		}
	}
	return conn.Write(b)
}

func (m *multipathDTLSConn) Close() error {
	m.cancel()

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, entry := range m.conns {
		_ = entry.conn.Close()
	}
	m.conns = nil
	return nil
}

func (m *multipathDTLSConn) LocalAddr() net.Addr {
	if addr := m.getLastLocalAddr(); addr != nil {
		return addr
	}
	if conn, err := m.pickConn(); err == nil {
		return conn.LocalAddr()
	}
	return dummyAddr("multipath-local")
}

func (m *multipathDTLSConn) RemoteAddr() net.Addr {
	if addr := m.getLastPeerAddr(); addr != nil {
		return addr
	}
	if conn, err := m.pickConn(); err == nil {
		return conn.RemoteAddr()
	}
	return dummyAddr("multipath-remote")
}

func (m *multipathDTLSConn) SetDeadline(t time.Time) error {
	m.deadlineMu.Lock()
	m.readDeadline = t
	m.writeDeadline = t
	m.deadlineMu.Unlock()
	return nil
}

func (m *multipathDTLSConn) SetReadDeadline(t time.Time) error {
	m.deadlineMu.Lock()
	m.readDeadline = t
	m.deadlineMu.Unlock()
	return nil
}

func (m *multipathDTLSConn) SetWriteDeadline(t time.Time) error {
	m.deadlineMu.Lock()
	m.writeDeadline = t
	m.deadlineMu.Unlock()
	return nil
}

func (m *multipathDTLSConn) getReadDeadline() time.Time {
	m.deadlineMu.RLock()
	defer m.deadlineMu.RUnlock()
	return m.readDeadline
}

func (m *multipathDTLSConn) getWriteDeadline() time.Time {
	m.deadlineMu.RLock()
	defer m.deadlineMu.RUnlock()
	return m.writeDeadline
}

func (m *multipathDTLSConn) setLastReadAddrs(localAddr, peerAddr net.Addr) {
	m.addrMu.Lock()
	m.lastLocalAddr = localAddr
	m.lastPeerAddr = peerAddr
	m.addrMu.Unlock()
}

func (m *multipathDTLSConn) getLastLocalAddr() net.Addr {
	m.addrMu.RLock()
	defer m.addrMu.RUnlock()
	return m.lastLocalAddr
}

func (m *multipathDTLSConn) getLastPeerAddr() net.Addr {
	m.addrMu.RLock()
	defer m.addrMu.RUnlock()
	return m.lastPeerAddr
}

type smuxHolder struct {
	mu        sync.RWMutex
	session   *smux.Session
	readyCh   chan struct{}
	readyOnce sync.Once
}

func newSmuxHolder() *smuxHolder {
	return &smuxHolder{readyCh: make(chan struct{})}
}

func (h *smuxHolder) set(s *smux.Session) {
	h.mu.Lock()
	h.session = s
	h.mu.Unlock()
	h.readyOnce.Do(func() { close(h.readyCh) })
}

func (h *smuxHolder) clear(s *smux.Session) {
	h.mu.Lock()
	if h.session == s {
		h.session = nil
	}
	h.mu.Unlock()
}

func (h *smuxHolder) get() *smux.Session {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.session
}

func (h *smuxHolder) waitReady(ctx context.Context) bool {
	if sess := h.get(); sess != nil && !sess.IsClosed() {
		return true
	}
	select {
	case <-ctx.Done():
		return false
	case <-h.readyCh:
		return true
	}
}

type dummyAddr string

func (d dummyAddr) Network() string { return "multipath" }
func (d dummyAddr) String() string  { return string(d) }

// runVLESSMode implements TCP forwarding over one logical KCP+smux session
// backed by N TURN/DTLS legs sharing the same session ID.
func runVLESSMode(ctx context.Context, tp *turnParams, peer *net.UDPAddr, listenAddr string, numSessions int, sessionID []byte) {
	if numSessions <= 0 {
		numSessions = 1
	}

	holder := newSmuxHolder()
	go maintainAggregatedVLESSSession(ctx, tp, peer, numSessions, sessionID, holder)

	log.Printf("TCP mode: waiting for aggregated session to connect (target legs: %d)", numSessions)
	if !holder.waitReady(ctx) {
		return
	}

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Panicf("TCP listen: %s", err)
	}
	context.AfterFunc(ctx, func() { _ = listener.Close() })
	log.Printf("TCP mode: listening on %s (shared smux over %d DTLS legs)", listenAddr, numSessions)

	var wgConn sync.WaitGroup
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				wgConn.Wait()
				return
			default:
			}
			log.Printf("TCP accept error: %s", err)
			continue
		}

		sess := holder.get()
		if sess == nil || sess.IsClosed() {
			log.Printf("No active aggregated smux session, rejecting local TCP connection")
			_ = tcpConn.Close()
			continue
		}
		log.Printf("TCP client accepted local connection from %s", tcpConn.RemoteAddr())

		wgConn.Add(1)
		go func(tc net.Conn, s *smux.Session) {
			defer wgConn.Done()
			defer func() { _ = tc.Close() }()

			log.Printf("Opening smux stream for local connection %s", tc.RemoteAddr())
			stream, err := s.OpenStream()
			if err != nil {
				log.Printf("smux open stream error: %s", err)
				return
			}
			log.Printf("smux stream opened for local connection %s", tc.RemoteAddr())
			defer func() { _ = stream.Close() }()

			pipe(ctx, tc, stream)
		}(tcpConn, sess)
	}
}

func maintainAggregatedVLESSSession(ctx context.Context, tp *turnParams, peer *net.UDPAddr, numSessions int, sessionID []byte, holder *smuxHolder) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		sessionCtx, cancel := context.WithCancel(ctx)
		bundle := newMultipathDTLSConn(sessionCtx)

		var wg sync.WaitGroup
		for i := 0; i < numSessions; i++ {
			wg.Add(1)
			go func(id byte) {
				defer wg.Done()
				select {
				case <-sessionCtx.Done():
					return
				case <-time.After(time.Duration(id) * 300 * time.Millisecond):
				}
				maintainDTLSStream(sessionCtx, tp, peer, id, sessionID, bundle)
			}(byte(i))
		}

		if !bundle.waitReady(sessionCtx) {
			cancel()
			_ = bundle.Close()
			wg.Wait()
			return
		}

		kcpSess, err := tcputil.NewKCPOverDTLS(bundle, false)
		if err != nil {
			log.Printf("aggregated KCP setup error: %s, retrying...", err)
			cancel()
			_ = bundle.Close()
			wg.Wait()
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
			continue
		}
		log.Printf("Aggregated KCP session established")

		smuxSess, err := smux.Client(kcpSess, tcputil.DefaultSmuxConfig())
		if err != nil {
			log.Printf("aggregated smux setup error: %s, retrying...", err)
			_ = kcpSess.Close()
			cancel()
			_ = bundle.Close()
			wg.Wait()
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
			continue
		}

		holder.set(smuxSess)
		log.Printf("Aggregated smux session established")
		log.Printf("Aggregated VLESS session established over %d DTLS legs", numSessions)

		for !smuxSess.IsClosed() {
			select {
			case <-ctx.Done():
				holder.clear(smuxSess)
				_ = smuxSess.Close()
				_ = kcpSess.Close()
				cancel()
				_ = bundle.Close()
				wg.Wait()
				return
			case <-time.After(1 * time.Second):
			}
		}

		holder.clear(smuxSess)
		_ = smuxSess.Close()
		_ = kcpSess.Close()
		cancel()
		_ = bundle.Close()
		wg.Wait()
		log.Printf("Aggregated VLESS session disconnected, reconnecting...")

		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func maintainDTLSStream(ctx context.Context, tp *turnParams, peer *net.UDPAddr, streamID byte, sessionID []byte, bundle *multipathDTLSConn) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		dtlsConn, cleanup, err := createDTLSStream(ctx, tp, peer, sessionID, streamID)
		if err != nil {
			log.Printf("[stream %d] setup error: %s, retrying...", streamID, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
			continue
		}

		done := bundle.AddConn(streamID, dtlsConn)
		log.Printf("[stream %d] connected (active legs: %d)", streamID, bundle.activeCount())

		select {
		case <-ctx.Done():
			cleanup()
			return
		case <-done:
			cleanup()
		}

		log.Printf("[stream %d] disconnected (active legs: %d), reconnecting...", streamID, bundle.activeCount())
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func createDTLSStream(ctx context.Context, tp *turnParams, peer *net.UDPAddr, sessionID []byte, streamID byte) (net.Conn, func(), error) {
	var cleanupFns []func()
	cleanup := func() {
		for i := len(cleanupFns) - 1; i >= 0; i-- {
			cleanupFns[i]()
		}
	}

	user, pass, turnServerAddr, turnServerUDPAddr, err := resolveTurnServerAddr(tp)
	if err != nil {
		return nil, nil, fmt.Errorf("get TURN creds: %w", err)
	}
	fmt.Println(turnServerUDPAddr.IP)

	var turnConn net.PacketConn
	ctx1, cancel1 := context.WithTimeout(ctx, 5*time.Second)
	defer cancel1()
	if tp.udp {
		conn, err := net.DialUDP("udp", nil, turnServerUDPAddr)
		if err != nil {
			return nil, nil, fmt.Errorf("dial TURN (udp): %w", err)
		}
		cleanupFns = append(cleanupFns, func() { _ = conn.Close() })
		turnConn = &connectedUDPConn{conn}
	} else {
		var d net.Dialer
		conn, err := d.DialContext(ctx1, "tcp", turnServerAddr)
		if err != nil {
			return nil, nil, fmt.Errorf("dial TURN (tcp): %w", err)
		}
		cleanupFns = append(cleanupFns, func() { _ = conn.Close() })
		turnConn = turn.NewSTUNConn(conn)
	}

	var addrFamily turn.RequestedAddressFamily
	if peer.IP.To4() != nil {
		addrFamily = turn.RequestedAddressFamilyIPv4
	} else {
		addrFamily = turn.RequestedAddressFamilyIPv6
	}
	cfg := &turn.ClientConfig{
		STUNServerAddr:         turnServerAddr,
		TURNServerAddr:         turnServerAddr,
		Conn:                   turnConn,
		Username:               user,
		Password:               pass,
		RequestedAddressFamily: addrFamily,
		LoggerFactory:          logging.NewDefaultLoggerFactory(),
	}
	turnClient, err := turn.NewClient(cfg)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("create TURN client: %w", err)
	}
	cleanupFns = append(cleanupFns, turnClient.Close)
	if err = turnClient.Listen(); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("TURN listen: %w", err)
	}
	relayConn, err := turnClient.Allocate()
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("TURN allocate: %w", err)
	}
	cleanupFns = append(cleanupFns, func() { _ = relayConn.Close() })
	log.Printf("relayed-address=%s", relayConn.LocalAddr().String())

	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("generate cert: %w", err)
	}

	dtlsPC := &relayPacketConn{relay: relayConn, peer: peer}
	dtlsConfig := &dtls.Config{
		Certificates:          []tls.Certificate{certificate},
		InsecureSkipVerify:    true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
	}

	dtlsConn, err := dtls.Client(dtlsPC, peer, dtlsConfig)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("DTLS client create: %w", err)
	}
	ctx2, cancel2 := context.WithTimeout(ctx, 30*time.Second)
	defer cancel2()
	if err = dtlsConn.HandshakeContext(ctx2); err != nil {
		_ = dtlsConn.Close()
		cleanup()
		return nil, nil, fmt.Errorf("DTLS handshake: %w", err)
	}
	cleanupFns = append(cleanupFns, func() { _ = dtlsConn.Close() })
	log.Printf("DTLS connection established")
	if tp.bootstrapToken != "" {
		if err = bootstrap.Write(dtlsConn, tp.bootstrapToken); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("write bootstrap token: %w", err)
		}
	}
	if len(sessionID) == 16 {
		header := append(append([]byte{}, sessionID...), streamID)
		if _, err = dtlsConn.Write(header); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("write session header: %w", err)
		}
	}
	return dtlsConn, cleanup, nil
}

// relayPacketConn wraps a TURN relay PacketConn to direct all writes to the peer.
type relayPacketConn struct {
	relay net.PacketConn
	peer  net.Addr
}

func (r *relayPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return r.relay.ReadFrom(b)
}

func (r *relayPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return r.relay.WriteTo(b, r.peer)
}

func (r *relayPacketConn) Close() error                       { return r.relay.Close() }
func (r *relayPacketConn) LocalAddr() net.Addr                { return r.relay.LocalAddr() }
func (r *relayPacketConn) SetDeadline(t time.Time) error      { return r.relay.SetDeadline(t) }
func (r *relayPacketConn) SetReadDeadline(t time.Time) error  { return r.relay.SetReadDeadline(t) }
func (r *relayPacketConn) SetWriteDeadline(t time.Time) error { return r.relay.SetWriteDeadline(t) }

// pipe copies data bidirectionally between two connections.
func pipe(ctx context.Context, c1, c2 net.Conn) {
	ctx2, cancel := context.WithCancel(ctx)
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
