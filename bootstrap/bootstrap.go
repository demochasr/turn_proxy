package bootstrap

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	headerMagic = "CTP1"
	maxTokenLen = 4096
)

type Claims struct {
	ProxyID  string `json:"proxy_id"`
	ServerID string `json:"server_id"`
	Mode     string `json:"mode"`
	Protocol string `json:"protocol"`
	jwt.RegisteredClaims
}

func Write(conn net.Conn, token string) error {
	if token == "" {
		return nil
	}
	if len(token) > maxTokenLen {
		return errors.New("bootstrap token too large")
	}
	header := make([]byte, 6)
	copy(header[:4], []byte(headerMagic))
	binary.BigEndian.PutUint16(header[4:], uint16(len(token)))
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write([]byte(token))
	return err
}

func Read(conn net.Conn) (string, error) {
	header := make([]byte, 6)
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return "", err
	}
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}
	if string(header[:4]) != headerMagic {
		return "", errors.New("invalid bootstrap header magic")
	}
	tokenLen := int(binary.BigEndian.Uint16(header[4:]))
	if tokenLen <= 0 || tokenLen > maxTokenLen {
		return "", errors.New("invalid bootstrap token length")
	}
	tokenBuf := make([]byte, tokenLen)
	if _, err := io.ReadFull(conn, tokenBuf); err != nil {
		return "", err
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return "", err
	}
	return string(tokenBuf), nil
}

func normalizeKeyMaterial(raw string) string {
	return strings.ReplaceAll(strings.TrimSpace(raw), `\n`, "\n")
}

func parseECPublicKey(publicKeyPEM string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("invalid public key PEM")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not ECDSA")
	}
	return pub, nil
}

func Verify(tokenString, secret, publicKeyPEM, expectedProxyID, expectedMode string) (*Claims, error) {
	if tokenString == "" {
		return nil, errors.New("missing bootstrap token")
	}
	secret = normalizeKeyMaterial(secret)
	publicKeyPEM = normalizeKeyMaterial(publicKeyPEM)
	if secret == "" && publicKeyPEM == "" {
		return nil, errors.New("missing bootstrap verifier")
	}

	claims := &Claims{}
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		if publicKeyPEM != "" {
			if token.Method.Alg() != jwt.SigningMethodES256.Alg() {
				return nil, fmt.Errorf("unexpected signing method: %s", token.Method.Alg())
			}
			return parseECPublicKey(publicKeyPEM)
		}
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Method.Alg())
		}
		return []byte(secret), nil
	}
	validMethods := []string{jwt.SigningMethodHS256.Alg()}
	if publicKeyPEM != "" {
		validMethods = []string{jwt.SigningMethodES256.Alg()}
	}
	parsed, err := jwt.ParseWithClaims(tokenString, claims, keyFunc, jwt.WithValidMethods(validMethods), jwt.WithIssuedAt(), jwt.WithExpirationRequired())
	if err != nil {
		return nil, err
	}
	if !parsed.Valid {
		return nil, errors.New("bootstrap token invalid")
	}
	if expectedProxyID != "" && claims.ProxyID != expectedProxyID {
		return nil, errors.New("bootstrap token proxy mismatch")
	}
	if expectedMode != "" && claims.Mode != expectedMode {
		return nil, errors.New("bootstrap token mode mismatch")
	}
	return claims, nil
}
