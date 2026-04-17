package cert

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

type FetchOptions struct {
	ServerName string
	Timeout    time.Duration
	ProxyURL   string
}

// FetchFromHost connects to host (hostname or hostname:port) over TLS,
// retrieves the certificate chain, and returns Info for each cert.
func FetchFromHost(host string, opts FetchOptions) ([]*Info, error) {
	hostName, port, err := splitHostPort(host)
	if err != nil {
		return nil, err
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	serverName := opts.ServerName
	if serverName == "" && net.ParseIP(hostName) == nil {
		serverName = hostName
	}

	proxyURL := strings.TrimSpace(opts.ProxyURL)
	if proxyURL == "" {
		proxyURL = strings.TrimSpace(os.Getenv("HTTPS_PROXY"))
	}
	if proxyURL == "" {
		proxyURL = strings.TrimSpace(os.Getenv("https_proxy"))
	}

	dialer := &net.Dialer{Timeout: timeout}
	cfg := &tls.Config{
		InsecureSkipVerify: true, // allow checking expired/self-signed certs too
		ServerName:         serverName,
	}

	targetHostPort := net.JoinHostPort(hostName, port)
	if proxyURL != "" {
		conn, err := dialTLSViaProxy(dialer, targetHostPort, proxyURL, cfg, timeout)
		if err != nil {
			return nil, fmt.Errorf("TLS connection failed via proxy: %w", err)
		}
		defer conn.Close()
		return peerCertificates(conn, host)
	}

	targets := buildDialTargets(hostName, port)

	var lastErr error
	for _, target := range targets {
		conn, err := tls.DialWithDialer(dialer, "tcp", target, cfg)
		if err != nil {
			lastErr = err
			continue
		}
		defer conn.Close()

		return peerCertificates(conn, host)
	}

	if lastErr != nil {
		return nil, fmt.Errorf("TLS connection failed: %w", lastErr)
	}
	return nil, fmt.Errorf("TLS connection failed")
}

func splitHostPort(host string) (string, string, error) {
	if h, p, err := net.SplitHostPort(host); err == nil {
		return h, p, nil
	}

	// If no explicit port is provided, default to 443.
	return host, "443", nil
}

func buildDialTargets(hostName, port string) []string {
	lookupTargets := make([]string, 0, 2)
	ips, err := net.LookupIP(hostName)
	if err == nil && len(ips) > 0 {
		lookupTargets = make([]string, 0, len(ips))
		for _, ip := range ips {
			lookupTargets = append(lookupTargets, net.JoinHostPort(ip.String(), port))
		}
		return lookupTargets
	}

	return []string{net.JoinHostPort(hostName, port)}
}

func peerCertificates(conn *tls.Conn, host string) ([]*Info, error) {
	state := conn.ConnectionState()
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates returned by %s", host)
	}

	result := make([]*Info, len(certs))
	for i, c := range certs {
		result[i] = &Info{Cert: c}
	}
	return result, nil
}

func dialTLSViaProxy(dialer *net.Dialer, target, rawProxyURL string, cfg *tls.Config, timeout time.Duration) (*tls.Conn, error) {
	proxyAddr, authHeader, err := parseProxySettings(rawProxyURL)
	if err != nil {
		return nil, err
	}

	conn, err := dialer.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, err
	}

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, err
	}

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if authHeader != "" {
		connectReq += "Proxy-Authorization: " + authHeader + "\r\n"
	}
	connectReq += "\r\n"

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, err
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !strings.Contains(statusLine, " 200 ") {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", strings.TrimSpace(statusLine))
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, err
		}
		if line == "\r\n" {
			break
		}
	}

	buffered := &bufferedConn{Conn: conn, reader: reader}
	tlsConn := tls.Client(buffered, cfg)
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, err
	}

	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		tlsConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

func parseProxySettings(rawProxyURL string) (addr string, authHeader string, err error) {
	proxyText := strings.TrimSpace(rawProxyURL)
	if proxyText == "" {
		return "", "", fmt.Errorf("proxy URL is empty")
	}
	if !strings.Contains(proxyText, "://") {
		proxyText = "http://" + proxyText
	}

	u, err := url.Parse(proxyText)
	if err != nil {
		return "", "", fmt.Errorf("invalid proxy URL: %w", err)
	}
	if u.Scheme != "http" {
		return "", "", fmt.Errorf("unsupported proxy scheme %q (only http is supported)", u.Scheme)
	}
	if u.Host == "" {
		return "", "", fmt.Errorf("proxy URL must include host")
	}

	addr = u.Host
	if _, _, splitErr := net.SplitHostPort(addr); splitErr != nil {
		addr = net.JoinHostPort(addr, "8080")
	}

	if u.User != nil {
		user := u.User.Username()
		pass, _ := u.User.Password()
		encoded := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		authHeader = "Basic " + encoded
	}

	return addr, authHeader, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.reader.Read(p)
}
