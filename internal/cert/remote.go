package cert

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// FetchFromHost connects to host (hostname or hostname:port) over TLS,
// retrieves the certificate chain, and returns Info for each cert.
func FetchFromHost(host string) ([]*Info, error) {
	// Default port to 443 if not specified
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{
		InsecureSkipVerify: true, // allow checking expired/self-signed certs too
	})
	if err != nil {
		return nil, fmt.Errorf("TLS connection failed: %w", err)
	}
	defer conn.Close()

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
