package cert

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// Info holds a parsed certificate.
type Info struct {
	Cert *x509.Certificate
}

// Load reads a PEM or DER certificate file and returns the first certificate found.
func Load(path string) (*Info, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read file: %w", err)
	}

	// Try PEM first
	block, _ := pem.Decode(data)
	if block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("PEM block is %q, expected CERTIFICATE", block.Type)
		}
		data = block.Bytes
	}

	// Parse DER bytes
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return &Info{Cert: cert}, nil
}

// Print outputs a formatted certificate analysis to w.
func (i *Info) Print(w io.Writer) {
	c := i.Cert
	now := time.Now()

	fmt.Fprintln(w)
	fmt.Fprintln(w, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Fprintln(w, "  CERTIFICATE ANALYSIS")
	fmt.Fprintln(w, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Subject
	fmt.Fprintln(w, "\n[ Subject ]")
	fmt.Fprintf(w, "  Common Name       : %s\n", c.Subject.CommonName)
	if len(c.Subject.Organization) > 0 {
		fmt.Fprintf(w, "  Organization      : %s\n", strings.Join(c.Subject.Organization, ", "))
	}
	if len(c.Subject.OrganizationalUnit) > 0 {
		fmt.Fprintf(w, "  Org Unit          : %s\n", strings.Join(c.Subject.OrganizationalUnit, ", "))
	}
	if len(c.Subject.Country) > 0 {
		fmt.Fprintf(w, "  Country           : %s\n", strings.Join(c.Subject.Country, ", "))
	}
	if len(c.Subject.Province) > 0 {
		fmt.Fprintf(w, "  State/Province    : %s\n", strings.Join(c.Subject.Province, ", "))
	}
	if len(c.Subject.Locality) > 0 {
		fmt.Fprintf(w, "  Locality          : %s\n", strings.Join(c.Subject.Locality, ", "))
	}

	// Issuer
	fmt.Fprintln(w, "\n[ Issuer ]")
	fmt.Fprintf(w, "  Common Name       : %s\n", c.Issuer.CommonName)
	if len(c.Issuer.Organization) > 0 {
		fmt.Fprintf(w, "  Organization      : %s\n", strings.Join(c.Issuer.Organization, ", "))
	}
	if len(c.Issuer.Country) > 0 {
		fmt.Fprintf(w, "  Country           : %s\n", strings.Join(c.Issuer.Country, ", "))
	}

	// Validity
	fmt.Fprintln(w, "\n[ Validity ]")
	fmt.Fprintf(w, "  Not Before        : %s\n", c.NotBefore.UTC().Format(time.RFC1123))
	fmt.Fprintf(w, "  Not After         : %s\n", c.NotAfter.UTC().Format(time.RFC1123))

	if now.After(c.NotAfter) {
		fmt.Fprintf(w, "  Status            : EXPIRED (%.0f days ago)\n", now.Sub(c.NotAfter).Hours()/24)
	} else if now.Before(c.NotBefore) {
		fmt.Fprintln(w, "  Status            : NOT YET VALID")
	} else {
		daysLeft := int(c.NotAfter.Sub(now).Hours() / 24)
		status := "VALID"
		if daysLeft < 30 {
			status = "VALID - EXPIRING SOON"
		}
		fmt.Fprintf(w, "  Status            : %s (%d days remaining)\n", status, daysLeft)
	}

	// Identity
	fmt.Fprintln(w, "\n[ Identity ]")
	fmt.Fprintf(w, "  Serial Number     : %s\n", formatSerial(c.SerialNumber))
	fmt.Fprintf(w, "  Signature Alg     : %s\n", c.SignatureAlgorithm.String())
	fmt.Fprintf(w, "  Is CA             : %v\n", c.IsCA)

	// Public Key
	fmt.Fprintln(w, "\n[ Public Key ]")
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		fmt.Fprintln(w, "  Key Type          : RSA")
		fmt.Fprintf(w, "  Key Size          : %d bits\n", pub.N.BitLen())
	case *ecdsa.PublicKey:
		fmt.Fprintln(w, "  Key Type          : ECDSA")
		fmt.Fprintf(w, "  Curve             : %s\n", pub.Curve.Params().Name)
	default:
		fmt.Fprintln(w, "  Key Type          : Unknown")
	}

	// SANs
	if len(c.DNSNames) > 0 || len(c.IPAddresses) > 0 || len(c.EmailAddresses) > 0 {
		fmt.Fprintln(w, "\n[ Subject Alternative Names ]")
		for _, d := range c.DNSNames {
			fmt.Fprintf(w, "  DNS               : %s\n", d)
		}
		for _, ip := range c.IPAddresses {
			fmt.Fprintf(w, "  IP                : %s\n", formatIP(ip))
		}
		for _, e := range c.EmailAddresses {
			fmt.Fprintf(w, "  Email             : %s\n", e)
		}
	}

	// Fingerprints
	fmt.Fprintln(w, "\n[ Fingerprints ]")
	sha1fp := sha1.Sum(c.Raw)
	sha256fp := sha256.Sum256(c.Raw)
	fmt.Fprintf(w, "  SHA-1             : %s\n", formatHex(sha1fp[:]))
	fmt.Fprintf(w, "  SHA-256           : %s\n", formatHex(sha256fp[:]))

	fmt.Fprintln(w)
	fmt.Fprintln(w, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

// PrintChain prints all certificates in a chain with positional labels.
func PrintChain(w io.Writer, infos []*Info, host string) {
	labels := []string{"LEAF (Server)", "INTERMEDIATE", "ROOT"}
	fmt.Fprintf(w, "\nChecking TLS certificate chain for: %s\n", host)
	fmt.Fprintf(w, "Total certificates in chain: %d\n", len(infos))

	for idx, info := range infos {
		label := "CERTIFICATE"
		if idx < len(labels) {
			label = labels[idx]
		}
		fmt.Fprintf(w, "\n[%d/%d] %s\n", idx+1, len(infos), label)
		info.Print(w)
	}
}

func formatSerial(n *big.Int) string {
	b := n.Bytes()
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}

func formatHex(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}

func formatIP(ip net.IP) string {
	return ip.String()
}
