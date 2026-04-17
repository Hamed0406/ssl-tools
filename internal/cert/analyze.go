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

type CertificateJSON struct {
	Subject      NameJSON         `json:"subject"`
	Issuer       NameJSON         `json:"issuer"`
	Validity     ValidityJSON     `json:"validity"`
	Identity     IdentityJSON     `json:"identity"`
	PublicKey    PublicKeyJSON    `json:"public_key"`
	SANs         SANsJSON         `json:"sans"`
	Fingerprints FingerprintsJSON `json:"fingerprints"`
}

type NameJSON struct {
	CommonName         string   `json:"common_name"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizational_unit,omitempty"`
	Country            []string `json:"country,omitempty"`
	Province           []string `json:"province,omitempty"`
	Locality           []string `json:"locality,omitempty"`
}

type ValidityJSON struct {
	NotBeforeUTC  string `json:"not_before_utc"`
	NotAfterUTC   string `json:"not_after_utc"`
	Status        string `json:"status"`
	DaysRemaining int    `json:"days_remaining,omitempty"`
	DaysExpired   int    `json:"days_expired,omitempty"`
}

type IdentityJSON struct {
	SerialNumber string `json:"serial_number"`
	SignatureAlg string `json:"signature_algorithm"`
	IsCA         bool   `json:"is_ca"`
}

type PublicKeyJSON struct {
	KeyType string `json:"key_type"`
	KeySize int    `json:"key_size_bits,omitempty"`
	Curve   string `json:"curve,omitempty"`
	RawType string `json:"raw_type,omitempty"`
}

type SANsJSON struct {
	DNS   []string `json:"dns,omitempty"`
	IP    []string `json:"ip,omitempty"`
	Email []string `json:"email,omitempty"`
}

type FingerprintsJSON struct {
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
}

// Load reads a PEM or DER certificate file and returns the first certificate found.
func Load(path string) (*Info, error) {
	infos, err := LoadChain(path)
	if err != nil {
		return nil, err
	}
	return infos[0], nil
}

// LoadChain reads a PEM/DER certificate file and returns all certificates found.
// For PEM files with multiple CERTIFICATE blocks, all blocks are parsed in order.
// For DER files, a single certificate is returned.
func LoadChain(path string) ([]*Info, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read file: %w", err)
	}

	// Parse PEM chains (all CERTIFICATE blocks) when present.
	if block, _ := pem.Decode(data); block != nil {
		infos := make([]*Info, 0, 1)
		rest := data
		for {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			if b.Type != "CERTIFICATE" {
				continue
			}

			parsed, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse PEM certificate: %w", err)
			}
			infos = append(infos, &Info{Cert: parsed})
		}
		if len(infos) == 0 {
			return nil, fmt.Errorf("no CERTIFICATE PEM blocks found")
		}
		return infos, nil
	}

	// Parse DER bytes as single certificate.
	parsed, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return []*Info{{Cert: parsed}}, nil
}

// Print outputs a formatted certificate analysis to w.
func (i *Info) Print(w io.Writer) {
	c := i.Cert
	now := time.Now()
	validity := validityDetails(c, now)

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

	if validity.DaysExpired > 0 {
		fmt.Fprintf(w, "  Status            : EXPIRED (%d days ago)\n", validity.DaysExpired)
	} else if validity.Status == "NOT YET VALID" {
		fmt.Fprintln(w, "  Status            : NOT YET VALID")
	} else {
		fmt.Fprintf(w, "  Status            : %s (%d days remaining)\n", validity.Status, validity.DaysRemaining)
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

// PrintChain prints all certificates from a remote TLS chain with positional labels.
func PrintChain(w io.Writer, infos []*Info, host string) {
	printChainWithTitle(w, infos, fmt.Sprintf("Checking TLS certificate chain for: %s", host))
}

// PrintFileChain prints all certificates loaded from a file with positional labels.
func PrintFileChain(w io.Writer, infos []*Info, path string) {
	printChainWithTitle(w, infos, fmt.Sprintf("Checking certificate chain from file: %s", path))
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

func printChainWithTitle(w io.Writer, infos []*Info, title string) {
	labels := []string{"LEAF (Server)", "INTERMEDIATE", "ROOT"}
	fmt.Fprintf(w, "\n%s\n", title)
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

func (i *Info) ToJSON() CertificateJSON {
	c := i.Cert
	now := time.Now()
	validity := validityDetails(c, now)

	sha1fp := sha1.Sum(c.Raw)
	sha256fp := sha256.Sum256(c.Raw)

	publicKey := PublicKeyJSON{KeyType: "Unknown", RawType: fmt.Sprintf("%T", c.PublicKey)}
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		publicKey = PublicKeyJSON{
			KeyType: "RSA",
			KeySize: pub.N.BitLen(),
		}
	case *ecdsa.PublicKey:
		publicKey = PublicKeyJSON{
			KeyType: "ECDSA",
			Curve:   pub.Curve.Params().Name,
		}
	}

	ips := make([]string, len(c.IPAddresses))
	for i, ip := range c.IPAddresses {
		ips[i] = formatIP(ip)
	}

	return CertificateJSON{
		Subject: NameJSON{
			CommonName:         c.Subject.CommonName,
			Organization:       c.Subject.Organization,
			OrganizationalUnit: c.Subject.OrganizationalUnit,
			Country:            c.Subject.Country,
			Province:           c.Subject.Province,
			Locality:           c.Subject.Locality,
		},
		Issuer: NameJSON{
			CommonName:         c.Issuer.CommonName,
			Organization:       c.Issuer.Organization,
			OrganizationalUnit: c.Issuer.OrganizationalUnit,
			Country:            c.Issuer.Country,
			Province:           c.Issuer.Province,
			Locality:           c.Issuer.Locality,
		},
		Validity: validity,
		Identity: IdentityJSON{
			SerialNumber: formatSerial(c.SerialNumber),
			SignatureAlg: c.SignatureAlgorithm.String(),
			IsCA:         c.IsCA,
		},
		PublicKey: publicKey,
		SANs: SANsJSON{
			DNS:   c.DNSNames,
			IP:    ips,
			Email: c.EmailAddresses,
		},
		Fingerprints: FingerprintsJSON{
			SHA1:   formatHex(sha1fp[:]),
			SHA256: formatHex(sha256fp[:]),
		},
	}
}

func validityDetails(c *x509.Certificate, now time.Time) ValidityJSON {
	out := ValidityJSON{
		NotBeforeUTC: c.NotBefore.UTC().Format(time.RFC3339),
		NotAfterUTC:  c.NotAfter.UTC().Format(time.RFC3339),
	}

	if now.After(c.NotAfter) {
		out.Status = "EXPIRED"
		out.DaysExpired = int(now.Sub(c.NotAfter).Hours() / 24)
		return out
	}

	if now.Before(c.NotBefore) {
		out.Status = "NOT YET VALID"
		return out
	}

	out.DaysRemaining = int(c.NotAfter.Sub(now).Hours() / 24)
	out.Status = "VALID"
	if out.DaysRemaining < 30 {
		out.Status = "VALID - EXPIRING SOON"
	}
	return out
}
