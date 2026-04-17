package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ssl-tools/internal/cert"
	"ssl-tools/pkg/output"
)

func RunCheck(args []string) error {
	opts, positional, err := parseOutputFlags(args)
	if err != nil {
		return err
	}

	if len(positional) == 0 {
		return fmt.Errorf("usage: ssl-tools check <file.pem|file.cer> [--json] [--quiet]")
	}

	path := positional[0]
	infos, err := cert.LoadChain(path)
	if err != nil {
		return fmt.Errorf("error loading certificate: %w", err)
	}

	// Create timestamped output file named after the cert filename
	name := "check-" + filepath.Base(path)
	folder := output.DefaultFolder()
	f, outPath, err := output.NewFile(folder, name)
	if err != nil {
		return err
	}
	defer f.Close()

	w := selectWriter(f, opts.Quiet)

	if opts.JSON {
		certs := make([]cert.CertificateJSON, len(infos))
		for i, info := range infos {
			certs[i] = info.ToJSON()
		}

		payload := struct {
			Type              string                 `json:"type"`
			SourceFile        string                 `json:"source_file"`
			TotalCertificates int                    `json:"total_certificates"`
			Certificates      []cert.CertificateJSON `json:"certificates"`
			OutputFile        string                 `json:"output_file"`
		}{
			Type:              "check",
			SourceFile:        path,
			TotalCertificates: len(infos),
			Certificates:      certs,
			OutputFile:        outPath,
		}

		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(payload); err != nil {
			return fmt.Errorf("error writing JSON output: %w", err)
		}
		return nil
	}

	if len(infos) == 1 {
		infos[0].Print(w)
	} else {
		cert.PrintFileChain(w, infos, path)
	}

	if !opts.Quiet {
		fmt.Printf("\nResult saved to: %s\n", outPath)
	}
	return nil
}

func RunHost(args []string) error {
	opts, positional, err := parseHostFlags(args)
	if err != nil {
		return err
	}

	if len(positional) == 0 {
		return fmt.Errorf("usage: ssl-tools host <hostname[:port]> [--json] [--quiet] [--servername <name>] [--timeout <duration>] [--proxy <url>]")
	}

	host := positional[0]
	proxyURL := opts.Proxy
	if proxyURL == "" {
		proxyURL = strings.TrimSpace(os.Getenv("HTTPS_PROXY"))
	}
	if proxyURL == "" {
		proxyURL = strings.TrimSpace(os.Getenv("https_proxy"))
	}

	infos, err := cert.FetchFromHost(host, cert.FetchOptions{
		ServerName: opts.ServerName,
		Timeout:    opts.Timeout,
		ProxyURL:   proxyURL,
	})
	if err != nil {
		return fmt.Errorf("error connecting to host: %w", err)
	}

	// Create timestamped output file named after the hostname
	folder := output.DefaultFolder()
	f, outPath, err := output.NewFile(folder, "host-"+host)
	if err != nil {
		return err
	}
	defer f.Close()

	w := selectWriter(f, opts.Quiet)

	if opts.JSON {
		certs := make([]cert.CertificateJSON, len(infos))
		for i, info := range infos {
			certs[i] = info.ToJSON()
		}

		payload := struct {
			Type              string                 `json:"type"`
			Host              string                 `json:"host"`
			ServerName        string                 `json:"servername,omitempty"`
			TimeoutSeconds    int                    `json:"timeout_seconds,omitempty"`
			ProxyConfigured   bool                   `json:"proxy_configured,omitempty"`
			TotalCertificates int                    `json:"total_certificates"`
			Certificates      []cert.CertificateJSON `json:"certificates"`
			OutputFile        string                 `json:"output_file"`
		}{
			Type:              "host",
			Host:              host,
			ServerName:        opts.ServerName,
			TimeoutSeconds:    int(opts.Timeout.Seconds()),
			ProxyConfigured:   proxyURL != "",
			TotalCertificates: len(infos),
			Certificates:      certs,
			OutputFile:        outPath,
		}

		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(payload); err != nil {
			return fmt.Errorf("error writing JSON output: %w", err)
		}
		return nil
	}

	cert.PrintChain(w, infos, host)

	if !opts.Quiet {
		fmt.Printf("\nResult saved to: %s\n", outPath)
	}
	return nil
}

type outputOptions struct {
	JSON  bool
	Quiet bool
}

type hostOptions struct {
	outputOptions
	ServerName string
	Timeout    time.Duration
	Proxy      string
}

func parseOutputFlags(args []string) (outputOptions, []string, error) {
	opts := outputOptions{}
	positional := make([]string, 0, len(args))

	for _, arg := range args {
		switch arg {
		case "--json":
			opts.JSON = true
		case "--quiet":
			opts.Quiet = true
		default:
			if strings.HasPrefix(arg, "--") {
				return outputOptions{}, nil, fmt.Errorf("unknown flag: %s", arg)
			}
			positional = append(positional, arg)
		}
	}

	return opts, positional, nil
}

func parseHostFlags(args []string) (hostOptions, []string, error) {
	opts := hostOptions{
		Timeout: 10 * time.Second,
	}
	positional := make([]string, 0, len(args))

	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch {
		case arg == "--json":
			opts.JSON = true
		case arg == "--quiet":
			opts.Quiet = true
		case arg == "--servername":
			if i+1 >= len(args) {
				return hostOptions{}, nil, fmt.Errorf("missing value for --servername")
			}
			i++
			opts.ServerName = args[i]
		case strings.HasPrefix(arg, "--servername="):
			opts.ServerName = strings.TrimPrefix(arg, "--servername=")
			if opts.ServerName == "" {
				return hostOptions{}, nil, fmt.Errorf("missing value for --servername")
			}
		case arg == "--timeout":
			if i+1 >= len(args) {
				return hostOptions{}, nil, fmt.Errorf("missing value for --timeout")
			}
			i++
			d, err := parseTimeoutValue(args[i])
			if err != nil {
				return hostOptions{}, nil, err
			}
			opts.Timeout = d
		case strings.HasPrefix(arg, "--timeout="):
			d, err := parseTimeoutValue(strings.TrimPrefix(arg, "--timeout="))
			if err != nil {
				return hostOptions{}, nil, err
			}
			opts.Timeout = d
		case arg == "--proxy":
			if i+1 >= len(args) {
				return hostOptions{}, nil, fmt.Errorf("missing value for --proxy")
			}
			i++
			opts.Proxy = strings.TrimSpace(args[i])
			if opts.Proxy == "" {
				return hostOptions{}, nil, fmt.Errorf("missing value for --proxy")
			}
		case strings.HasPrefix(arg, "--proxy="):
			opts.Proxy = strings.TrimSpace(strings.TrimPrefix(arg, "--proxy="))
			if opts.Proxy == "" {
				return hostOptions{}, nil, fmt.Errorf("missing value for --proxy")
			}
		default:
			if strings.HasPrefix(arg, "--") {
				return hostOptions{}, nil, fmt.Errorf("unknown flag: %s", arg)
			}
			positional = append(positional, arg)
		}
	}

	return opts, positional, nil
}

func selectWriter(file io.Writer, quiet bool) io.Writer {
	if quiet {
		return file
	}
	return output.MultiWriter(file)
}

func parseTimeoutValue(raw string) (time.Duration, error) {
	if raw == "" {
		return 0, fmt.Errorf("missing value for --timeout")
	}

	if n, err := strconv.Atoi(raw); err == nil {
		if n <= 0 {
			return 0, fmt.Errorf("--timeout must be > 0")
		}
		return time.Duration(n) * time.Second, nil
	}

	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid --timeout value %q (use seconds like 30 or duration like 30s)", raw)
	}
	if d <= 0 {
		return 0, fmt.Errorf("--timeout must be > 0")
	}
	return d, nil
}
