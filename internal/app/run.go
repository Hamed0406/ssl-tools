package app

import (
	"fmt"
	"path/filepath"

	"ssl-tools/internal/cert"
	"ssl-tools/pkg/output"
)

func RunCheck(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ssl-tools check <file.pem|file.cer>")
	}

	path := args[0]
	info, err := cert.Load(path)
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

	w := output.MultiWriter(f)
	info.Print(w)

	fmt.Printf("\nResult saved to: %s\n", outPath)
	return nil
}

func RunHost(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ssl-tools host <hostname[:port]>")
	}

	host := args[0]
	infos, err := cert.FetchFromHost(host)
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

	w := output.MultiWriter(f)
	cert.PrintChain(w, infos, host)

	fmt.Printf("\nResult saved to: %s\n", outPath)
	return nil
}
