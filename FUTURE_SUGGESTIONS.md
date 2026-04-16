Future suggestions for ssl-tools

1. Add JSON/quiet output flags
   Useful for automation and scripting. Example: --json to emit structured data, --quiet to skip banners.

2. Support full PEM chains in files
   check currently parses only the first cert in a PEM file. Many .pem files contain a chain. Add a loop to parse all PEM blocks and print a chain (like the host command).

3. Add --servername (SNI) override
   Some hosts require SNI to return the correct certificate. Allow: ssl-tools host <ip> --servername example.com.

4. Add --timeout flag
   Allow users to control network timeout instead of the fixed 10s in FetchFromHost.

5. Add TLS verification option
   InsecureSkipVerify is always true. Add --verify to optionally validate the chain and report verification errors.

6. Save outputs as .json or .txt based on flag
   Helpful for integrations or logging systems.

7. Add unit tests for parser logic
   Especially for formatSerial, PEM chain parsing, and output file naming.
