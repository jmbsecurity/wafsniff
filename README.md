# wafsniff

Fast WAF detection tool written in Rust. Combines XSStrike's signature matching with wafw00f's behavioral detection.

## How it works

1. Sends a normal request to establish a baseline
2. Sends an XSS attack probe
3. Sends a request without User-Agent
4. Sends a SQLi attack probe
5. Compares responses — if status codes change between normal and attack requests, a WAF is likely active
6. Matches response headers, cookies, body content, and status codes against 69 WAF signatures

## Build

```
git clone https://github.com/jmbsecurity/wafsniff.git
cd wafsniff
cargo build --release
```

Install globally:

```
cargo install --path .
```

## Usage

```
wafsniff -u https://example.com
wafsniff -u https://example.com -v
wafsniff -u "https://example.com/search?q=test" -v
wafsniff -u https://example.com -t 15
wafsniff -u https://example.com --user-agent "curl/7.88.1"
```

### Flags

```
-u, --url          Target URL (required)
-s, --signatures   Path to signatures JSON (default: signatures.json)
-t, --timeout      Request timeout in seconds (default: 10)
-v, --verbose      Show detailed output
--user-agent       Custom User-Agent string
```

### Scan multiple targets

```
while read url; do wafsniff -u "$url"; done < targets.txt
```

## Signatures

69 WAFs detected including Cloudflare, Akamai, AWS WAF, Imperva, ModSecurity, F5 BIG-IP, Sucuri, Fortinet, and more. Signatures are sourced from XSStrike, wafw00f, and the Awesome-WAF project.

Add custom signatures by editing `signatures.json`.

## Disclaimer

For authorized security testing only.
