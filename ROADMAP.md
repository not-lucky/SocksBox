# Roadmap

Future improvements for SocksBox, organized by area.

## Protocol Support

- [x] Add HTTP/HTTPS proxy link parsing (`http://`, `https://`)
- [x] Add SOCKS5 direct link support (`socks5://`)
- [x] Add WireGuard config parsing
- [x] Add ShadowsocksR (SSR) support
- [x] Add NaiveProxy support
- [x] Handle Xray XHTTP/splitHTTP transport (rejected with clear error — sing-box does not support this transport)

## Verification

- [ ] Bandwidth/speed testing (currently only latency is measured)
- [ ] DNS leak detection
- [ ] IP leak checking
- [ ] Streaming/connectivity quality scoring
- [ ] Chunked proxy testing for large lists (>500 proxies) to avoid port exhaustion
- [ ] Configurable test endpoints beyond `cp.cloudflare.com`

## Enrichment

- [ ] Multiple geo-IP providers (ip-api.com, ipapi.co) instead of ipinfo.io only
- [ ] Local/offline geo-IP database support (MaxMind GeoLite2)
- [ ] ASN and ISP detail enrichment
- [ ] Caching layer to avoid redundant API calls for the same IPs

## Export Formats

- [ ] Clash (Meta/Mihomo) YAML config export
- [ ] V2Ray/Xray JSON config export
- [ ] Surge config format
- [ ] Quantumult X format
- [ ] CSV/TSV tabular export
- [ ] Markdown report generation
- [ ] QR code generation for mobile import

## CLI & UX

- [ ] `watch` command for periodic auto-refresh pipeline runs
- [ ] `diff` command to compare results between two runs
- [ ] `benchmark` command for detailed speed tests (download/upload)
- [ ] JSON output mode (`--json`) for machine-readable results
- [ ] Terminal UI (TUI) for interactive proxy selection and browsing
- [ ] Progress bars (e.g., `rich` or `tqdm`) replacing current `\r` progress lines

## Architecture & Robustness

- [ ] SQLite/JSON cache for previously verified proxies with TTL expiry
- [ ] Historical data tracking across runs
- [ ] Daemon mode for continuous proxy health monitoring
- [ ] Plugin system for custom parsers and exporters
- [ ] Retry logic with exponential backoff for API calls
- [ ] Rate limiting for geo-IP API requests

## Testing & Quality

- [ ] Unit test suite
- [ ] Integration tests with sample proxy link fixtures
- [ ] Mock sing-box binary for testing without external dependency
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] Type checking with mypy/pyright
- [ ] Linting with ruff
