# Roadmap

Future improvements for SocksBox, organized by area.

## Protocol Support

- [x] Add HTTP/HTTPS proxy link parsing (`http://`, `https://`)
- [x] Add SOCKS5 direct link support (`socks5://`)
- [x] Add WireGuard config parsing
- [x] Add ShadowsocksR (SSR) support
- [x] Add NaiveProxy support
- [x] Handle Xray XHTTP/splitHTTP transport (rejected with clear error — sing-box does not support this transport)
- [ ] SSH proxy link parsing (`ssh://`)
- [ ] Subscription format decoding (Clash YAML subscriptions, Surge CONF, base64 `SUB://` scheme)
- [ ] Proxy deduplication across sources (same server:port+protocol = duplicate entry)
- [ ] Mieru protocol support
- [ ] TUIC v5 option parsing (congestion control, UDP relay mode)

## Verification

- [ ] Bandwidth/speed testing (currently only latency is measured)
- [ ] DNS leak detection
- [ ] IP leak checking
- [ ] Streaming/connectivity quality scoring
- [ ] Chunked proxy testing for large lists (>500 proxies) to avoid port exhaustion
- [ ] Configurable test endpoints beyond `cp.cloudflare.com`
- [ ] Adaptive timeout per protocol type (QUIC-based like Hysteria2/TUIC may need different thresholds)
- [ ] Connection stability testing (sustained multi-second connection check, not just TCP handshake)
- [ ] Graceful handling of sing-box crash mid-test (currently untested proxies retain `inf` latency with no crash indication)
- [ ] Port range pre-validation with actionable error when system lacks available ephemeral ports
- [ ] Concurrent sing-box instances for very large lists (split proxies across multiple processes to stay within port limits)
- [ ] Full HTTP round-trip validation (fetch a real URL through the proxy, not just `/generate_204`)
- [ ] Jitter measurement (standard deviation across latency samples)
- [ ] Packet loss estimation via repeated small transfers

## Enrichment

- [ ] Multiple geo-IP providers (ip-api.com, ipapi.co) instead of ipinfo.io only
- [ ] Local/offline geo-IP database support (MaxMind GeoLite2)
- [ ] ASN and ISP detail enrichment
- [ ] Caching layer to avoid redundant API calls for the same IPs
- [ ] Fallback geo-IP provider chain (try ipinfo.io, then ip-api.com, then ipapi.co on failure)
- [ ] Reverse DNS lookup for proxy server hostnames
- [ ] Batch IP lookup support (ipinfo.io `/batch` endpoint for bulk queries)
- [ ] Geo-IP accuracy cross-validation between multiple providers
- [ ] Latency-to-geo correlation (flag proxies whose reported country doesn't match expected latency range)

## Export Formats

- [ ] Clash (Meta/Mihomo) YAML config export
- [ ] V2Ray/Xray JSON config export
- [ ] Surge config format
- [ ] Quantumult X format
- [ ] CSV/TSV tabular export
- [ ] Markdown report generation
- [ ] QR code generation for mobile import
- [ ] Sing-box config with `urltest`/`selector` outbound groups (currently only flat per-port routing rules)
- [ ] Credential-redacted export mode (mask passwords/UUIDs for sharing results safely)
- [ ] Template-based export (user-provided Jinja2 templates for custom output formats)
- [ ] Export filtering (min/max latency, country whitelist/blacklist, protocol filter)
- [ ] Shadowrocket subscription link generation (base64-encoded link list)
- [ ] Loon config format

## CLI & UX

- [ ] `watch` command for periodic auto-refresh pipeline runs
- [ ] `diff` command to compare results between two runs
- [ ] `benchmark` command for detailed speed tests (download/upload)
- [ ] JSON output mode (`--json`) for machine-readable results
- [ ] Terminal UI (TUI) for interactive proxy selection and browsing
- [ ] Progress bars (e.g., `rich` or `tqdm`) replacing current `\r` progress lines
- [ ] `--filter` flag for country/protocol/latency filtering at any pipeline stage
- [ ] Colored terminal output (pass/fail highlighting, latency heat coloring)
- [ ] Dry-run mode that parses and validates without starting sing-box
- [ ] `--config` flag for persistent defaults via `.socksbox.toml` or `.socksbox.yaml`
- [ ] Shell completions (bash, zsh, fish)
- [ ] `stats` subcommand to print summary statistics from a previous run's `diagnostics.json`
- [ ] Quiet mode (`-q`) that suppresses all non-error output

## Architecture & Robustness

- [ ] SQLite/JSON cache for previously verified proxies with TTL expiry
- [ ] Historical data tracking across runs
- [ ] Daemon mode for continuous proxy health monitoring
- [ ] Plugin system for custom parsers and exporters
- [ ] Retry logic with exponential backoff for API calls
- [ ] Rate limiting for geo-IP API requests
- [ ] Provider interface pattern for enricher (swap ipinfo.io for any geo-IP backend without code changes)
- [ ] Pipeline stage skip/reorder (e.g., enrich without verify, or verify-only in `run`)
- [ ] Signal handling (SIGINT graceful shutdown with partial result save)
- [ ] Structured logging framework replacing scattered `print(..., file=sys.stderr)` calls
- [ ] Configuration file support (`.socksbox.toml` for persistent CLI defaults)
- [ ] Typed exception hierarchy (replace bare `ValueError` with domain-specific exceptions)

## Subscription Management

- [ ] Auto-update subscription sources on a configurable schedule
- [ ] Source health tracking (which subscriptions consistently yield working proxies)
- [ ] Subscription URL rotation and fallback chains (try primary, fall back to mirror)
- [ ] Diff detection between subscription updates (report new/removed/changed proxies)
- [ ] Local subscription cache with staleness detection
- [ ] Subscription format auto-detection (base64, plain text, Clash YAML, sing-box JSON)

## Security & Privacy

- [ ] Credential redaction in log and diagnostic output (mask UUIDs, passwords, public keys)
- [ ] Proxy server trust scoring (flag known honeypot IPs or suspicious ASNs)
- [ ] TLS certificate pinning/validation for proxy connections
- [ ] Sanitization of exported configs (strip identifiable metadata like timestamps and hostnames)
- [ ] Input sanitization hardening (reject links with embedded shell metacharacters or path traversal)
- [ ] Optional encrypted export (age/symmetric encryption for credential-bearing files)

## Proxy Chaining & Routing

- [ ] Multi-hop proxy chain construction (proxy A -> proxy B -> target)
- [ ] Automatic failover chain generation (primary + backup per route)
- [ ] Country-based routing rules in generated sing-box config
- [ ] `urltest` group generation for sing-box (auto-select fastest proxy per destination)
- [ ] Split tunneling rule generation (geo-based bypass rules for local traffic)
- [ ] Chain latency measurement (end-to-end through the full hop sequence)

## Performance & Scalability

- [ ] Worker pool with adaptive concurrency (auto-tune batch size based on success/failure rate)
- [ ] Memory-efficient streaming parser for very large proxy lists (10k+ entries)
- [ ] Incremental verification (skip previously verified proxies within a configurable TTL)
- [ ] Parallel sing-box instances for port-range splitting (overcome 65535 port ceiling)
- [ ] Disk-backed proxy queue for memory-constrained environments
- [ ] Connection pooling for enrichment HTTP requests (reuse aiohttp sessions)
- [ ] Lazy sing-box config generation (only materialize config for active test batch)

## Data & Analytics

- [ ] Historical latency trending (track proxy performance across multiple runs)
- [ ] Proxy reliability scoring (uptime percentage and consistency across runs)
- [ ] Geographic distribution visualization data export (GeoJSON or chart-ready JSON)
- [ ] Source quality scoring (which input sources produce the highest working-proxy ratio)
- [ ] Anomaly detection (flag proxies with sudden latency spikes or country changes)
- [ ] Run comparison report (side-by-side diff of two `diagnostics.json` outputs)

## Integration & API

- [ ] HTTP API server mode (REST endpoint for on-demand proxy lookup and health checks)
- [ ] Webhook notifications when proxy pool health degrades below threshold
- [ ] Telegram/Discord bot integration for proxy status queries
- [ ] Docker containerization with health check endpoint and volume-mounted config
- [ ] Systemd service unit for daemon mode with watchdog support
- [ ] Webhook/CI trigger (run pipeline automatically when a subscription URL is updated)

## Testing & Quality

- [ ] Unit test suite
- [ ] Integration tests with sample proxy link fixtures
- [ ] Mock sing-box binary for testing without external dependency
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] Type checking with mypy/pyright
- [ ] Linting with ruff
- [ ] Property-based testing for parsers (hypothesis library with random valid/malformed links)
- [ ] Fuzz testing for link parsers with adversarial inputs
- [ ] Code coverage reporting (target >80% for `parser.py` and `config_gen.py`)
- [ ] Performance benchmark suite for parser and verifier throughput
