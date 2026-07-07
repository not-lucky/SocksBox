# SocksBox 🧦📦

SocksBox is a high-performance, robust, and extensible Python proxy toolkit. It is built to scrape, parse, verify, enrich, and export proxy configurations. 

By orchestrating background `sing-box` processes, SocksBox routes target checks through local SOCKS endpoints to measure precise real-world latency, filter dead proxies, check geo-location databases, query reputation APIs, and generate production-ready routing configurations.

---

## 🌟 Key Features

1. **Extensive Protocol Support**: Decodes raw links for SOCKS5, HTTP, Shadowsocks, ShadowsocksR, VMess, VLess, Trojan, Hysteria 2, TUIC, NaïveProxy, and WireGuard.
2. **Dynamic Proxy Scraping**: Adapters included to scrape from ProxyScrape API, Shadowmere API, and plain-text/Base64 subscription lists.
3. **Advanced Latency Testing**: Runs lightweight, short-lived `sing-box` processes to verify connectivity and measure latency to target servers (e.g. `cp.cloudflare.com`).
4. **Enrichment Engine & Provider Registry**: Geolocates IPs using `ipinfo.io` and runs security checks using `abuseipdb.com` with support for dynamic provider registry.
5. **API Key Cycling**: Distributes API queries across multiple, comma-separated tokens configured in your environment to mitigate rate limits.
6. **Robust Download verification**: Performs opt-in speed/download tests using concurrent worker pools to weed out slow or non-responsive proxies.
7. **Rate Limit & Forbidden Detection**: Detects blocks and rate limits (e.g. Google's 403 Forbidden pages), records issues, and writes audit logs.
8. **Categorized Exports**: Exports proxies split by protocol, by country, top 10 latency ranks, and saves complete diagnostic reports alongside the main `config.json`.

---

## 🛠 Supported Proxy Protocols

SocksBox parses and parses raw subscription link formats for the following schemes:

- **SOCKS5**: `socks5://[user:pass@]host:port`
- **HTTP**: `http://[user:pass@]host:port`
- **Shadowsocks (SS)**: `ss://[method:password@]host:port`
- **ShadowsocksR (SSR)**: `ssr://[base64-config]`
- **VMess**: `vmess://[base64-json-config]`
- **VLess**: `vless://uuid@host:port?query-params`
- **Trojan**: `trojan://password@host:port?query-params`
- **Hysteria 2**: `hysteria2://password@host:port?query-params`
- **TUIC**: `tuic://uuid:password@host:port?query-params`
- **NaïveProxy**: `naive+https://user:pass@host:port?query-params`
- **WireGuard**: `wireguard://private-key@host:port?query-params`

---

## 📡 Built-In Scraper Sources

SocksBox implements a Template Method pattern to parse and load links from various sources:

- **UrlTextSource** (`UrlTextSource`): Downloads plain-text subscription lists or Base64-encoded subscription files.
- **ShadowmereSource** (`ShadowmereSource`): Fetches JSON configurations from the `shadowmere.xyz` public proxy API.
- **ProxyscrapeSource** (`ProxyscrapeSource`): Queries public elite proxies from `proxyscrape.com`'s public endpoints.

---

## ⚙️ Configuration & Environment Setup

SocksBox automatically loads configurations from a `.env` file in your root workspace directory on startup. Every configuration option can be customized via environment variables (in `.env` or in the host shell) and, where applicable, overridden temporarily using CLI arguments.

### Configuration Reference Table

| Setting | Environment Variable | CLI Option | Type | Default Value | Description |
|---|---|---|---|---|---|
| **SOCKS Port Start** | `START_PORT` | `--start-port` | `int` | `10808` | The first SOCKS port to assign to proxies during validation or configuration generation. |
| **SOCKS Listen IP** | `LISTEN` | `--listen` | `str` | `127.0.0.1` | The listen address for the temporary local `sing-box` SOCKS inbound listeners. |
| **Concurrency Limit** | `CONCURRENCY` | `--concurrency` | `int` | `100` | Maximum number of concurrent proxy latency/verification checks. |
| **Verification Tries** | `TRIES` | `--tries` | `int` | `5` | The number of connection latency test attempts to run per proxy. |
| **Timeout Duration** | `TIMEOUT` | `--timeout` | `float` | `4.0` | Connection timeout per validation check attempt in seconds. |
| **Target Host** | `TARGET_HOST` | `--target-host` | `str` | `cp.cloudflare.com` | Host domain name used to verify SOCKS connectivity and measure latency. |
| **Target Port** | `TARGET_PORT` | `--target-port` | `int` | `80` | Network port on the target server to connect to. |
| **Sing-Box Binary** | `SING_BOX` | `--sing-box` | `str` | `sing-box` | The system path or command name to execute the `sing-box` binary. |
| **Active Providers** | `ENRICH_PROVIDERS` | *N/A* | `str` | `ipinfo` | Comma-separated list of active enrichment providers to query (e.g. `ipinfo,abuseipdb`). |
| **IPInfo API Keys** | `IPINFO_TOKEN` | `--ipinfo-token` | `str` | `""` | Comma-separated list of API tokens to cycle through for `ipinfo.io` lookups. |
| **AbuseIPDB Keys** | `ABUSEIPDB_TOKEN` | *N/A* | `str` | `""` | Comma-separated list of API keys to cycle through for `abuseipdb.com` reputational lookups. |
| **Skip Enrichment** | `NO_ENRICH` | `--no-enrich` | `bool` | `False` | Skip the geolocation/security API lookup stage entirely. |
| **Skip SSL Verification**| `NO_VERIFY_SSL` | `--no-verify-ssl` | `bool` | `False` | Disable SSL validation when parsing or downloading subscriptions (INSECURE). |
| **Audit Log Path** | `AUDIT_LOG` | `--audit-log` | `str` | `None` | Custom path to write ipinfo rate-limit/forbidden logs. Defaults to `forbidden_detections.log` in output folder. |
| **Verbose Debugging** | `VERBOSE` | `-v` / `--verbose` | `bool` | `False` | Enable logging of trace errors and diagnostic prints to stderr. |
| **Output Folder** | `OUTPUT_DIR` | `--output-dir` | `str` | `output` | Directory where output files, summaries, and configurations are saved. |
| **Download Test** | `DOWNLOAD_TEST` | `--download-test` | `bool` | `False` | Enable post-export download validation via concurrent HTTP speed-test checks. |
| **Download Test URL** | `DOWNLOAD_URL` | `--download-url` | `str` | `https://speed...` | File URL to retrieve for download speed tests (defaults to Cloudflare 1MB payload). |
| **Download Timeout** | `DOWNLOAD_TIMEOUT` | `--download-timeout` | `float` | `30.0` | Maximum time allowed in seconds for a proxy to download speed test payloads. |
| **Download Concurrency**| `DOWNLOAD_CONCURRENCY`| `--download-concurrency`| `int` | `5` | Maximum number of concurrent speed-test download threads. |
| **Legacy Routing** | `LEGACY_ROUTE` | `--legacy-route` | `bool` | `False` | Generate legacy format sing-box routing rules without actions. |

---

### Detailed `.env` File Example

Create a file named `.env` in the project root to configure all options:

```ini
# Core verification settings
START_PORT=10808
LISTEN=127.0.0.1
CONCURRENCY=150
TRIES=3
TIMEOUT=5.0
TARGET_HOST=cp.cloudflare.com
TARGET_PORT=80
SING_BOX=/usr/local/bin/sing-box

# Enrichment providers
ENRICH_PROVIDERS=ipinfo,abuseipdb
IPINFO_TOKEN=ipinfo_key_1,ipinfo_key_2
ABUSEIPDB_TOKEN=abuse_key_1,abuse_key_2,abuse_key_3

# Verification & Logging
NO_ENRICH=False
NO_VERIFY_SSL=False
AUDIT_LOG=output/audit_failures.log
VERBOSE=True
OUTPUT_DIR=output

# Post-verification speed validation
DOWNLOAD_TEST=True
DOWNLOAD_URL=https://speed.cloudflare.com/__down?bytes=1048576
DOWNLOAD_TIMEOUT=20.0
DOWNLOAD_CONCURRENCY=8

# Routing profile configuration
LEGACY_ROUTE=False
```

---

## 💻 CLI Reference

SocksBox provides a unified CLI entry point:

### 1. `run` (Full Pipeline)
Scrapes raw lists, verifies latency, enriches metadata, performs download verification, and exports results.
```bash
uv run socksbox run [OPTIONS]
```
**Options**:
- `--output-dir <path>`: Directory to save results (default: `output/`).
- `--concurrency <num>`: Max concurrent testing operations (default: `100`).
- `--tries <num>`: Latency check attempts per proxy (default: `5`).
- `--timeout <float>`: Timeout per check attempt in seconds (default: `4.0`).
- `--target-host <host>`: HTTP server used for target verification (default: `cp.cloudflare.com`).
- `--no-enrich`: Skip geolocation/reputation lookup.
- `--download-test`: Opt-in to run post-export download validation.
- `--download-url <url>`: URL to pull speed test payloads from (default: 1 MiB payload).
- `--download-concurrency <num>`: Max parallel download workers (default: `5`).
- `--audit-log <path>`: Log file path for forbidden IP warnings.

### 2. `verify`
Parses and checks raw configurations. Saves verified working proxy links to a text file.
```bash
uv run socksbox verify -o verified_links.txt
```

### 3. `enrich`
Loads, verifies, and runs geo/reputation enrichment on proxies using configured API credentials.
```bash
uv run socksbox enrich
```

### 4. `parse`
A debug command that downloads, parses, and displays structured lists of parsed proxies.
```bash
uv run socksbox parse
```

### 5. `config`
Generates a raw sing-box configuration file with all input outbounds mapped to SOCKS5 listen endpoints (no latency checking).
```bash
uv run socksbox config -o config.json
```

---

## 📂 Outputs & Outputs Structure

When you run the pipeline, the following files are populated in the output directory:

- **`config.json`**: sing-box production profile, containing all verified, working proxy servers listed under `outbounds`.
- **`diagnostics.json`**: High-detail analysis payload containing proxy metrics, timestamps, latency logs, status, and the raw responses from all providers (e.g. `raw_geo.ipinfo`, `raw_geo.abuseipdb`).
- **`summary.json`**: Aggregate diagnostics (total, working, protocol distributions, and top 10 low-latency proxies).
- **`all.txt`**: Flat text list of all parsed proxy links.
- **`all_working.txt`**: Flat text list of all verified working proxy links.
- **`top10.txt`**: The 10 fastest verified proxy links.
- **`by_protocol/`**: Proxy links organized into separate files by protocol (e.g. `by_protocol/vmess.txt`).
- **`by_country/`**: Proxy links grouped by ISO country code (e.g. `by_country/US.txt`).

---

## 🧬 Extending the Codebase

### Adding custom protocols
Create a new parser class inside `src/socksbox/parsing/protocols/` subclassing `ParserStrategy`, and register it in `ParserRegistry` (`src/socksbox/parsing/registry.py`).

### Adding custom sources
Subclass `BaseSource` inside `src/socksbox/sources/base.py`, implement `_fetch()` and `_parse()`, and add it to `DEFAULT_SOURCES` or create it dynamically using `GLOBAL_SOURCE_FACTORY`.

### Custom enrichment providers
Implement `EnrichmentProvider` and register the instance to `PROVIDER_REGISTRY`:
```python
from socksbox.enrichment import PROVIDER_REGISTRY, EnrichmentProvider

class MyCustomProvider(EnrichmentProvider):
    @property
    def name(self) -> str:
        return "my_api"
    # Implement enrich and populate_proxy...

PROVIDER_REGISTRY.register(MyCustomProvider())
```

---

## 🧪 Testing

SocksBox comes with a comprehensive suite of unit tests. Run the test suite:
```bash
uv run pytest
```
