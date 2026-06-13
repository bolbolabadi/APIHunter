# APIHunter

APIHunter is a fast, asynchronous API reconnaissance and route fuzzing tool. It discovers Swagger/OpenAPI documentation, Postman collections, GraphQL endpoints, and source maps, then fuzzes routes using built-in wordlists and dynamically generated patterns.

> **DISCLAIMER:** This tool is intended for **authorized security testing only**. Always obtain explicit permission before scanning any target you do not own. The authors assume no liability for misuse or damage caused by this tool.

---

## Features

- **Phase 1 — Discovery:** Probes for API docs (`swagger.json`, `openapi.json`, GraphQL, Postman, etc.), JS source maps, and extracts routes from discovered specs.
- **Phase 2 — Fuzzing:** Brute-forces API routes using built-in wordlists + auto-generated permutations (`api/v1/...`, `rest/...`, `internal/...`, etc.).
- **Smart Noise Suppression:** Calibrates soft-404 / catch-all behavior to reduce false positives.
- **JS LinkFinder-style Extraction:** Parses JavaScript bundles for hidden endpoints using regex patterns inspired by LinkFinder and BurpJSLinkFinder.
- **Async & Fast:** Built on `aiohttp` with configurable concurrency.
- **Multi-target Support:** Scan a single URL or a list of targets from a file.
- **Custom Headers & User-Agent Rotation:** Supports custom headers and rotating User-Agents.

---

## Installation

```bash
git clone https://github.com/bolbolabadi/APIHunter.git
cd APIHunter
pip install -r requirements.txt
```

---

## Usage

### Basic scan (all phases)
```bash
python apihunter.py https://example.com
```

### Scan multiple targets
```bash
python apihunter.py -f targets.txt
```

### Discovery only (no fuzzing)
```bash
python apihunter.py -m docs https://example.com
```

### Route fuzzing only (skip discovery)
```bash
python apihunter.py -m routes https://example.com
```

### Custom headers & concurrency
```bash
python apihunter.py -H "Cookie: session=abc123" -H "Authorization: Bearer token" -t 50 https://example.com
```

### Rotate User-Agents
```bash
python apihunter.py --random-agent https://example.com
```

### Disable SSL verification
```bash
python apihunter.py --insecure https://example.com
```

---

## Output

Results are saved to `apihunter_results.json` (or a target-prefixed variant when scanning multiple targets). The JSON contains:

- `target`: The scanned base URL
- `results`: Array of discovered endpoints with status, length, and body preview
- `discovered_from_specs`: Routes extracted from OpenAPI/Swagger/JS maps

---

## Wordlists

Place custom wordlists in:

- `wordlists/docs/*.txt` — Paths to probe for API documentation
- `wordlists/routes/*.txt` — Route candidates for fuzzing

Lines starting with `#` are ignored.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

---

## Acknowledgments

- Inspired by [LinkFinder](https://github.com/GerbenJavado/LinkFinder) and BurpJSLinkFinder for JavaScript endpoint extraction.
