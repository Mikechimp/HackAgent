# HackAgent — AI-Powered Bug Bounty Recon Tool

An Electron desktop application with a Firefox extension for authorized security testing and bug bounty hunting. Uses GPT-4o + the Jhaddix attack surface knowledge base for intelligent vulnerability detection.

**Important:** This tool is for **authorized security testing only**. Always verify you have written permission before scanning any target.

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Build the app
npm run build

# 3. Run in development mode
npm run dev
```

On first launch, enter your OpenAI API key in the setup screen.

## npm Scripts

| Command | What it does |
|---------|-------------|
| `npm run build` | Compile TypeScript + copy renderer files to `dist/` |
| `npm run dev` | Development mode with live reload (TypeScript watcher + file watcher + Electron) |
| `npm start` | Build and launch the Electron app |
| `npm run build:extension` | Package the Firefox extension into `dist/extension/hackagent.xpi` |
| `npm run package` | Build app + extension, then create distributable (unpacked) |
| `npm run make` | Build app + extension, then create installer (AppImage/dmg/nsis) |

## Architecture

```
Electron Main Process (main.ts)
 |
 +---> BackendManager  ---> Express server (port 5175)
 |                           |
 |                           +---> Page Analyzer (20+ automated checks)
 |                           +---> OpenAI Client (GPT-4o with Jhaddix context)
 |                           +---> Projects CRUD (file-based persistence)
 |                           +---> Attack Surface DB (Jhaddix knowledge base)
 |
 +---> BrowserWindow   ---> Renderer (index.html + app.js)
                             |
                             +---> Scanner Panel (URL analysis)
                             +---> Chat Panel (HackAgent AI assistant)
                             +---> Projects Panel (saved research)
                             +---> Extension Panel (Firefox extension setup)

Firefox Extension (MV2)
 |
 +---> popup.js        ---> Analyze current page / capture screenshot
 +---> content.js      ---> Deep page data capture (DOM, storage, scripts)
 +---> background.js   ---> Message routing to backend API
```

## Detection Engine

The automated scanner checks 20+ vulnerability categories before feeding everything to GPT-4o:

- **Secret Scanning** — 28 patterns (AWS keys, Google API, GitHub tokens, Stripe, Slack, JWT, private keys, DB connection strings, S3 buckets)
- **CORS Misconfiguration** — Wildcard origins, credential leaks
- **Sensitive Path Detection** — 55 paths (.git, .env, /admin, /actuator, /graphiql, /phpinfo, terraform.tfstate)
- **Technology Fingerprinting** — 70+ technologies with version extraction (CMS, frameworks, DevOps tools, servers, CDNs, WAFs)
- **CSP Analysis** — unsafe-inline, unsafe-eval, wildcards, data: URI
- **Cookie Security** — Secure, HttpOnly, session cookie analysis
- **Form Security** — Missing CSRF, file uploads, IDOR hidden fields, HTTP submissions
- **Dangerous JS Patterns** — 18 DOM XSS sinks (eval, innerHTML, postMessage, Function constructor)
- **Open Redirect Detection** — 26 known redirect parameter names
- **API Endpoint Discovery** — REST/GraphQL/auth endpoints from inline JS
- **Subdomain Enumeration** — From page links
- **Source Map Exposure** — Leaked original source code
- **Comment Analysis** — Secrets, internal IPs, TODO notes
- **WAF/CDN Detection** — Cloudflare, Sucuri, Imperva, AWS WAF
- **Mixed Content** — HTTP resources on HTTPS pages
- **Email Disclosure** — Exposed email addresses
- **JSONP Detection** — Cross-origin data leak vectors
- **Server Version Disclosure** — Version info in headers

## Jhaddix Attack Surface Integration

The `data/attack_surface.json` knowledge base is loaded at startup and actively fed into every analysis:

- **Attack vectors** for matched technologies (Jenkins, GitLab, Confluence, Vault, etc.)
- **Critical CVEs** cross-referenced against detected software versions
- **Default credentials** for 28+ services (databases, web apps, network devices)
- **OWASP Top 10** checklist applied to every scan
- **Web vulnerability signatures** (XSS, SQLi, SSRF, path traversal, RCE, LFI)

GPT-4o receives all of this context alongside the automated findings, enabling it to validate discoveries and identify attack paths the scanner can't see.

## Firefox Extension

The extension captures deep page data from the browser:

- Full HTML + inline script contents (for secret scanning)
- localStorage / sessionStorage keys and values
- All forms with hidden field values (IDOR detection)
- API endpoints discovered in JavaScript
- Client-side technology detection
- HTML comments, meta tags, cookies
- Service worker info, CSP meta tags

### Installing the Extension

1. Run `npm run build:extension` to create the `.xpi` file
2. In Firefox: `about:debugging` > This Firefox > Load Temporary Add-on
3. Select `firefox_extension/manifest.json`

Or use the Extension panel in the app for guided setup.

## Project Structure

```
HackAgent/
├── src/
│   ├── main/
│   │   ├── main.ts              # Electron main process
│   │   ├── preload.ts           # Context bridge for renderer
│   │   └── backend-manager.ts   # Express server lifecycle
│   ├── backend/
│   │   ├── server.ts            # Express API routes + unified pipeline
│   │   ├── services/
│   │   │   ├── page-analyzer.ts # 20+ automated vulnerability checks
│   │   │   └── openai-client.ts # GPT-4o with Jhaddix context injection
│   │   └── models/
│   │       └── types.ts         # TypeScript interfaces
│   └── renderer/
│       ├── index.html           # Main UI
│       ├── app.js               # Frontend logic
│       └── styles/style.css     # Styles
├── firefox_extension/
│   ├── manifest.json            # WebExtension manifest (MV2)
│   ├── popup/                   # Extension popup UI
│   ├── content/content.js       # Deep page capture script
│   └── background/background.js # Message routing
├── data/
│   ├── attack_surface.json      # Jhaddix attack surface knowledge base
│   └── projects/                # Saved analysis results (auto-created)
├── config/
│   └── settings.yaml            # App settings
├── package.json
├── tsconfig.json
└── README.md
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | OpenAI API key (can also be set via the app UI) |
| `HACKAGENT_PORT` | Backend server port (default: `5175`) |

## License

[MIT](LICENSE)
