# Retichat Web

> **⚠️ Work in Progress** — This project is under active development. APIs, protocols, and UI may change.  
> **🤖 AI-Assisted Development** — A significant portion of this codebase was generated and refined with AI coding assistance (GitHub Copilot / Claude). All generated code has been reviewed and tested by a human developer.

Browser chat client for the [Reticulum Network Stack](https://reticulum.network/). Drop this folder onto any static web server — no npm, no build step, no Node.js required.

Connects to a [Reticulum-post](https://github.com/jrl290/Reticulum-post) HTTP exchange node to send and receive encrypted LXMF messages across the Reticulum mesh.

## Architecture

```
┌──────────────────────────────────────────────┐
│  Retichat Web (Browser)                      │
│  ┌──────────┐  ┌──────────┐  ┌────────────┐ │
│  │  UI (JS) │──│  RNS.js  │──│  HTTP Poll  │ │
│  │  Two-panel│  │  LXMF    │  │  Exchange   │ │
│  │  layout  │  │  Crypto  │  │  Client     │ │
│  └──────────┘  └──────────┘  └──────┬─────┘ │
└─────────────────────────────────────┼───────┘
                                      │ HTTP POST
                                      ▼
┌──────────────────────────────────────────────┐
│  Reticulum-post (PHP Router)                 │
│  ┌──────────────────┐  ┌──────────────────┐ │
│  │  HTTP Exchange   │  │  Python Bridge   │ │
│  │  API (index.php) │──│  (PostInterface) │ │
│  └──────────────────┘  └────────┬─────────┘ │
└─────────────────────────────────┼───────────┘
                                  │
                          ┌───────┴───────┐
                          │  Reticulum    │
                          │  Backbone     │
                          └───────────────┘
```

## Transport Mechanisms

### Pull-Poll (One-Way Initiation)

The primary transport mode. The browser client **pulls** by periodically HTTP POSTing queued outbound packets to the PHP router, and receiving any inbound packets queued for it in the response. This works through firewalls, shared hosting, and NAT — the client initiates every request, the server never pushes.

```
Client                              PHP Router
  │                                     │
  │── POST /exchange (outbound pkts) ──►│
  │◄─ JSON response (inbound pkts) ────│
  │                                     │
  │        ... wait (poll interval) ... │
  │                                     │
  │── POST /exchange (outbound pkts) ──►│
  │◄─ JSON response (inbound pkts) ────│
```

- No WebSocket, no raw sockets, no open inbound ports
- Works behind any static web host or CDN
- Poll interval is adaptive (speeds up when messages are flowing)

### Push-Push (Two-Way Initiation)

When two nodes both have registered interfaces and have exchanged announces, the transport can operate in **push-push** mode. Either side can initiate a transfer at any time — packets flow bidirectionally without polling. This requires both nodes to be reachable (e.g., via Direct Sockets or a mutually accessible exchange node).

```
Node A                               Node B
  │                                     │
  │──── announce (lxmf.delivery) ──────►│  path established
  │◄─── announce (lxmf.delivery) ──────│  bidirectional
  │                                     │
  │──── LXMF message ──────────────────►│  either side pushes
  │◄─── LXMF message ──────────────────│  independently
```

## Features

- **Zero tooling** — pure ES modules loaded directly by the browser via import maps
- **Two-panel responsive UI** — sidebar + chat on wide screens (≥800px), slide-in chat on phones, modeled after Retichat iOS
- **Dark theme by default** with light mode toggle (matches iOS design language)
- **HTTP exchange transport** — no WebSocket, no raw sockets, works behind any hosting
- **End-to-end encryption** — AES-256-CBC + X25519 key exchange matching Python RNS reference
- **Privacy filter** — only accept messages from contacts you've explicitly added
- **Contact management** — add by destination hash or lxmf:///lxma:// link, share your own identity
- **Glass-morphism UI** — translucent surfaces matching iOS GlassBackground design language

## Quick Start

1. Edit `config.json` — set `exchangeUrl` to your Reticulum-post node
2. Drop this folder on any static web server
3. Open in a browser

```json
{
    "exchangeUrl": "https://your-node.example.com/reticulum",
    "displayName": "Retichat Web",
    "announceIntervalMs": 300000
}
```

## Structure

```
├── index.html              Entry point (import map + mount)
├── app.js                  Main application (UI + RNS client)
├── config.json             Node URL + preferences
├── style.css               Theme system + responsive layout
├── retichat-icon.png       App icon (favicon + PWA)
└── lib/
    ├── rns/                RNS protocol library (ES modules)
    │   └── reticulum.js    Identity, Destination, LXMF, interfaces
    └── shims/              Browser polyfills
        ├── crypto.js       Web Crypto API shim
        ├── net.js          Network stubs
        └── ws.js           WebSocket stubs
```

## Dependencies

All external dependencies are loaded from CDN via import map in `index.html`:
- `@noble/curves` — elliptic curve cryptography
- `@noble/hashes` — SHA-256, SHA-512
- `msgpackr` — MessagePack encoding
- `buffer` — Node.js Buffer polyfill

No `package.json`. No `node_modules`. No build step.

## Related Projects

- [Reticulum-post](https://github.com/jrl290/Reticulum-post) — PHP HTTP exchange router + Python bridge
- [Reticulum](https://github.com/markqvist/Reticulum) — Python reference implementation
- [Retichat Android](https://github.com/jrl290/Retichat-android) — Native Android client
- [Retichat iOS](https://github.com/jrl290/Retichat-ios) — Native iOS client

## License

MIT
