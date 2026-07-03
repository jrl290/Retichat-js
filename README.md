# Retichat Web

Zero-tooling browser chat app for the [Reticulum Network Stack](https://reticulum.network/). Drop this folder onto any static web server — no npm, no build step, no Node.js required.

Connects to a [Reticulum-php](https://github.com/jrl290/Reticulum-post) HTTP exchange node to send and receive encrypted LXMF messages over the Reticulum mesh.

## Quick Start

1. Edit `config.json` — set `exchangeUrl` to your Reticulum-php node
2. Drop this folder on any static web server
3. Open in a browser

```json
{
    "exchangeUrl": "https://your-node.example.com/reticulum",
    "displayName": "Retichat Web",
    "announceIntervalMs": 300000
}
```

## Features

- **No build step** — pure ES modules loaded directly by the browser
- **HTTP exchange transport** — no WebSocket, no raw sockets, works behind any hosting
- **End-to-end encryption** — AES-256-CBC + X25519 key exchange matching Python RNS reference
- **Privacy filter** — only accept messages from contacts you've explicitly added
- **Contact management** — add by destination hash, share your own identity

## Structure

```
├── index.html          Entry point
├── app.js              Main application
├── config.json         Node URL + preferences
├── style.css           UI styles
└── lib/
    ├── rns/            RNS protocol library (ES modules)
    └── shims/          Browser polyfills (crypto, net, ws)
```

## Dependencies

All external dependencies are loaded from CDN via import map in `index.html`:
- `@noble/curves` — elliptic curve cryptography
- `@noble/hashes` — SHA-256, SHA-512
- `msgpackr` — MessagePack encoding
- `buffer` — Node.js Buffer polyfill

No package.json. No node_modules. No build.

## License

MIT
