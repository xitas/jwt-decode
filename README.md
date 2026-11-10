# JWT Decoder

A JSON Web Token decoder built with plain HTML, CSS and JavaScript. Paste a token to read its header, payload and claims, and check its signature. No frameworks, no build step, and your token never leaves your browser.

**Live demo:** [https://xitas.github.io/jwt-decoder/](https://xitas.github.io/jwt-decoder/)

## Features

- **Decode** the header and payload with syntax highlighting
- **Color-coded token:** header, payload and signature are shown in different colors
- **Standard claims explained:** issuer, subject, audience, token ID, and the times `exp`, `nbf` and `iat` as readable dates with "in 2 hours" or "3 days ago"
- **Expiry status** that tells you if a token is expired or not active yet
- **Warnings** for risky tokens: algorithm `none`, no expiry, and times given in milliseconds
- **Verify the signature** for `HS`, `RS`, `PS` and `ES` algorithms with 256, 384 or 512 bits
- **Helpful errors:** wrong number of parts, bad Base64URL, invalid JSON, and encrypted (JWE) tokens
- **Copy** the decoded header or payload
- Accepts a pasted `Bearer ` prefix and tokens split over several lines
- **Light and dark** themes that follow your system setting

## Project structure

```
.
├── index.html   # Page markup
├── style.css    # Styles
├── script.js    # Decoding, claim handling, signature checks and UI
└── README.md
```

## Getting started

No installation needed. You can use the [live demo](https://xitas.github.io/jwt-decoder/) or run it locally.

1. Clone the repository:
   ```bash
   git clone https://github.com/xitas/jwt-decoder.git
   cd jwt-decoder
   ```
2. Open `index.html` in your browser.

Optionally, serve it locally:

```bash
python3 -m http.server 8000
```

Then visit `http://localhost:8000`.

## Usage

1. Paste a token into **Encoded token**, or click **Load sample**.
2. Read the header, payload and standard claims on the right.
3. To check the signature, enter the key under **Verify signature**:
   - For `HS256`, `HS384` and `HS512`, enter the shared secret. Tick the box if the secret is Base64URL encoded.
   - For `RS`, `PS` and `ES` algorithms, paste the public key in `-----BEGIN PUBLIC KEY-----` format.

The sample token is created in your browser and signed with the secret `demo-secret`, so you can try the signature check right away.

## How it works

- A JWT has three Base64URL parts separated by dots: `header.payload.signature`. The page decodes the first two and parses them as JSON.
- Signatures are checked with the browser's built-in Web Crypto API (`crypto.subtle`). No library is used.
- `ES` signatures are in the raw format JWTs use, which Web Crypto accepts directly.
- The token and key are only kept in memory while the page is open. Nothing is saved or sent.

## Notes

- **Decoding is not verifying.** Anyone can create a token that decodes fine. Only a successful signature check shows it was signed with the key you expect.
- Never paste a private key. The page rejects keys that look private.
- Public keys must be in the `BEGIN PUBLIC KEY` (SPKI) format. Certificates and older `BEGIN RSA PUBLIC KEY` keys need converting first. The page shows the `openssl` command for this.
- Algorithms such as `EdDSA` and `ES256K` can be decoded but not verified here.
- Signature checks need a secure page. They work on `https`, on `localhost` and on GitHub Pages.
- Very large numbers in a payload can lose precision, because the page uses the browser's `JSON.parse`.

## License

Add a license of your choice (for example MIT) in a `LICENSE` file.
