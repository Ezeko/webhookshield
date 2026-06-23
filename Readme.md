# 🛡️ webhookshield

[![NPM Version](https://img.shields.io/npm/v/webhookshield.svg?style=flat-square&color=blue)](https://www.npmjs.com/package/webhookshield)
[![Downloads](https://img.shields.io/npm/dm/webhookshield.svg?style=flat-square)](https://www.npmjs.com/package/webhookshield)
[![Build Status](https://img.shields.io/github/actions/workflow/status/Ezeko/webhookshield/ci.yml?branch=main&style=flat-square)](https://github.com/Ezeko/webhookshield/actions)
[![License](https://img.shields.io/npm/l/webhookshield.svg?style=flat-square)](https://github.com/Ezeko/webhookshield/blob/main/LICENCE)
[![GitHub Stars](https://img.shields.io/github/stars/Ezeko/webhookshield.svg?style=flat-square&label=stars&color=yellow)](https://github.com/Ezeko/webhookshield/stargazers)

> **Unified, zero-dependency, edge-compatible webhook signature verification library for Node.js and TypeScript.**

`webhookshield` is a lightweight security utility that provides a single, unified API to verify webhook signatures across popular SaaS platforms. By using native runtime cryptography, it eliminates the need to install heavy official SDKs (like `@stripe/stripe-js` or `@clerk/backend`), resulting in a smaller bundle size and zero external dependencies.

---

## Key Features

*   **⚡ Sub-10ms Edge Execution**: Zero dependencies and fully optimized for Edge runtimes (Cloudflare Workers, Vercel Edge, Bun, Lagon) as well as traditional Node.js.
*   **🔒 Hardened Security**: Utilizes cryptographic constant-time comparison algorithms (`crypto.timingSafeEqual`) to completely block timing attacks.
*   **🛠️ Multi-Provider Support**: Verify signatures for Stripe, GitHub, Clerk, Resend, Shopify, and Lemon Squeezy in one library.
*   **📦 Native TypeScript Support**: Prepackaged with type definitions (`index.d.ts`) for developer autocompletion.
*   **⏳ Replay Attack Guards**: Automated timestamp drift verification checks (with customizable tolerances).

---

## Supported Providers

| Provider | Signature Format | Header Key | Replay Protection |
| :--- | :--- | :--- | :--- |
| **Stripe** | HMAC-SHA256 (Hex) | `stripe-signature` | ✅ Yes (5m Tolerance) |
| **GitHub** | HMAC-SHA256 (Hex) | `x-hub-signature-256` | ❌ No |
| **Clerk / Svix** | HMAC-SHA256 (Base64) | `svix-signature` | ✅ Yes (5m Tolerance) |
| **Resend** | HMAC-SHA256 (Base64) | `svix-signature` | ✅ Yes (5m Tolerance) |
| **Shopify** | HMAC-SHA256 (Base64) | `x-shopify-hmac-sha256` | ❌ No |
| **Lemon Squeezy** | HMAC-SHA256 (Hex) | `x-signature` | ❌ No |

---

## Installation

Install via your preferred package manager:

```bash
npm install webhookshield
# or
yarn add webhookshield
# or
pnpm add webhookshield
# or
bun add webhookshield
```

---

## Quick Start Examples

### 1. Stripe Webhooks

```javascript
const { verify } = require('webhookshield');

const isValid = verify('stripe', {
  payload: req.rawBody, // Must be the raw request string
  signature: req.headers['stripe-signature'],
  secret: process.env.STRIPE_WEBHOOK_SECRET
});

if (!isValid) {
  return res.status(400).send('Webhook signature verification failed');
}
```

### 2. Clerk (Svix) Webhooks

```javascript
const { verify } = require('webhookshield');

const isValid = verify('clerk', {
  payload: req.rawBody,
  signature: req.headers['svix-signature'],
  secret: process.env.CLERK_WEBHOOK_SECRET,
  svixId: req.headers['svix-id'],
  svixTimestamp: req.headers['svix-timestamp']
});
```

### 3. GitHub Webhooks

```javascript
const { verify } = require('webhookshield');

const isValid = verify('github', {
  payload: req.rawBody,
  signature: req.headers['x-hub-signature-256'],
  secret: process.env.GITHUB_WEBHOOK_SECRET
});
```

---

## Contributing

We welcome community contributions! If you want to add signature support for a new provider:

1. Fork and clone the repository: `git clone https://github.com/Ezeko/webhookshield.git`
2. Add your provider logic in `src/providers.js`
3. Write automated unit assertions in `tests/index.test.js`
4. Run tests locally: `npm test`

Please read our [Contributing Guide](CONTRIBUTING.md) to understand linting rules and PR submission procedures.

---

## License

MIT © [Ezekiel Adejobi](https://github.com/ezeko)
