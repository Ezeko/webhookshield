# Contributing to webhookshield

First off, thank you for considering contributing to `webhookshield`! It is through community contributions that this library grows to support new services.

We welcome support for:
*   Adding signature verification for a new SaaS webhook provider
*   Fixing security holes or edge case payload parser bugs
*   Performance enhancements for edge runtime optimization
*   Improving TypeScript definitions

---

## How to Add a New Webhook Provider

Adding verification for a new SaaS provider is straightforward:

1.  **Fork and clone** the repository.
2.  Open [src/providers.js](src/providers.js) and implement your verification function:
    ```javascript
    /**
     * MyProvider signature verification
     */
    function verifyMyProvider({ payload, signature, secret }) {
      if (!signature || !secret) return false;
      
      const expectedMac = crypto
        .createHmac('sha256', secret)
        .update(payload)
        .digest('hex'); // or 'base64'
        
      return safeCompare(signature, expectedMac);
    }
    ```
3.  Add the new function mapping to `module.exports` at the bottom of the file:
    ```javascript
    module.exports = {
      // ... existing providers
      myprovider: verifyMyProvider,
    };
    ```
4.  Add automated unit assertions in [tests/index.test.js](tests/index.test.js) mapping success and failure signature scenarios.
5.  Update the TypeScript definition types in [index.d.ts](index.d.ts) to include the new provider name.
6.  Run the tests to verify your implementation:
    ```bash
    npm test
    ```
7.  Submit a pull request to the `main` branch.

---

## Coding Rules & Security

*   **Timing Attack Mitigation**: Always use the native `safeCompare` helper function to verify signatures. Do not use direct string equality checks (`===`) as they expose endpoints to timing attacks.
*   **Zero Dependencies**: We do not allow external dependencies (like official vendor SDKs). All verification routines must use native Node.js `crypto` or Web Cryptography APIs.
*   **Edge Compatibility**: Code must run successfully in edge environments (Cloudflare Workers, Vercel Edge). Avoid referencing Node-only globals that aren't available on the Edge.

Thank you for helping keep webhooks secure!
