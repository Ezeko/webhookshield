/**
 * webhookshield: Unified, zero-dependency, edge-compatible webhook signature verifier.
 */

const providers = require('./providers');

class WebhookShield {
  /**
   * Verify authenticity of a webhook request payload
   * @param {string} provider - Name of the provider (stripe, github, clerk, shopify, lemonsqueezy, resend)
   * @param {object} options - Verification arguments
   * @param {string | Buffer} options.payload - Raw payload body string or Buffer
   * @param {string} options.signature - Signature header value from provider
   * @param {string} options.secret - Shared signing secret key
   * @param {number} [options.tolerance=300] - Timestamp offset tolerance in seconds (Stripe, Clerk)
   * @param {string} [options.svixId] - Svix-ID header (Clerk)
   * @param {string} [options.svixTimestamp] - Svix-Timestamp header (Clerk)
   * @returns {boolean} True if the signature is valid, false otherwise
   */
  static verify(provider, options = {}) {
    if (!provider) {
      throw new Error('Provider name is required');
    }

    const normalizedProvider = provider.toLowerCase().replace(/[^a-z0-9]/g, '');
    const verifier = providers[normalizedProvider];

    if (!verifier) {
      throw new Error(`Unsupported webhook provider: ${provider}`);
    }

    // Standardize payload to string for consistent hashing
    const payloadStr = typeof options.payload === 'string'
      ? options.payload
      : (Buffer.isBuffer(options.payload) ? options.payload.toString('utf8') : '');

    if (!payloadStr && options.payload) {
      return false;
    }

    try {
      return verifier({
        ...options,
        payload: payloadStr,
      });
    } catch (err) {
      // Return false instead of breaking on corrupted signature shapes
      return false;
    }
  }
}

module.exports = {
  WebhookShield,
  verify: WebhookShield.verify,
};
