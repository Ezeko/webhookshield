const crypto = require('crypto');

/**
 * Timing-safe string comparison to mitigate timing attacks.
 * Verifies length equivalence first to avoid V8 timingSafeEqual crashes.
 */
function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Stripe signature verification
 */
function verifyStripe({ payload, signature, secret, tolerance = 300 }) {
  if (!signature || !secret) return false;

  const parts = signature.split(',');
  let timestamp = '';
  const signatures = [];

  for (const part of parts) {
    const [key, value] = part.split('=');
    if (key === 't') {
      timestamp = value;
    } else if (key === 'v1') {
      signatures.push(value);
    }
  }

  if (!timestamp || signatures.length === 0) {
    return false;
  }

  // Validate request timestamp offset to prevent replay attacks
  const currentTimestamp = Math.floor(Date.now() / 1000);
  const diff = Math.abs(currentTimestamp - Number(timestamp));
  if (diff > tolerance) {
    return false;
  }

  const toSign = `${timestamp}.${payload}`;
  const expectedMac = crypto
    .createHmac('sha256', secret)
    .update(toSign)
    .digest('hex');

  return signatures.some((sig) => safeCompare(sig, expectedMac));
}

/**
 * GitHub signature verification
 */
function verifyGitHub({ payload, signature, secret }) {
  if (!signature || !secret) return false;

  let expectedSignature = signature;
  if (signature.startsWith('sha256=')) {
    expectedSignature = signature.substring(7);
  }

  const expectedMac = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');

  return safeCompare(expectedSignature, expectedMac);
}

/**
 * Clerk & Svix signature verification
 */
function verifyClerk({ payload, signature, secret, svixId, svixTimestamp, tolerance = 300 }) {
  if (!signature || !secret || !svixId || !svixTimestamp) {
    return false;
  }

  // Check clock skew tolerance
  const currentTimestamp = Math.floor(Date.now() / 1000);
  const diff = Math.abs(currentTimestamp - Number(svixTimestamp));
  if (diff > tolerance) {
    return false;
  }

  // Svix secrets are base64 encoded. Strip whsec_ prefix if present.
  const cleanSecret = secret.startsWith('whsec_') ? secret.substring(6) : secret;
  let secretKey;
  try {
    secretKey = Buffer.from(cleanSecret, 'base64');
  } catch (err) {
    secretKey = cleanSecret;
  }

  const toSign = `${svixId}.${svixTimestamp}.${payload}`;
  const expectedMac = crypto
    .createHmac('sha256', secretKey)
    .update(toSign)
    .digest('base64');

  // svix-signature header can contain multiple signatures separated by spaces (e.g. v1,sig1 v1,sig2)
  const passedSignatures = signature.split(' ').map((sig) => {
    if (sig.startsWith('v1,')) {
      return sig.substring(3);
    }
    return sig;
  });

  return passedSignatures.some((sig) => safeCompare(sig, expectedMac));
}

/**
 * Shopify signature verification
 */
function verifyShopify({ payload, signature, secret }) {
  if (!signature || !secret) return false;

  const expectedMac = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('base64');

  return safeCompare(signature, expectedMac);
}

/**
 * Lemon Squeezy signature verification
 */
function verifyLemonSqueezy({ payload, signature, secret }) {
  if (!signature || !secret) return false;

  const expectedMac = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');

  return safeCompare(signature, expectedMac);
}

module.exports = {
  stripe: verifyStripe,
  github: verifyGitHub,
  clerk: verifyClerk,
  resend: verifyClerk, // Resend shares the standard Svix webhook signature format
  shopify: verifyShopify,
  lemonsqueezy: verifyLemonSqueezy,
};
