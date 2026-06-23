const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { verify, WebhookShield } = require('../src/index.js');

test('webhookshield verification suite', async (t) => {
  const secret = 'super-secret-signing-key';
  const payload = JSON.stringify({ event: 'user.created', id: 'usr_123' });

  await t.test('verifies Stripe signatures correctly', () => {
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const toSign = `${timestamp}.${payload}`;
    const validMac = crypto.createHmac('sha256', secret).update(toSign).digest('hex');
    const signatureHeader = `t=${timestamp},v1=${validMac}`;

    const isValid = verify('stripe', {
      payload,
      signature: signatureHeader,
      secret,
    });
    assert.strictEqual(isValid, true);

    const isInvalid = verify('stripe', {
      payload,
      signature: `t=${timestamp},v1=badmac`,
      secret,
    });
    assert.strictEqual(isInvalid, false);
  });

  await t.test('fails Stripe verification if timestamp is out of tolerance', () => {
    // 10 minutes ago (tolerance is 300s/5m by default)
    const oldTimestamp = (Math.floor(Date.now() / 1000) - 600).toString();
    const toSign = `${oldTimestamp}.${payload}`;
    const validMac = crypto.createHmac('sha256', secret).update(toSign).digest('hex');
    const signatureHeader = `t=${oldTimestamp},v1=${validMac}`;

    const isValid = verify('stripe', {
      payload,
      signature: signatureHeader,
      secret,
    });
    assert.strictEqual(isValid, false);
  });

  await t.test('verifies GitHub signatures with or without prefix', () => {
    const validMac = crypto.createHmac('sha256', secret).update(payload).digest('hex');

    const isValidWithPrefix = verify('github', {
      payload,
      signature: `sha256=${validMac}`,
      secret,
    });
    assert.strictEqual(isValidWithPrefix, true);

    const isValidWithoutPrefix = verify('github', {
      payload,
      signature: validMac,
      secret,
    });
    assert.strictEqual(isValidWithoutPrefix, true);

    const isInvalid = verify('github', {
      payload,
      signature: 'sha256=invalidmac',
      secret,
    });
    assert.strictEqual(isInvalid, false);
  });

  await t.test('verifies Clerk (Svix) signatures', () => {
    // Svix secrets are base64 strings. Let's make a mock base64 secret.
    const svixSecret = Buffer.from('my-svix-secret-key-12345').toString('base64');
    const svixId = 'msg_xyz789';
    const svixTimestamp = Math.floor(Date.now() / 1000).toString();

    const toSign = `${svixId}.${svixTimestamp}.${payload}`;
    const validMac = crypto
      .createHmac('sha256', Buffer.from(svixSecret, 'base64'))
      .update(toSign)
      .digest('base64');

    const isValid = verify('clerk', {
      payload,
      signature: `v1,${validMac}`,
      secret: svixSecret,
      svixId,
      svixTimestamp,
    });
    assert.strictEqual(isValid, true);

    const isInvalid = verify('clerk', {
      payload,
      signature: 'v1,badmac',
      secret: svixSecret,
      svixId,
      svixTimestamp,
    });
    assert.strictEqual(isInvalid, false);
  });

  await t.test('verifies Resend signatures by delegating to Clerk verifier', () => {
    const resendSecret = Buffer.from('my-resend-secret-key').toString('base64');
    const svixId = 'msg_resend_1';
    const svixTimestamp = Math.floor(Date.now() / 1000).toString();

    const toSign = `${svixId}.${svixTimestamp}.${payload}`;
    const validMac = crypto
      .createHmac('sha256', Buffer.from(resendSecret, 'base64'))
      .update(toSign)
      .digest('base64');

    const isValid = verify('resend', {
      payload,
      signature: `v1,${validMac}`,
      secret: resendSecret,
      svixId,
      svixTimestamp,
    });
    assert.strictEqual(isValid, true);
  });

  await t.test('verifies Shopify signatures', () => {
    const validMac = crypto.createHmac('sha256', secret).update(payload).digest('base64');

    const isValid = verify('shopify', {
      payload,
      signature: validMac,
      secret,
    });
    assert.strictEqual(isValid, true);
  });

  await t.test('verifies Lemon Squeezy signatures', () => {
    const validMac = crypto.createHmac('sha256', secret).update(payload).digest('hex');

    const isValid = verify('lemonsqueezy', {
      payload,
      signature: validMac,
      secret,
    });
    assert.strictEqual(isValid, true);
  });

  await t.test('handles unsupported providers and missing parameters cleanly', () => {
    assert.throws(() => {
      verify('unknown_provider', { payload, signature: 'any', secret });
    }, /Unsupported webhook provider/);

    // Missing signature returns false rather than throwing
    const isInvalid = verify('stripe', { payload, secret });
    assert.strictEqual(isInvalid, false);
  });
});
