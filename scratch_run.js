const { verify } = require('./src/index.js');
const crypto = require('crypto');

// Basic ANSI formatting colors
const green = (t) => `\x1b[32m${t}\x1b[0m`;
const red = (t) => `\x1b[31m${t}\x1b[0m`;
const cyan = (t) => `\x1b[36m${t}\x1b[0m`;

console.log('--- Running webhookshield Verification Checks ---');

const secret = 'webhook-signing-secret-key-abc';
const payload = JSON.stringify({ userId: 99, email: 'user@example.com' });

// 1. Stripe Verify
const stripeTime = Math.floor(Date.now() / 1000).toString();
const stripeMac = crypto.createHmac('sha256', secret).update(`${stripeTime}.${payload}`).digest('hex');
const stripeHeader = `t=${stripeTime},v1=${stripeMac}`;
const isStripeValid = verify('stripe', { payload, signature: stripeHeader, secret });
console.log(`Stripe:       [${isStripeValid ? green('PASSED') : red('FAILED')}]`);

// 2. GitHub Verify
const githubMac = crypto.createHmac('sha256', secret).update(payload).digest('hex');
const githubHeader = `sha256=${githubMac}`;
const isGithubValid = verify('github', { payload, signature: githubHeader, secret });
console.log(`GitHub:       [${isGithubValid ? green('PASSED') : red('FAILED')}]`);

// 3. Clerk Verify (Svix)
const clerkSecret = Buffer.from('svix-secret-base64-bytes-abc').toString('base64');
const svixId = 'msg_987654';
const svixTimestamp = Math.floor(Date.now() / 1000).toString();
const clerkMac = crypto
  .createHmac('sha256', Buffer.from(clerkSecret, 'base64'))
  .update(`${svixId}.${svixTimestamp}.${payload}`)
  .digest('base64');
const clerkHeader = `v1,${clerkMac}`;
const isClerkValid = verify('clerk', {
  payload,
  signature: clerkHeader,
  secret: clerkSecret,
  svixId,
  svixTimestamp,
});
console.log(`Clerk (Svix): [${isClerkValid ? green('PASSED') : red('FAILED')}]`);

// 4. Invalid Check (Sanity Failure)
const isBadStripeValid = verify('stripe', { payload, signature: `t=${stripeTime},v1=badmac`, secret });
console.log(`Tampered Sig: [${!isBadStripeValid ? green('BLOCKED') : red('ALLOWED')}] (Expected: BLOCKED)`);
