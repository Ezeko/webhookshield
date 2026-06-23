export interface VerifyOptions {
  /**
   * Raw request body payload. Can be a string or a Buffer.
   */
  payload: string | Buffer;
  /**
   * Signature header value from the provider.
   */
  signature: string;
  /**
   * Shared signing secret key.
   */
  secret: string;
  /**
   * Timestamp drift offset tolerance in seconds (Stripe, Clerk, Resend).
   * Defaults to 300.
   */
  tolerance?: number;
  /**
   * Svix message ID (Required for Clerk, Resend).
   */
  svixId?: string;
  /**
   * Svix timestamp header (Required for Clerk, Resend).
   */
  svixTimestamp?: string;
}

export type WebhookProvider =
  | 'stripe'
  | 'github'
  | 'clerk'
  | 'resend'
  | 'shopify'
  | 'lemonsqueezy'
  | string;

export class WebhookShield {
  /**
   * Verifies the authenticity of a webhook request payload.
   */
  static verify(provider: WebhookProvider, options: VerifyOptions): boolean;
}

/**
 * Shorthand function to verify the authenticity of a webhook request payload.
 */
export function verify(provider: WebhookProvider, options: VerifyOptions): boolean;
