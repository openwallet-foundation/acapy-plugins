/**
 * URL Encoding utilities for walt.id wallet.
 * 
 * The walt.id wallet uses base64url encoding for credential offer and presentation
 * request URLs passed as query parameters.
 */

/**
 * Encode a URL/string for use in walt.id wallet request parameter.
 * Uses base64url encoding (URL-safe base64 with padding removed).
 * 
 * @param input - The URL or string to encode
 * @returns base64url encoded string
 */
export function encodeRequest(input: string): string {
  // Convert to base64
  const base64 = Buffer.from(input, 'utf-8').toString('base64');
  
  // Convert to base64url (replace + with -, / with _, remove padding =)
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Decode a base64url encoded request parameter.
 * 
 * @param encoded - The base64url encoded string
 * @returns Decoded URL or string
 */
export function decodeRequest(encoded: string): string {
  // Convert from base64url to base64 (replace - with +, _ with /)
  let base64 = encoded
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  
  // Add padding if needed
  const padding = base64.length % 4;
  if (padding) {
    base64 += '='.repeat(4 - padding);
  }
  
  // Decode from base64
  return Buffer.from(base64, 'base64').toString('utf-8');
}

/**
 * Build the issuance page URL for walt.id wallet.
 * 
 * The walt.id wallet expects:
 * - Path: /wallet/{walletId}/exchange/issuance
 * - Query: ?request={base64-encoded-offer-url}
 * 
 * @param baseUrl - The wallet frontend base URL
 * @param credentialOfferUrl - The full credential offer URL (openid-credential-offer://...)
 * @param walletId - Optional wallet ID (if not provided, will navigate without wallet in path)
 * @returns Full URL to navigate to for credential issuance
 */
export function buildIssuanceUrl(
  baseUrl: string,
  credentialOfferUrl: string,
  walletId?: string
): string {
  const encodedOffer = encodeRequest(credentialOfferUrl);
  // If walletId is provided, include it in the path (for authenticated users)
  // Otherwise, use the simpler path and let the wallet redirect to the right wallet
  if (walletId) {
    return `${baseUrl}/wallet/${walletId}/exchange/issuance?request=${encodedOffer}`;
  }
  // Without wallet ID, try api/siop/initiateIssuance which will redirect
  return `${baseUrl}/api/siop/initiateIssuance?credential_offer=${encodeURIComponent(credentialOfferUrl)}`;
}

/**
 * Build the presentation page URL for walt.id wallet.
 * 
 * The walt.id wallet expects:
 * - Path: /wallet/{walletId}/exchange/presentation
 * - Query: ?request={base64-encoded-request-url}
 * 
 * @param baseUrl - The wallet frontend base URL
 * @param presentationRequestUrl - The full presentation request URL (openid4vp://...)
 * @param walletId - Optional wallet ID
 * @returns Full URL to navigate to for credential presentation
 */
export function buildPresentationUrl(
  baseUrl: string,
  presentationRequestUrl: string,
  walletId?: string
): string {
  const encodedRequest = encodeRequest(presentationRequestUrl);
  if (walletId) {
    return `${baseUrl}/wallet/${walletId}/exchange/presentation?request=${encodedRequest}`;
  }
  return `${baseUrl}/api/siop/initiatePresentation?presentation_request=${encodeURIComponent(presentationRequestUrl)}`;
}
