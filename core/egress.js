/**
 * Egress filtering for outbound text and response payloads.
 * This layer is the last line of defense before the user sees the response.
 */

const INTERNAL_PATTERNS = [
  // AWS access key formats
  /AKIA[0-9A-Z]{8,20}/,
  // Stripe secret keys
  /(?:sk_live|sk_test)_[0-9a-zA-Z]{24,}/,
  // JWT-like tokens
  /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/,
  // GitHub personal access tokens
  /ghp_[A-Za-z0-9_]{36}/,
  // Google API keys
  /AIza[0-9A-Za-z_-]{35}/,
  // SendGrid API keys
  /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/,
  // Slack tokens
  /xox[baprs]-[0-9A-Za-z-]{10,}/,
  // Private keys and SSH public key headers
  /(?:ssh-rsa|ssh-ed25519|-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)/i,
  // Inline credential assignments — captures the value to avoid partial redaction
  /(?:password|passwd|secret|api_key|apikey)\s*[=:]\s*\S+/i,
  // Internal account ID pattern
  /\bACC-\d{4}-\d{4}\b/,
  // Credit card-like strings (4x4 digit groups)
  /\b\d{4}-\d{4}-\d{4}-\d{4}\b/,
];

export function detectLeakage(text) {
  if (typeof text !== 'string') {
    return { leaked: false, matches: [] };
  }

  const matches = INTERNAL_PATTERNS.filter((pattern) => pattern.test(text));
  return {
    leaked: matches.length > 0,
    matches: matches.map((pattern) => pattern.toString()),
  };
}

export function filterOutbound(responseText, { placeholder = '[REDACTED]' } = {}) {
  if (typeof responseText !== 'string') {
    return responseText;
  }

  let safeText = responseText;
  INTERNAL_PATTERNS.forEach((pattern) => {
    // Always apply with 'g' flag so all occurrences in the response are replaced,
    // not just the first match.
    const globalPattern = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
    safeText = safeText.replace(globalPattern, placeholder);
  });

  return safeText;
}

export function assertSafeEgress(responseText) {
  const result = detectLeakage(responseText);
  if (result.leaked) {
    return {
      safe: false,
      message: 'Outbound response contains patterns resembling internal secrets or regulated identifiers.',
      matches: result.matches,
    };
  }

  return { safe: true, message: 'Egress text passed the outbound safety checks.' };
}
