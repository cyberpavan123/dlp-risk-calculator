/**
 * Tier 1 ingress protection for public and lightly sensitive content.
 * This module is intentionally simple so developers can copy it into middleware.
 */

const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+all\s+previous\s+instructions/i,
  /ignore\s+previous\s+instructions/i,
  /bypass.*security/i,
  /delete.*this.*message/i,
  /do not follow.*earlier/i,
  /act\s+as\s+(a|an|the)\s+/i,
  /pretend\s+(you\s+are|to\s+be)\s+/i,
  /forget\s+(all\s+)?(your\s+)?(previous\s+)?(instructions|rules|guidelines)/i,
  /you\s+are\s+now\s+(a|an|the)\s+/i,
  /\bDAN\b/,
  /override\s+(your\s+)?(instructions|constraints|rules)/i,
  /new\s+instructions\s*:/i,
  /disregard\s+(your\s+)?(previous|all|prior)\s+/i,
  /reveal\s+(your\s+)?(system\s+prompt|instructions|prompt)/i,
  /repeat\s+(the\s+)?(above|following)\s+(instructions|text|prompt)/i,
  /generate.*secret/i,
];

// Strips control chars except LF (\x0a), which is preserved after CRLF normalization.
// \x00-\x09 = NUL..HT, \x0b-\x1f = VT..US (skips LF at \x0a), \x7f-\x9f = DEL + C1.
const CONTROL_CHARACTERS = /[\x00-\x09\x0b-\x1f\x7f-\x9f]/g;

/**
 * Basic sanitization for Tier 1 public payloads.
 * - normalizes CRLF/CR to LF first (must happen before control-char stripping)
 * - strips remaining control characters (LF is preserved)
 * - trims leading/trailing whitespace
 */
export function sanitizeInput(rawText) {
  if (typeof rawText !== 'string') {
    return rawText;
  }

  return rawText
    .replace(/\r\n?/g, '\n')
    .replace(CONTROL_CHARACTERS, ' ')
    .trim();
}

/**
 * Detect prompt-injection-style payloads before calling the LLM.
 */
export function checkPromptInjection(text) {
  const normalized = String(text || '').toLowerCase();
  const matches = PROMPT_INJECTION_PATTERNS.filter((pattern) => pattern.test(normalized));

  return {
    blocked: matches.length > 0,
    reason: matches.length > 0 ? 'Potential prompt injection detected.' : 'No injection patterns found.',
    matches: matches.map((pattern) => pattern.toString()),
  };
}

/**
 * Example Tier 1 public input handler.
 * Use this before the prompt is composed and sent to your LLM orchestration layer.
 */
export function handleTier1PublicInput(rawInput) {
  const sanitized = sanitizeInput(rawInput);
  const injectionResult = checkPromptInjection(sanitized);

  if (injectionResult.blocked) {
    throw new Error(`Security violation: ${injectionResult.reason}`);
  }

  return sanitized;
}

/**
 * Recursively sanitize all string fields in a request object.
 * Good for generic JSON payloads arriving at a web endpoint.
 *
 * NOTE: This function performs string sanitization only (control-character stripping,
 * whitespace normalization). It does NOT detect prompt injection. For injection
 * detection, call handleTier1PublicInput() on user-controlled prompt fields.
 */
export function ingressProtect(payload) {
  if (payload == null || typeof payload !== 'object') {
    return sanitizeInput(payload);
  }

  if (Array.isArray(payload)) {
    return payload.map(ingressProtect);
  }

  return Object.entries(payload).reduce((cleaned, [key, value]) => {
    cleaned[key] = typeof value === 'string' ? sanitizeInput(value) : ingressProtect(value);
    return cleaned;
  }, {});
}
