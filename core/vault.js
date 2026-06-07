/**
 * Mock vault that tokenizes sensitive values and detokenizes on demand.
 * This local implementation is intended as a copy/paste starter for Tier 4 PII handling.
 */

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function normalizeKey(value) {
  return String(value || '').trim().toLowerCase();
}

export class MockTokenVault {
  constructor({ tokenPrefix = 'TOKEN', rotateAfter = 1000 } = {}) {
    this.tokenPrefix = tokenPrefix;
    this.rotateAfter = rotateAfter;
    this.tokenStore = new Map();
    this.secretStore = new Map();
    this.counter = 1;
  }

  createToken() {
    return `${this.tokenPrefix}_${String(this.counter).padStart(6, '0')}`;
  }

  /**
   * Replace a raw sensitive value with an opaque token.
   * Example: `alice@example.com` -> `TOKEN_000001`
   */
  tokenize(value) {
    if (value == null) {
      return value;
    }

    this.rotate();

    const normalized = normalizeKey(value);
    if (this.tokenStore.has(normalized)) {
      return this.tokenStore.get(normalized);
    }

    const token = this.createToken();
    this.counter += 1;
    this.tokenStore.set(normalized, token);
    this.secretStore.set(token, value);
    return token;
  }

  /**
   * Restore a token back to its original secret.
   */
  detokenize(token) {
    return this.secretStore.get(token) ?? null;
  }

  /**
   * Replace sensitive fields inside a JSON payload with tokens.
   * This is useful for deterministic Tier 4 tokenization before prompt composition.
   */
  tokenizePayload(payload, fieldMatcher = /(email|phone|ssn|nationalId|name)/i) {
    if (payload == null || typeof payload !== 'object') {
      return payload;
    }

    if (Array.isArray(payload)) {
      return payload.map((item) => this.tokenizePayload(item, fieldMatcher));
    }

    return Object.entries(payload).reduce((result, [key, value]) => {
      if (fieldMatcher.test(key) && typeof value === 'string') {
        result[key] = this.tokenize(value);
      } else if (typeof value === 'object' && value !== null) {
        result[key] = this.tokenizePayload(value, fieldMatcher);
      } else {
        result[key] = value;
      }
      return result;
    }, {});
  }

  /**
   * Replace any token references in a response string with their original values.
   * Useful for authorized post-processing after output filtering.
   */
  hydrateTokens(text) {
    if (typeof text !== 'string') {
      return text;
    }

    const tokenKeys = Array.from(this.secretStore.keys());
    if (!tokenKeys.length) {
      return text;
    }

    const pattern = new RegExp(tokenKeys.map(escapeRegExp).join('|'), 'g');
    return text.replace(pattern, (token) => this.secretStore.get(token) || token);
  }

  /**
   * Clears all token mappings once the vault reaches rotateAfter entries.
   * Called automatically before each tokenize() call.
   * WARNING: clearing invalidates all existing tokens — any previously issued
   * tokens in LLM responses can no longer be hydrated or redacted. In production,
   * use a persistent vault with proper key versioning instead.
   */
  rotate() {
    if (this.tokenStore.size >= this.rotateAfter) {
      this.tokenStore.clear();
      this.secretStore.clear();
      this.counter = 1;
    }
  }

  /**
   * Redact token references in a text blob.
   */
  redactTokens(payload, placeholder = '[REDACTED]') {
    if (payload == null) {
      return payload;
    }

    const escapedPrefix = escapeRegExp(this.tokenPrefix);
    const tokenPattern = new RegExp(`\\b${escapedPrefix}_[0-9]{6}\\b`, 'g');
    return String(payload).replace(tokenPattern, placeholder);
  }
}
