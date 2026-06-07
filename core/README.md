# Core Security Middleware Components

This folder contains starter code for a three-layer LLM perimeter:
- `ingress/` — Tier 1 public sanitization and prompt injection blocking
- `vault/` — Tier 4 PII tokenization and deterministic ghost tokens
- `egress/` — outbound filtering and leakage detection

## The six-tier data classification framework

The framework below classifies enterprise input data into six tiers, from fully sendable to strictly blocked, plus mandatory output controls.

### Tier 1 — Public (safe to send)
- Required control: basic sanitization only
- Use case: product catalogs, public documentation, FAQs, non-sensitive user queries
- Implementation:
  ```js
  if (isPromptInjection(input)) block();
  cleanInput = sanitize(input); // trim, normalize, strip control chars
  sendToLLM(cleanInput);
  ```
  Example: `List all products in the software category` → sanitize whitespace and control characters → send.

### Tier 2 — Internal (handle with care)
- Required control: data minimization + RBAC enforcement
- Use case: employee assignments, internal IDs, project codes, org-level configs
- Implementation:
  ```js
  if (!hasAccess(user, 'internal')) deny();
  input = removeFields(input, ['employeeId', 'fullName', 'costCenter']);
  sendToLLM(input);
  ```
  Example: `Employee (ID: EMP-4821) is assigned to Project Alpha` → verify access → strip identifier → send `A team member is assigned to Project Alpha.`

### Tier 3 — Confidential (restricted)
- Required control: encryption at rest + RBAC + aggregation
- Use case: financial forecasts, strategic metrics, business-sensitive documents
- Implementation:
  ```js
  if (!hasRole(user, 'finance-analyst')) deny();
  input = aggregate(input); // '~$5M range' not '$4,982,341.00'
  sendToLLM(input);
  ```
  Example: `Q1 revenue is $4,982,341` → aggregate → send `Revenue increased by approximately 12% in Q1.`

### Tier 4 — PII (tokenize)
- Required control: tokenization + audit logging
- Use case: names, emails, phone numbers, national IDs
- Implementation:
  ```js
  tokens = tokenizePII(input); // 'Alice Brown' -> 'USER_4F2A'
  logAccess(user, resource, 'PII');
  sendToLLM(tokens.sanitizedText);
  ```
  Example: `Alice Brown can be reached at alice@company.com` → `USER_4F2A can be reached at EMAIL_001.`

### Tier 5 — PCI / regulated IDs (blocked)
- Required control: DLP detection + application-layer blocking
- Use case: credit card numbers, account IDs, tax identifiers
- Implementation:
  ```js
  if (dlpScan(input).containsRegulatedData()) {
    auditLog(user, 'BLOCKED: Tier 5 detected');
    throw new Error('Request blocked: regulated data');
  }
  ```
  Note: redaction is a trap here. Block the entire request, do not pass partial sanitized data.

### Tier 6 — Highly regulated (hard reject)
- Required control: hard block + security alert + zero payload logging
- Use case: biometrics, health records, passport/visa details, genetic data
- Implementation:
  ```js
  if (detectHighlyRegulated(input)) {
    triggerAlert(securityTeam, {
      user: user.id,
      timestamp: new Date(),
      reason: 'Tier 6 data detected'
    });
    return reject('Request cannot be processed');
  }
  ```
  Example: health or biometric data must be blocked entirely, not redacted.

### Output tiers
- Output filtering and PII redaction must run on every response.
- If the model synthesizes sensitive insights, the outbound layer must catch and redact or block them before UI delivery.

---

## Implementation checklist for engineering teams
Use this checklist as part of your AI feature design review. Every LLM integration should satisfy these before shipping.

- Data classification has been assigned to every field that could reach a prompt
- Prompt injection detection runs before all LLM calls, across all tiers
- RBAC is enforced at the application layer, not only in the UI
- A regex + NER pipeline is implemented for PII detection (Tier 4)
- The token vault is encrypted and access-controlled (Tier 4)
- DLP scanning is integrated and runs before the LLM pipeline is invoked (Tier 5+)
- Tier 5 and 6 data triggers hard blocks with automated alerting, not soft warnings
- Output filtering and PII redaction run on every LLM response without exception
- Every LLM exchange is audit-logged (excluding Tier 6 payload content)
- Private or on-premises LLM deployment has been evaluated for Tier 3+ workloads
 - Transport encryption (TLS) is enforced for all networked LLM calls and data-in-transit

---

## What is included

- `ingress.js`
  - `sanitizeInput(rawText)`
  - `checkPromptInjection(text)`
  - `handleTier1PublicInput(rawInput)`
  - `ingressProtect(payload)`

- `vault.js`
  - `MockTokenVault`
  - `tokenize(value)`
  - `tokenizePayload(payload, fieldMatcher)`
  - `hydrateTokens(text)`
  - `redactTokens(payload, placeholder)`

- `egress.js`
  - `detectLeakage(text)`
  - `filterOutbound(responseText, options)`
  - `assertSafeEgress(responseText)`

---

## How to use these layers

### 1. Tier 1 public input (ingress.js)
Use this for public or lightly sensitive prompts before the request enters your model pipeline.

```js
import { handleTier1PublicInput } from './ingress.js';

const rawPrompt = req.body.userPrompt;
const safePrompt = handleTier1PublicInput(rawPrompt);
// safePrompt is now normalized, whitespace-cleaned, and blocked if injection is detected
```

### 2. Tier 4 PII tokenization (vault.js)
Use this before you build the final prompt, swapping raw PII for opaque identifiers.

```js
import { MockTokenVault } from './vault.js';

const vault = new MockTokenVault({ tokenPrefix: 'USER' });
const userPayload = {
  name: 'Alice Brown',
  email: 'alice@example.com',
  phone: '+1-555-1212',
};

const tokenizedPayload = vault.tokenizePayload(userPayload);
// { name: 'USER_000001', email: 'USER_000002', phone: 'USER_000003' }

const prompt = `Please analyze support request for ${tokenizedPayload.email}`;
```

If the LLM response needs to present a user-specific value back to an authorized caller, hydrate the token safely after filtering:

```js
const response = 'Contact USER_000002 for details.';
const finalText = vault.hydrateTokens(response);
```

### 3. Output filtering and safety checks (egress.js)
Always scan the raw model output before it reaches the client.

```js
import { filterOutbound, assertSafeEgress } from './egress.js';

const rawLLMOutput = await callLLM(safePrompt);
const filtered = filterOutbound(rawLLMOutput);
const egressCheck = assertSafeEgress(filtered);
if (!egressCheck.safe) {
  throw new Error(`Blocked output: ${egressCheck.message}`);
}
return { text: filtered };
```

---

## Example middleware flow

```js
import { ingressProtect, handleTier1PublicInput } from './ingress.js';
import { MockTokenVault } from './vault.js';
import { filterOutbound, assertSafeEgress } from './egress.js';

const vault = new MockTokenVault({ tokenPrefix: 'TOKEN' });

export async function processRequest(req, res) {
  // 1. Ingress: normalize the incoming request body
  const requestBody = ingressProtect(req.body);

  // 2. Tier 1 prompt hygiene
  const safePrompt = handleTier1PublicInput(requestBody.userPrompt);

  // 3. Tier 4 tokenization for any PII fields
  const tokenizedContext = vault.tokenizePayload(requestBody);

  // 4. Call the LLM with a privacy-safe prompt/context
  const rawModelOutput = await callLLM({ prompt: safePrompt, context: tokenizedContext });

  // 5. Egress: redact leaked secrets and verify safety
  const filteredOutput = filterOutbound(rawModelOutput);
  const egressResult = assertSafeEgress(filteredOutput);
  if (!egressResult.safe) {
    throw new Error(egressResult.message);
  }

  // 6. Optionally restore token values for an authorized client
  const finalResponse = vault.hydrateTokens(filteredOutput);
  res.json({ text: finalResponse });
}
```

---

## Notes

- This implementation is intentionally lightweight and illustrative.
- For Tier 2 / Tier 3 controls, enforce RBAC and data minimization before the model request is constructed.
- For Tier 5 / Tier 6 payloads, do not try to sanitize: hard stop and alert.
- Never log raw Tier 6 content.
