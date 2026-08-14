/**
 * Maps a Match (from any detector) to a typed placeholder name, e.g.
 * PERSON, PASSWORD, AMOUNT_INR — instead of one generic SEC bucket.
 *
 * Why this matters (this is the whole point of this file): a placeholder
 * like [SEC-1] carries zero information for the model to reason about, so
 * models are more likely to "fix" it — drop it, rephrase it, replace it
 * with a generic word like "password". A typed, double-angle-bracket
 * token like <<PASSWORD_N>> looks unmistakably like a machine-generated
 * placeholder rather than a word the model might paraphrase, and the type
 * name preserves enough shape (this is a currency amount, this is a
 * person's name) for the model to still reason correctly around it without
 * ever seeing the real value.
 */

import { Match } from "./patternMatcher";

export function entityTypeFor(match: Match): string {
  const id = match.ruleId.toLowerCase();

  if (id.includes("amount-inr")) return "AMOUNT_INR";
  if (id.includes("amount-usd")) return "AMOUNT_USD";
  if (id.includes("amount")) return "AMOUNT";
  if (id.includes("person-name")) return "PERSON";
  // Every shape the username rules produce: the structural
  // "username-assignment", and the proximity matcher's generated
  // "proximity-<phrase>" ids (proximity-login, proximity-userid, ...).
  //
  // This list has to be extended whenever a username keyword is added, and it
  // is easy to forget because nothing fails loudly — the value still gets
  // redacted, just as <<SECRET_1>> instead of <<USERNAME_1>>. Both
  // "service account" and bare "user" shipped that way briefly. The exact
  // match on "proximity-user" is deliberate: `includes("user")` would swallow
  // unrelated future ids, while the generated id for the bare keyword is
  // always exactly this.
  if (
    id.includes("username") ||
    id.includes("user-name") ||
    id.includes("user-id") ||
    id.includes("userid") ||
    id.includes("login") ||
    id.includes("account-name") ||
    id.includes("service-account") ||
    id === "proximity-user"
  ) {
    return "USERNAME";
  }
  if (id.includes("email")) return "EMAIL";
  if (id.includes("phone")) return "PHONE";
  if (id.includes("pan-india")) return "PAN";
  if (id.includes("aadhaar")) return "AADHAAR";
  if (id.includes("ssn")) return "SSN";
  if (id.includes("passport")) return "PASSPORT";
  if (id.includes("drivers-license")) return "DRIVERS_LICENSE";
  if (id.includes("credit-card")) return "CARD_NUMBER";
  if (id.includes("ifsc")) return "IFSC";
  if (id.includes("account-number")) return "ACCOUNT_NUMBER";
  if (id.includes("customer-id")) return "CUSTOMER_ID";

  // Proximity keyword ruleIds are "proximity-<phrase-joined-by-dash>" (see
  // nlpProximityMatcher.ts) — "proximity-pd", "proximity-pass",
  // "proximity-key" etc. don't contain the fuller substrings checked below
  // ("password", "pwd", "api-key"...), so without these explicit checks
  // they fell through to the generic category fallback at the bottom, e.g.
  // a bare "key" match showing up as <<SECRET_N>> instead of <<API_KEY_N>>.
  if (id.includes("password") || id.includes("passwd") || id.includes("pwd") || id === "proximity-pd" || id === "proximity-pass" || id === "proximity-pwrd") return "PASSWORD";
  if (id.includes("passphrase")) return "PASSPHRASE";
  if (id.includes("api-key") || id.includes("apikey") || id === "proximity-key") return "API_KEY";
  if (id.includes("aws")) return "AWS_KEY";
  if (id.includes("github")) return "GITHUB_TOKEN";
  if (id.includes("slack")) return "SLACK_TOKEN";
  if (id.includes("jwt")) return "JWT";
  if (id.includes("private-key")) return "PRIVATE_KEY";
  if (id.includes("connection-string")) return "DB_CONNECTION_STRING";
  if (id.includes("creds") || id.includes("credential")) return "CREDENTIAL";
  if (id.includes("secret")) return "SECRET";
  if (id.includes("token") || id === "proximity-tokn") return "TOKEN";

  if (id.includes("mac-address")) return "MAC_ADDRESS";
  if (id.includes("ipv6")) return "IPV6";
  if (id.includes("ip")) return "IP_ADDRESS";
  // The URL rules redact the AUTHORITY only (host, plus port) and leave the
  // path in clear — see scanUrls in infraDetector.ts — so the value they carry
  // IS a hostname and a URL token would misdescribe it. Sharing the type with
  // internal-hostname-contextual is a bonus: EntityStore keys on
  // `entityType::value`, so the same host found both ways gets one token.
  if (id === "internal-url" || id === "external-url") return "HOSTNAME";
  if (id.includes("hostname")) return "HOSTNAME";
  if (id.includes("port")) return "PORT";
  if (id.includes("url")) return "URL";
  if (id.includes("path")) return "FILE_PATH";

  // Fallback: derive from category so nothing ever falls through untyped.
  return match.category; // "SECRET" | "PII" | "INFRA" | "BUSINESS"
}
