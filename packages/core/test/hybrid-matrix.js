const path = require("path");
const { scanAll } = require(path.join(__dirname, "..", "out", "detectionPipeline"));
const { decide } = require(path.join(__dirname, "..", "out", "policyEngine"));
const { tokenize } = require(path.join(__dirname, "..", "out", "tokenizer"));

const cases = [
  // --- The example from the strategy discussion ---
  { label: "PII: name + org + account number", text: "Rahul Sharma from HDFC Bank has account number 1234567890" },

  // --- Structural PII ---
  { label: "PAN (India)", text: "his PAN is ABCDE1234F for the KYC form" },
  { label: "IFSC (India)", text: "use IFSC HDFC0001234 for the transfer" },
  { label: "SSN (US)", text: "SSN on file is 123-45-6789" },
  { label: "Aadhaar, grouped", text: "Aadhaar number 1234 5678 9012 was verified" },
  { label: "Aadhaar, bare digits + keyword", text: "aadhaar 123456789012 needs updating" },
  { label: "Aadhaar, bare digits NO keyword (should NOT match)", text: "the invoice total was 123456789012 paise" },
  { label: "email address", text: "reach out to rahul.sharma@hdfcbank.com about this" },
  { label: "credit card, valid Luhn", text: "card number 4532015112830366 was charged" },
  { label: "credit card, INVALID Luhn (should NOT match)", text: "random number 4532015112830367 came up" },

  // --- Contextual PII numbers ---
  { label: "phone, contextual", text: "my phone number is 9876543210, call me tomorrow" },
  { label: "account number, contextual", text: "account number 55512345 needs to be closed" },
  { label: "customer id, contextual", text: "customer id 88213 was flagged for review" },
  { label: "bare number, NO keyword (should NOT match as PII)", text: "the total came to 88213 dollars" },

  // --- Infra: IP / URL / path ---
  { label: "internal URL", text: "hit http://internal-api.company.com/v1/users for the data" },
  { label: "public URL (should be low severity, not blocked)", text: "check https://google.com for docs" },
  { label: "URL with embedded private IP", text: "the db lives at http://10.0.4.12:5432/mydb" },
  { label: "standalone private IP", text: "internal IP is 192.168.1.50 for the router" },
  { label: "standalone public IP", text: "public IP 8.8.8.8 is google dns" },
  { label: "unix file path", text: "config file is at /etc/passwd on the box" },
  { label: "windows file path", text: "logs are in C:\\Users\\jdoe\\AppData\\Local\\Temp\\app.log" },

  // --- Infra: contextual hostname / port ---
  { label: "hostname, contextual", text: "the server prod-db-01 needs a restart" },
  { label: "hostname shape, NO context (should NOT match)", text: "step-by-step-3 guide was helpful" },
  { label: "port, contextual", text: "the server runs on port 8080 for the internal API" },
  { label: "port-looking number, NO keyword — sports score (should NOT match)", text: "he scored 8080 runs across his career" },
  { label: "port, contextual, different phrasing", text: "the port is 443 for https traffic" },

  // --- Conversational secrets (regression check — must still work) ---
  { label: "password, is-form (regression)", text: 'my password is "hunter2isnotsecure"' },
  { label: "AWS key (structural, regression)", text: "AKIAABCDEFGHIJKLMNOP" },

  // --- Cross-layer: multiple categories in one message ---
  {
    label: "multi-category: PII + SECRET + INFRA in one message",
    text: 'customer id 4521, my password is "hunter2isnotsecure", and the server is prod-db-02',
  },

  // --- Known, honest remaining gaps ---
  { label: "GAP: business secret, no keyword, no NER", text: "we're spending $80k on Project Falcon for the German expansion" },
];

async function main() {
  console.log("=".repeat(110));
  for (const c of cases) {
    const { matches, businessMatches } = await scanAll(c.text);
    const decision = decide(matches, businessMatches, { blockOnHighSeverity: true, blockOnBusinessContent: true });
    const { redactedText } = tokenize(c.text, matches);

    console.log(`\n[${c.label}]`);
    console.log(`  input:    ${c.text}`);
    console.log(`  action:   ${decision.action.toUpperCase()}  (${matches.length} match(es))`);
    for (const m of matches) {
      console.log(`    - [${m.category}] ${m.label} [${m.severity}] -> "${m.value}"`);
    }
    if (matches.length > 0) console.log(`  redacted: ${redactedText}`);
  }
  console.log("\n" + "=".repeat(110));
}

main();
