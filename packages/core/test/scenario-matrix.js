const path = require("path");
const { scanAll } = require(path.join(__dirname, "..", "out", "detectionPipeline"));
const { decide } = require(path.join(__dirname, "..", "out", "policyEngine"));
const { tokenize } = require(path.join(__dirname, "..", "out", "tokenizer"));

const cases = [
  // --- Original gap that started this ---
  { label: "operator form (baseline, already worked)", text: 'password="hunter2isnotsecure"' },
  { label: "is-form (the one that was missed)", text: 'my password is "hunter2isnotsecure"' },
  { label: "was-form", text: 'the password was "hunter2isnotsecure"' },
  { label: "equals-word form", text: "the password equals hunter2isnotsecure" },
  { label: "'set to' form", text: "set the password to hunter2isnotsecure" },
  { label: "'should be' form", text: "the password should be hunter2isnotsecure" },
  { label: "no connector, just adjacency", text: 'here is my password "hunter2isnotsecure"' },
  { label: "no connector, bare value adjacency", text: "my password hunter2isnotsecure" },
  { label: "value BEFORE keyword", text: 'hunter2isnotsecure is my password' },

  // --- Multi-word keywords, conversational ---
  { label: "api key is-form", text: "the api key is ab12cd34ef56gh78" },
  { label: "access token was-form", text: "the access token was ab12cd34ef56gh78" },
  { label: "client secret is-form", text: "our client secret is ab12cd34ef56gh78" },

  // --- Plural / synonyms ---
  { label: "plural 'credentials'", text: 'the credentials are "hunter2isnotsecure"' },
  { label: "synonym 'passphrase'", text: 'my passphrase is "hunter2isnotsecure"' },
  { label: "synonym 'secret'", text: 'the secret is "hunter2isnotsecure"' },

  // --- Quoting / formatting variants ---
  { label: "backtick value", text: "password is `hunter2isnotsecure`" },
  { label: "single-quoted value", text: "password is 'hunter2isnotsecure'" },
  { label: "uppercase keyword", text: 'PASSWORD is "hunter2isnotsecure"' },
  { label: "mixed case + abbreviation pwd", text: 'my Pwd is "hunter2isnotsecure"' },

  // --- Structural cases that should still work unchanged ---
  { label: "AWS key (structural, unaffected)", text: "AKIAABCDEFGHIJKLMNOP" },
  { label: "connection string (structural, unaffected)", text: "postgres://user:hunter2isnotsecure@db.internal:5432/app" },

  // --- Deliberate false-positive checks (should NOT match) ---
  { label: "FALSE POSITIVE CHECK: policy talk, no value", text: "what's a good password policy for new hires?" },
  { label: "FALSE POSITIVE CHECK: forgot password, no value", text: "I forgot my password again" },
  { label: "FALSE POSITIVE CHECK: password field description", text: "the password field is required and protected" },
  { label: "FALSE POSITIVE CHECK: token as common word", text: "the win was more than a token gesture" },

  // --- Known, honest remaining gaps (should NOT match — no keyword to anchor on) ---
  { label: "GAP (needs layer 3/4): business secret, no keyword", text: "we're spending $80k on Project Falcon for the German expansion" },
  { label: "GAP (needs layer 3/4): paraphrased credential, no keyword or clean value", text: "you know the string I use to log into the db, it's the same one from last time" },
];

async function main() {
  console.log("=".repeat(100));
  for (const c of cases) {
    const { matches, businessMatches } = await scanAll(c.text);
    const decision = decide(matches, businessMatches, { blockOnHighSeverity: true, blockOnBusinessContent: true });
    const { redactedText } = tokenize(c.text, matches);

    console.log(`\n[${c.label}]`);
    console.log(`  input:    ${c.text}`);
    console.log(`  action:   ${decision.action.toUpperCase()}  (${matches.length} match(es))`);
    if (matches.length > 0) {
      for (const m of matches) {
        console.log(`    - ${m.label} [${m.severity}] -> "${m.value}"`);
      }
      console.log(`  redacted: ${redactedText}`);
    }
  }
  console.log("\n" + "=".repeat(100));
}

main();
