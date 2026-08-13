/**
 * Multi-turn matrix — the leak this suite exists for:
 *
 *   turn 1: "...and password is"                    <- keyword, no value
 *   turn 2: "can you replace it with hunter1x2y3z"  <- value, no keyword
 *
 * Turn 2 has nothing for nlpProximityMatcher to anchor on, so before
 * conversationContext.ts existed the password went to the model in plaintext.
 *
 * Unlike scenario-matrix.js (descriptive — prints what each single message
 * produces), this file ASSERTS and exits non-zero on failure. A cross-turn
 * leak is a silent regression: nothing throws, the product just quietly stops
 * protecting people. It needs a test that fails loudly.
 *
 * Each case drives a REAL GuardSession turn by turn, because the behaviour
 * under test is the interaction between messages — scanning them individually
 * would pass while the actual product leaked.
 *
 * No embedding router (router: null), so routing fails open and every
 * contextual detector runs. That keeps this hermetic and fast; routing itself
 * is covered by routingMatrix.js.
 */

const os = require("os");
const path = require("path");
const { AuditLog } = require(path.join(__dirname, "..", "out", "auditLog"));
const { GuardSession } = require(path.join(__dirname, "..", "out", "guardSession"));

function makeSession(overrides = {}) {
  const context = {
    auditLog: new AuditLog(path.join(os.tmpdir(), "vaultline-multiturn-test")),
    scanOptions: () => ({ router: null, semanticMatcher: null, ...overrides }),
    policyConfig: () => ({ blockOnHighSeverity: false, blockOnBusinessContent: false }),
    auditIncludesValues: () => false,
  };
  return new GuardSession(context);
}

/**
 * `turns` is a list of [message, expectation] pairs, where expectation is
 * either a string that must appear in the redacted output (i.e. the value was
 * NOT redacted) or { redacted: "value" } asserting it WAS.
 */
const cases = [
  {
    label: "THE REPORTED BUG: password promised in turn 1, supplied in turn 2",
    turns: [
      { text: "URL - https://svc-01.corp.example.internal/api/getToken\nusername is svc_corp_uat\nand password is" },
      { text: "can you replace it with hunter1isnotsecure", redacts: "hunter1isnotsecure", type: "PASSWORD" },
    ],
  },
  {
    label: "satisfied keyword still arms: 'password is X' then 'actually use Y'",
    turns: [
      { text: "the password is Passw0rd123", redacts: "Passw0rd123" },
      { text: "actually use Xy9zAb12Cd instead", redacts: "Xy9zAb12Cd" },
    ],
  },
  {
    label: "other leaking phrasings from the original report",
    turns: [
      { text: "what should the api key be?" },
      { text: "use ab12cd34ef56gh78 instead", redacts: "ab12cd34ef56gh78" },
    ],
  },
  {
    label: "bare 'it is X' follow-up",
    turns: [{ text: "and the secret is" }, { text: "it is Passw0rd123", redacts: "Passw0rd123" }],
  },
  {
    label: "carry-over reaches the SECOND following turn (default is 2)",
    turns: [
      { text: "and password is" },
      { text: "sorry, one moment" },
      { text: "here it is: hunter1isnotsecure", redacts: "hunter1isnotsecure" },
    ],
  },
  {
    label: "DECAY: expectation is gone by the third following turn",
    turns: [
      { text: "and password is" },
      { text: "sorry, one moment" },
      { text: "actually let's do something else" },
      { text: "deploy commit a1b2c3d4e5f6", leaks: "a1b2c3d4e5f6" },
    ],
  },
  {
    label: "NO false arming: a conversation that never mentions credentials",
    turns: [
      { text: "how do I parse a CSV in python?" },
      { text: "deploy commit a1b2c3d4e5f6", leaks: "a1b2c3d4e5f6" },
    ],
  },
  {
    label: "in-message detection unchanged (no carry-over involved)",
    turns: [{ text: 'my password is "hunter2isnotsecure"', redacts: "hunter2isnotsecure" }],
  },
  {
    // Both detectors claim the same span here. Overlap resolution in
    // mergeAndFinalize() must keep the in-message one, so the banner says
    // "Password (conversational)" rather than the carried-over label — the
    // keyword IS visible in this message, and claiming otherwise would be
    // confusing.
    label: "armed AND keyword present: the in-message match wins the span",
    turns: [
      { text: "the password is Passw0rd123", redacts: "Passw0rd123" },
      { text: "the password is Xy9zAb12Cd", redacts: "Xy9zAb12Cd", label: "Password (conversational)" },
    ],
  },
  {
    label: "issued placeholders are not re-redacted into fresh tokens",
    turns: [
      { text: "and password is" },
      { text: "keep using <<PASSWORD_1>> for now", leaks: "PASSWORD_1" },
    ],
  },
  {
    label: "OFF SWITCH: enableCrossTurnSecretCarryover=false restores old behaviour",
    overrides: { enableCrossTurnSecretCarryover: false },
    turns: [
      { text: "and password is" },
      { text: "can you replace it with hunter1isnotsecure", leaks: "hunter1isnotsecure" },
    ],
  },
  {
    label: "crossTurnSecretTurns=1 stops one turn earlier",
    overrides: { crossTurnSecretTurns: 1 },
    turns: [
      { text: "and password is" },
      { text: "sorry, one moment" },
      { text: "here it is: hunter1isnotsecure", leaks: "hunter1isnotsecure" },
    ],
  },
];

async function main() {
  let failures = 0;
  let checks = 0;

  for (const c of cases) {
    const overrides = {};
    if (c.overrides) {
      if ("enableCrossTurnSecretCarryover" in c.overrides) {
        overrides.enableCrossTurnSecrets = c.overrides.enableCrossTurnSecretCarryover;
      }
      if ("crossTurnSecretTurns" in c.overrides) {
        overrides.crossTurnSecretTurns = c.overrides.crossTurnSecretTurns;
      }
    }
    const session = makeSession(overrides);
    console.log(`\n[${c.label}]`);

    for (const turn of c.turns) {
      const result = await session.guardPrompt(turn.text);
      console.log(`  > ${turn.text.replace(/\n/g, " / ")}`);
      console.log(`    -> ${result.redactedText.replace(/\n/g, " / ")}`);

      if (turn.redacts) {
        checks++;
        const gone = !result.redactedText.includes(turn.redacts);
        const typeOk = !turn.type || result.mappings.some((m) => m.token.includes(turn.type));
        const labelOk = !turn.label || result.mappings.some((m) => m.label === turn.label);
        if (gone && typeOk && labelOk) {
          console.log(`    PASS: "${turn.redacts}" redacted${turn.type ? ` as ${turn.type}` : ""}`);
          if (turn.label) console.log(`          labelled "${turn.label}"`);
        } else {
          failures++;
          const why = !gone
            ? "it is still present in the outgoing text"
            : !typeOk
              ? `redacted, but not typed ${turn.type}`
              : `redacted, but labelled "${result.mappings.map((m) => m.label).join(", ")}" not "${turn.label}"`;
          console.log(`    FAIL: expected "${turn.redacts}" to be redacted — ${why}`);
        }
      }

      if (turn.leaks) {
        checks++;
        if (result.redactedText.includes(turn.leaks)) {
          console.log(`    PASS: "${turn.leaks}" correctly left alone`);
        } else {
          failures++;
          console.log(`    FAIL: "${turn.leaks}" was redacted, but should NOT have been (false positive)`);
        }
      }
    }
  }

  console.log("\n" + "=".repeat(80));
  console.log(failures === 0 ? `ALL ${checks} CHECKS PASSED` : `${failures} of ${checks} CHECKS FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
