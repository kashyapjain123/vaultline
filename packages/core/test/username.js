/**
 * Username and service-account detection.
 *
 * Closes the oldest open item in the project. From the very first bug report:
 *
 *     username is svc_corp_uat        <- went through in clear
 *     and password is                 <- the password half was fixed in 1.2.5
 *
 * Two independent reasons it survived that long: `username` was in no keyword
 * list, and `looksLikeSecretValue("svc_corp_uat")` is false — no digit, no
 * symbol — so adding the keyword alone would not have helped.
 *
 * THE RISK IS FALSE POSITIVES, and it is a big one. A username is an ordinary
 * identifier, so `looksLikeUsername` has to accept bare words — which makes
 * `username: string` look identical to `username: svc_corp_uat`. Building this
 * produced exactly that class of error twice before it settled: `def login(self,
 * email, password)` had **def** redacted (the proximity matcher searching
 * backwards) and then **email** (a parameter name passing the value test).
 * Hence the emphasis below on the negative cases.
 */

const path = require("path");
const { scanCurrentMessage } = require(path.join(__dirname, "..", "out", "detectionPipeline"));
const { tokenize, restore } = require(path.join(__dirname, "..", "out", "tokenizer"));
const { EntityStore } = require(path.join(__dirname, "..", "out", "entityStore"));
const { ConversationContext } = require(path.join(__dirname, "..", "out", "conversationContext"));
const { looksLikeUsername } = require(path.join(__dirname, "..", "out", "proximityUtils"));

const OPTS = { router: null, semanticMatcher: null };

let failures = 0;
function check(label, condition, detail = "") {
  if (condition) {
    console.log(`  PASS  ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label}${detail ? ` — ${detail}` : ""}`);
  }
}

async function redact(text, store) {
  const { matches } = await scanCurrentMessage(text, OPTS);
  return tokenize(text, matches, store);
}

async function expectDetected(label, text, secret) {
  const { redactedText, mappings } = await redact(text);
  const gone = !redactedText.includes(secret);
  const typed = mappings.some((m) => m.token.includes("USERNAME"));
  check(label, gone && typed, `got ${JSON.stringify(redactedText)}`);
}

async function expectUntouched(label, text) {
  const { redactedText } = await redact(text);
  check(label, redactedText === text, `got ${JSON.stringify(redactedText)}`);
}

async function main() {
  console.log("\n[THE ORIGINAL REPORT]");
  {
    // A real conversation context, so the cross-turn carry-over that GuardSession
    // normally supplies is actually exercised here.
    const conversation = new ConversationContext();
    const turn = async (text, store) => {
      const { matches } = await scanCurrentMessage(text, { ...OPTS, conversationContext: conversation });
      return tokenize(text, matches, store);
    };
    const store = new EntityStore();
    const first = await turn("username is svc_corp_uat", store);
    check("username redacted", !first.redactedText.includes("svc_corp_uat"), first.redactedText);
    check("typed as USERNAME", /<<USERNAME_\d+>>/.test(first.redactedText), first.redactedText);

    // The other half, still working — the two together are a full credential.
    await turn("and password is", store);
    const second = await turn("can you replace it with hunter1isnotsecure", store);
    check("password still caught across turns", !second.redactedText.includes("hunter1isnotsecure"), second.redactedText);
  }

  console.log("\n[the forms these actually appear in]");
  await expectDetected("env var", "USERNAME=svc_corp_uat", "svc_corp_uat");
  await expectDetected("json field", '"username": "svc_corp_uat"', "svc_corp_uat");
  await expectDetected("compound name", "SERVICE_USERNAME = deploy_bot", "deploy_bot");
  await expectDetected("login assignment", "login: kashyap.jain", "kashyap.jain");
  await expectDetected("user_id", "user_id = svc-prod-01", "svc-prod-01");
  await expectDetected("prose", "the username is deploy_bot", "deploy_bot");

  console.log("\n[FALSE POSITIVES — the whole risk of this feature]");
  await expectUntouched("type annotation", "username: string");
  await expectUntouched("Optional annotation", "def login(self, username: Optional[str])");
  await expectUntouched("python signature", "def f(self, username: str)");
  await expectUntouched("property access", "username = user.name");
  await expectUntouched("nested property", "username = obj.username");
  await expectUntouched("express handler", "const username = req.body.username;");
  await expectUntouched("parameter list", "def login(self, email, password)");
  await expectUntouched("method call", "self.login(username, password)");

  console.log("\n[a whole ordinary file stays clean]");
  {
    const src = [
      "import os",
      "from typing import Optional",
      "",
      "class Auth:",
      "    def login(self, username: Optional[str], password: Optional[str]) -> bool:",
      "        if not username or not password:",
      "            return False",
      "        user = self.repo.find(username)",
      "        return user is not None",
    ].join("\n");
    await expectUntouched("ordinary python", src);
  }

  console.log("\n[looksLikeUsername directly]");
  for (const v of ["svc_corp_uat", "kashyap.jain", "svc-prod-01", "deploy_bot"]) {
    check(`accepts ${v}`, looksLikeUsername(v));
  }
  for (const v of ["string", "Optional", "None", "self", "boolean", "uuid", "user", "x", "user.name", "obj.username", "not", "admin", "email", "svc_corp_uat.", "kashyap.jain-"]) {
    check(`rejects ${v}`, !looksLikeUsername(v));
  }

  console.log("\n[trailing punctuation belongs to the sentence, not the value]");
  {
    // Reported against 1.3.1. Checking secrets alongside it found something
    // worse: the tokenizer keeps '.' inside a token (it must, for
    // `kashyap.jain`), so `my password is hunter2isnotsecure.` matched NOTHING —
    // looksLikeSecretValue rejects a dot — and the password went through in
    // clear. An end-of-sentence secret was a silent leak, not a cosmetic bug.
    const cases = [
      ["username is svc_corp_uat.", "svc_corp_uat"],
      ["login: kashyap.jain.", "kashyap.jain"],
      ["the username is deploy_bot!", "deploy_bot"],
      ["user_id = svc-prod-01;", "svc-prod-01"],
      ["username is svc_corp_uat, and more", "svc_corp_uat"],
    ];
    for (const [text, want] of cases) {
      const store = new EntityStore();
      const { redactedText } = await redact(text, store);
      const stored = (store.allMappings()[0] ?? {}).originalValue;
      check(`${text} -> ${want}`, stored === want, `stored ${JSON.stringify(stored)}`);
      check(`punctuation survives: ${text}`, restore(redactedText, store.allMappings()) === text, redactedText);
    }
  }

  console.log("\n[the leak found alongside it: secrets ending a sentence]");
  {
    const cases = [
      ["my password is hunter2isnotsecure.", "hunter2isnotsecure"],
      ["the api key is ab12cd34ef56gh78.", "ab12cd34ef56gh78"],
      ["the secret is Hunter@123!", "Hunter@123"],
    ];
    for (const [text, want] of cases) {
      const store = new EntityStore();
      const { redactedText } = await redact(text, store);
      check(`${want} is redacted at end of sentence`, !redactedText.includes(want), redactedText);
      const stored = (store.allMappings()[0] ?? {}).originalValue;
      check(`…and stored without the punctuation`, stored === want, `stored ${JSON.stringify(stored)}`);
    }
  }

  console.log("\n[round trip]");
  {
    const store = new EntityStore();
    const { redactedText } = await redact("username is svc_corp_uat", store);
    const token = /<<USERNAME_\d+>>/.exec(redactedText)[0];
    const restored = restore(`connect(user="${token}")`, store.allMappings());
    check("restores the real account name", restored.includes("svc_corp_uat"), restored);
  }

  console.log("\n" + "=".repeat(80));
  console.log(failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
