#!/usr/bin/env node
/**
 * Assert this extension's settings manifest agrees with @vaultline/core.
 *
 * WHY: a setting's default is declared in two places — package.json, which is
 * what VS Code actually applies, and DEFAULT_SETTINGS in the core, which is
 * what every other host (and every test, and ConsoleHost) uses. When those
 * disagree, the manifest wins silently and the core's value never runs. That
 * is not hypothetical: vaultline.semanticMatchThreshold shipped declared as
 * 0.4 while the calibration that produced 0.5 sat in a comment right next to
 * the constant, so the threshold in force was one the measurements
 * specifically rule out ("passed", "license" and "string" register as
 * credential keywords at 0.4).
 *
 * Nothing here can detect that at runtime — both values are individually
 * plausible — so it's checked at build time instead. Run by `npm run package`
 * before anything is built.
 *
 * Also checks the reverse direction: a setting the core knows about but the
 * manifest never declares is a setting no VS Code user can reach.
 */

const path = require("path");
const { DEFAULT_SETTINGS, RULE_IDS } = require("@vaultline/core");

const manifestPath = path.join(__dirname, "..", "package.json");
const properties = require(manifestPath).contributes?.configuration?.properties ?? {};

/** Which core setting each checkbox-list property must offer the rule IDs for. */
const RULE_LIST_SETTINGS = {
  disabledSecretRules: "secret",
  disabledPiiRules: "pii",
  disabledInfraRules: "infra",
  disabledConversationalSecretRules: "conversationalSecret",
  disabledSemanticRules: "semantic",
};

/**
 * Settings that exist ONLY in this host and deliberately have no counterpart
 * in the core.
 *
 * The reverse-direction check below exists to catch a setting the core reads
 * but no user can reach. These are the opposite case: presentation choices
 * about VS Code's editor surface — decorations, ghost text, which replacement
 * string a command writes — that the core has no concept of and that a
 * JetBrains or CLI host would answer completely differently. Pushing them
 * into DEFAULT_SETTINGS to satisfy this script would put editor concerns in
 * an editor-agnostic package, which is the thing the split exists to prevent.
 *
 * Anything that affects DETECTION belongs in the core, not here.
 */
const HOST_ONLY_SETTINGS = new Set([
  "highlightDetectedPii",
  "inlineWarnings",
  "anonymizeMode",
  "highlightMaxFileLength",
]);

const problems = [];

for (const [key, coreDefault] of Object.entries(DEFAULT_SETTINGS)) {
  const declared = properties[`vaultline.${key}`];

  if (!declared) {
    problems.push(`vaultline.${key} is defined in @vaultline/core but not declared in package.json — no user can change it.`);
    continue;
  }

  if (JSON.stringify(declared.default) !== JSON.stringify(coreDefault)) {
    problems.push(
      `vaultline.${key}: package.json declares ${JSON.stringify(declared.default)} but the core default is ` +
        `${JSON.stringify(coreDefault)}. The manifest value is the one that runs in VS Code — make them match.`
    );
  }

  const ruleGroup = RULE_LIST_SETTINGS[key];
  if (ruleGroup) {
    const declaredIds = declared.items?.enum ?? [];
    const coreIds = RULE_IDS[ruleGroup];
    const missing = coreIds.filter((id) => !declaredIds.includes(id));
    const extra = declaredIds.filter((id) => !coreIds.includes(id));
    if (missing.length > 0) problems.push(`vaultline.${key}: missing rule id(s) ${missing.join(", ")} from its enum.`);
    if (extra.length > 0) problems.push(`vaultline.${key}: enum lists unknown rule id(s) ${extra.join(", ")}.`);
  }
}

for (const key of Object.keys(properties)) {
  const bare = key.replace(/^vaultline\./, "");
  if (!(bare in DEFAULT_SETTINGS) && !HOST_ONLY_SETTINGS.has(bare)) {
    problems.push(
      `${key} is declared in package.json but @vaultline/core has no such setting — it will never be read. ` +
        `If it is a VS Code presentation setting rather than a detection setting, add it to HOST_ONLY_SETTINGS.`
    );
  }
}

if (problems.length > 0) {
  console.error("Settings manifest is out of sync with @vaultline/core:\n");
  for (const problem of problems) console.error(`  - ${problem}`);
  console.error("");
  process.exit(1);
}

console.log(`Settings manifest matches @vaultline/core (${Object.keys(DEFAULT_SETTINGS).length} settings).`);
