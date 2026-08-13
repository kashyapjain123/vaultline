/**
 * Cross-turn credential expectation — the state that makes a conversation a
 * conversation rather than a series of unrelated strings.
 *
 * THE LEAK THIS EXISTS TO CLOSE. Every detector in this package is stateless
 * per message, and nlpProximityMatcher.ts in particular needs its anchor
 * keyword and the value in the SAME string, within a 6-token window. Real
 * developers don't type that way:
 *
 *     turn 1: "...and password is"                    <- keyword, no value
 *     turn 2: "can you replace it with hunter1x2y3z"  <- value, no keyword
 *
 * Turn 2 has nothing for the proximity matcher to anchor on, so the password
 * went to the model in plaintext. The value heuristic was never the problem —
 * looksLikeSecretValue("hunter1x2y3z") was already true. The only missing
 * ingredient was the keyword, and it was one turn back.
 *
 * WHY THIS ISN'T THE ENTITY STORE'S JOB: EntityStore persists value -> token
 * mappings, i.e. things already identified as secret. This persists the
 * EXPECTATION that a secret is inbound, which is a different thing with a
 * different lifetime — a mapping lives for the whole session, an expectation
 * has to expire or it turns every later value-shaped string into a false
 * positive.
 *
 * WHAT ARMS IT: any credential keyword occurrence, whether or not a value was
 * found alongside it. "the password is Passw0rd1" arms it just as "and
 * password is" does, so a subsequent "actually use Xy9zAb12" is still caught.
 *
 * DECAY, and why it is turn-based rather than time-based: the unit that
 * matters is conversational distance, not wall-clock. A developer who steps
 * away for lunch mid-credential-exchange and comes back to paste the value is
 * still in the same exchange; two unrelated questions later, they are not.
 */

export interface CredentialExpectation {
  /**
   * The arming keyword's rule ID, reused verbatim (e.g. "proximity-password").
   *
   * Load-bearing, not cosmetic: entityTypes.ts maps ruleId -> placeholder type,
   * so reusing it means a carried-over hit is typed <<PASSWORD_n>> exactly like
   * an in-message one, and the user's existing
   * `disabledConversationalSecretRules` opt-outs already cover it. Minting a
   * new rule ID here would have silently bypassed both.
   */
  ruleId: string;
  /** The arming keyword's label, e.g. "Password (conversational)". */
  label: string;
  /** Messages this expectation still applies to. Decremented once per scanned message. */
  turnsRemaining: number;
}

/**
 * One per GuardSession — same lifetime as its EntityStore, which is what makes
 * "the previous turn" a meaningful concept at all.
 */
export class ConversationContext {
  private expectation: CredentialExpectation | null = null;

  /**
   * Arm (or re-arm) the expectation for the next `turns` messages.
   *
   * Re-arming always resets the counter to full: a conversation that keeps
   * mentioning credentials should stay armed throughout, not time out mid-way
   * because the first mention is aging out.
   */
  arm(ruleId: string, label: string, turns: number): void {
    if (turns <= 0) {
      this.expectation = null;
      return;
    }
    this.expectation = { ruleId, label, turnsRemaining: turns };
  }

  /** The live expectation, or null. Does not mutate — decay is explicit, via decayTurn(). */
  peek(): CredentialExpectation | null {
    return this.expectation;
  }

  /** Consume one message's worth of lifetime; clears the expectation when it runs out. */
  decayTurn(): void {
    if (!this.expectation) return;
    this.expectation.turnsRemaining -= 1;
    if (this.expectation.turnsRemaining <= 0) this.expectation = null;
  }

  clear(): void {
    this.expectation = null;
  }
}
