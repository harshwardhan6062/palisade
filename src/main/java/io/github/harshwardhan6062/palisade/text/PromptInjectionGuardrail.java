package io.github.harshwardhan6062.palisade.text;

import java.util.List;

import io.github.harshwardhan6062.palisade.Context;
import io.github.harshwardhan6062.palisade.Decision;
import io.github.harshwardhan6062.palisade.Finding;
import io.github.harshwardhan6062.palisade.Finding.Severity;
import io.github.harshwardhan6062.palisade.Guardrail;
import io.github.harshwardhan6062.palisade.TextSubject;

/**
 * Detects known-shape prompt-injection attempts.
 *
 * <p>Three families, and it's worth knowing which is which because they fail
 * differently:
 *
 * <ul>
 *   <li><b>Instruction override</b> — "ignore previous instructions". Cheap to
 *       detect, cheap to paraphrase around. High precision, low recall.
 *   <li><b>Role hijack</b> — forging a {@code system:} turn or an
 *       {@code &lt;instructions&gt;} tag inside user content, exploiting the fact
 *       that the model sees one flat token stream and cannot verify who wrote
 *       which part. The structural fix is to never interpolate untrusted text
 *       where a role marker would be meaningful; this rail is the net under it.
 *   <li><b>Obfuscation</b> — bidirectional-override characters that make text
 *       render differently than it tokenises, or a large base64 payload carrying
 *       an instruction past a scanner that only reads plain text.
 * </ul>
 *
 * <p><b>This will not catch a competent novel attack.</b> Paraphrase defeats
 * regex, and that is not a fixable property of this approach. It is here because
 * it is fast, deterministic, and explainable, and because most real traffic is
 * not novel. Layer a model-based classifier above it and treat least-privilege
 * tool permissions as the control that actually contains a successful injection.
 */
public final class PromptInjectionGuardrail implements Guardrail<TextSubject> {

    private static final List<PatternRule> RULES = List.of(
            // --- instruction override -------------------------------------
            PatternRule.of("injection.override_instructions",
                    "(?i)\\b(?:ignore|disregard|forget)\\s+(?:all\\s+|any\\s+)?"
                            + "(?:the\\s+)?(?:previous|prior|above|preceding|earlier|foregoing)\\s+"
                            + "(?:instructions?|prompts?|rules?|directions?|context|messages?)",
                    Severity.CRITICAL, "attempt to discard prior instructions"),
            PatternRule.of("injection.forget_everything",
                    "(?i)\\bforget\\s+(?:everything|all)\\b",
                    Severity.HIGH, "attempt to clear prior context"),
            PatternRule.of("injection.reassign_role",
                    "(?i)\\byou\\s+are\\s+now\\s+(?:a|an|the)\\b",
                    Severity.HIGH, "attempt to reassign the model's role"),
            PatternRule.of("injection.new_instructions",
                    "(?i)\\bnew\\s+(?:instructions?|system\\s+prompt|rules?)\\s*[:\\-]",
                    Severity.HIGH, "attempt to supply replacement instructions"),

            // --- role hijack ----------------------------------------------
            PatternRule.of("injection.role_marker",
                    "(?im)^\\s*(?:system|assistant|developer)\\s*:",
                    Severity.HIGH, "forged conversation role marker"),
            PatternRule.of("injection.role_tag",
                    "(?i)</?\\s*(?:system|instructions?|prompt|im_start|im_end)\\s*>",
                    Severity.HIGH, "forged structural tag"),
            PatternRule.of("injection.markdown_role_header",
                    "(?im)^\\s*#{2,}\\s*(?:system|instruction|prompt)\\b",
                    Severity.MEDIUM, "heading masquerading as a system section"),

            // --- prompt exfiltration --------------------------------------
            PatternRule.of("injection.exfiltrate_prompt",
                    "(?i)\\b(?:reveal|show|print|output|repeat|echo|display|dump)\\s+"
                            + "(?:me\\s+)?(?:your|the)\\s+"
                            + "(?:system\\s+prompt|initial\\s+instructions|original\\s+instructions|"
                            + "instructions|prompt|rules)\\b",
                    Severity.HIGH, "attempt to extract the system prompt"),

            // --- jailbreak framing ----------------------------------------
            PatternRule.of("injection.jailbreak",
                    "(?i)\\b(?:jailbreak|developer\\s+mode|do\\s+anything\\s+now|DAN\\s+mode|"
                            + "bypass\\s+(?:your|the)\\s+(?:restrictions?|guardrails?|safety|filters?))\\b",
                    Severity.HIGH, "known jailbreak framing"),

            // --- obfuscation ----------------------------------------------
            PatternRule.of("injection.bidi_override",
                    "[\\u202A-\\u202E\\u2066-\\u2069]",
                    Severity.HIGH, "bidirectional override character; rendered text differs from raw"),
            PatternRule.of("injection.base64_payload",
                    "[A-Za-z0-9+/]{120,}={0,2}",
                    Severity.MEDIUM, "long base64-like blob may carry hidden instructions"),
            PatternRule.of("injection.zero_width",
                    "[\\u200B-\\u200D\\uFEFF]{3,}",
                    Severity.MEDIUM, "run of zero-width characters"));

    /** Whether findings are enforced or only recorded. */
    public enum Mode {
        /** Block/escalate per the configured thresholds. */
        ENFORCE,
        /**
         * Never block. Every match is still reported as a finding, so you can
         * measure a rule's real false-positive rate against live traffic before
         * you let it refuse anything. Shipping a blocking rule you haven't
         * measured is how a guardrail layer gets switched off in week two.
         */
        OBSERVE
    }

    private final Severity blockAt;
    private final Severity escalateAt;
    private final Mode mode;

    public PromptInjectionGuardrail(Severity blockAt, Severity escalateAt, Mode mode) {
        this.blockAt = java.util.Objects.requireNonNull(blockAt, "blockAt");
        this.escalateAt = java.util.Objects.requireNonNull(escalateAt, "escalateAt");
        this.mode = java.util.Objects.requireNonNull(mode, "mode");
        if (escalateAt.ordinal() > blockAt.ordinal()) {
            throw new IllegalArgumentException("escalateAt must not be more severe than blockAt");
        }
    }

    /** Blocks HIGH and above, escalates MEDIUM to a human. */
    public static PromptInjectionGuardrail defaults() {
        return new PromptInjectionGuardrail(Severity.HIGH, Severity.MEDIUM, Mode.ENFORCE);
    }

    /** Reports everything, blocks nothing. Use this to measure before enforcing. */
    public static PromptInjectionGuardrail observeOnly() {
        return new PromptInjectionGuardrail(Severity.HIGH, Severity.MEDIUM, Mode.OBSERVE);
    }

    @Override
    public String name() {
        return "prompt-injection";
    }

    @Override
    public Decision inspect(TextSubject subject, Context context) {
        var matches = PatternRule.scan(subject.text(), RULES);
        if (matches.isEmpty()) {
            return Decision.allow();
        }
        List<Finding> findings = PatternRule.findings(matches);

        if (mode == Mode.OBSERVE) {
            return Decision.allowWith(findings);
        }

        Severity peak = PatternRule.peakSeverity(matches).orElseThrow();
        if (peak.ordinal() >= blockAt.ordinal()) {
            return new Decision.Block(
                    "possible prompt injection (%s)".formatted(peak), findings);
        }
        if (peak.ordinal() >= escalateAt.ordinal()) {
            return new Decision.NeedsApproval(
                    "suspicious input pattern (%s)".formatted(peak), findings);
        }
        return Decision.allowWith(findings);
    }

    /** The rule set, for tests and inspection. Immutable. */
    public static List<PatternRule> rules() {
        return RULES;
    }
}
