package io.github.harshwardhan6062.palisade.text;

import java.util.List;

import io.github.harshwardhan6062.palisade.Context;
import io.github.harshwardhan6062.palisade.Decision;
import io.github.harshwardhan6062.palisade.Finding;
import io.github.harshwardhan6062.palisade.Finding.Severity;
import io.github.harshwardhan6062.palisade.Guardrail;
import io.github.harshwardhan6062.palisade.TextSubject;

/**
 * Detects and optionally redacts personal data.
 *
 * <p>Direction changes what this means, which is why {@link TextSubject} carries
 * it. Inbound, PII is usually the user's own and redacting protects it from
 * being logged or sent to a third-party model. Outbound, the same match may be
 * one user's data leaking into another's session — a different and worse problem.
 * The default is {@link Mode#REDACT} in both directions because redaction is the
 * option that keeps the agent useful.
 *
 * <p>Card numbers are Luhn-validated before being reported. Without that check
 * every order number, tracking ID, and 16-digit identifier trips the rule, and a
 * rail with that false-positive rate gets disabled — so the validation is what
 * makes the rule survivable in production, not a nicety.
 */
public final class PiiGuardrail implements Guardrail<TextSubject> {

    public enum Mode {
        /** Replace matches with {@code [REDACTED:…]} and continue. */
        REDACT,
        /** Refuse outright. */
        BLOCK,
        /** Record findings, change nothing. */
        REPORT
    }

    private static final String CARD_RULE_ID = "credit_card";

    private static final List<PatternRule> RULES = List.of(
            // Longest / most specific digit patterns first so overlap resolution
            // prefers them over the shorter phone-number shapes.
            PatternRule.of(CARD_RULE_ID,
                    "\\b(?:\\d[ -]?){12,18}\\d\\b",
                    Severity.HIGH, "payment card number (Luhn-valid)"),
            PatternRule.of("ssn_us",
                    "\\b\\d{3}-\\d{2}-\\d{4}\\b",
                    Severity.HIGH, "US social security number"),
            PatternRule.of("aadhaar",
                    "\\b[2-9]\\d{3}\\s?\\d{4}\\s?\\d{4}\\b",
                    Severity.HIGH, "Aadhaar-shaped identifier"),
            PatternRule.of("email",
                    "\\b[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}\\b",
                    Severity.MEDIUM, "email address"),
            PatternRule.of("phone_in",
                    "(?:\\+?91[\\s\\-]?)?\\b[6-9]\\d{9}\\b",
                    Severity.MEDIUM, "Indian mobile number"),
            PatternRule.of("phone_us",
                    "\\b\\(?\\d{3}\\)?[\\s.\\-]\\d{3}[\\s.\\-]\\d{4}\\b",
                    Severity.MEDIUM, "US phone number"),
            PatternRule.of("ipv4",
                    "\\b(?:(?:25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]?\\d)\\.){3}"
                            + "(?:25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]?\\d)\\b",
                    Severity.LOW, "IPv4 address"));

    private final Mode mode;

    public PiiGuardrail(Mode mode) {
        this.mode = java.util.Objects.requireNonNull(mode, "mode");
    }

    public static PiiGuardrail defaults() {
        return new PiiGuardrail(Mode.REDACT);
    }

    @Override
    public String name() {
        return "pii";
    }

    @Override
    public Decision inspect(TextSubject subject, Context context) {
        var matches = PatternRule.scan(subject.text(), RULES).stream()
                .filter(PiiGuardrail::plausible)
                .toList();

        if (matches.isEmpty()) {
            return Decision.allow();
        }
        List<Finding> findings = PatternRule.findings(matches);

        return switch (mode) {
            case REPORT -> Decision.allowWith(findings);
            case BLOCK -> new Decision.Block(
                    "input contains personal data (%d match%s)"
                            .formatted(matches.size(), matches.size() == 1 ? "" : "es"),
                    findings);
            case REDACT -> new Decision.Rewrite(
                    PatternRule.redact(subject.text(), matches), findings);
        };
    }

    /** Post-filter: drop digit matches that fail their format's checksum. */
    private static boolean plausible(PatternRule.Match match) {
        if (!match.rule().id().equals(CARD_RULE_ID)) {
            return true;
        }
        return luhnValid(match.matched());
    }

    /**
     * Luhn (mod-10) checksum, as used by every major card network.
     *
     * <p>Doubles every second digit from the right, subtracting 9 from any result
     * above 9, and requires the total to be divisible by 10.
     */
    public static boolean luhnValid(String candidate) {
        int sum = 0;
        boolean doubling = false;
        for (int i = candidate.length() - 1; i >= 0; i--) {
            char c = candidate.charAt(i);
            if (c == ' ' || c == '-') {
                continue;
            }
            if (c < '0' || c > '9') {
                return false;
            }
            int digit = c - '0';
            if (doubling) {
                digit *= 2;
                if (digit > 9) {
                    digit -= 9;
                }
            }
            sum += digit;
            doubling = !doubling;
        }
        return sum > 0 && sum % 10 == 0;
    }

    public static List<PatternRule> rules() {
        return RULES;
    }

    public Mode mode() {
        return mode;
    }
}
