package io.github.harshwardhan6062.palisade.text;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import io.github.harshwardhan6062.palisade.Finding;

/**
 * A named regex with a severity, plus the shared machinery for scanning and
 * redacting with a set of them.
 *
 * <p>Pattern matching is a floor, not a ceiling. It catches known-shape attacks
 * and known-shape data — which is most of what actually shows up — and it is
 * fast, deterministic, explainable, and testable. It will not catch a novel
 * paraphrase. Treat these rails as defence in depth alongside a model-based
 * classifier, never as a complete solution. See DESIGN.md.
 */
public record PatternRule(String id, Pattern pattern, Finding.Severity severity, String detail) {

    public PatternRule {
        java.util.Objects.requireNonNull(id, "id");
        java.util.Objects.requireNonNull(pattern, "pattern");
        java.util.Objects.requireNonNull(severity, "severity");
        java.util.Objects.requireNonNull(detail, "detail");
    }

    public static PatternRule of(String id, String regex, Finding.Severity severity, String detail) {
        return new PatternRule(id, Pattern.compile(regex), severity, detail);
    }

    /** A match: which rule fired, and where. */
    public record Match(PatternRule rule, int start, int end, String matched) {
        public Finding toFinding() {
            return Finding.at(rule.id(), rule.severity(), rule.detail(), start, end);
        }
    }

    /**
     * Scan {@code text} with every rule.
     *
     * <p>An individual rule that throws is skipped rather than propagated —
     * one bad pattern shouldn't disable the whole rail. Callers that need
     * fail-closed semantics get them from the pipeline, which treats a thrown
     * guardrail as a block.
     */
    public static List<Match> scan(String text, List<PatternRule> rules) {
        var matches = new ArrayList<Match>();
        for (PatternRule rule : rules) {
            try {
                Matcher m = rule.pattern().matcher(text);
                while (m.find()) {
                    matches.add(new Match(rule, m.start(), m.end(), m.group()));
                }
            } catch (RuntimeException ignored) {
                // Defensive: a malformed or catastrophically-backtracking rule
                // must not take the rail down with it.
            }
        }
        return matches;
    }

    /**
     * Replace every match with {@code [REDACTED:ID]}, resolving overlaps.
     *
     * <p>Overlap resolution matters more than it looks. A 16-digit string can
     * match both a card-number rule and a phone rule; naive sequential
     * replacement corrupts offsets and can leave fragments of the original
     * value in the output. Here matches are sorted, higher severity wins a
     * conflict, and the string is rebuilt once from non-overlapping spans.
     */
    public static String redact(String text, List<Match> matches) {
        if (matches.isEmpty()) {
            return text;
        }
        var ordered = new ArrayList<>(matches);
        ordered.sort(Comparator
                .comparingInt(Match::start)
                .thenComparing(Comparator.comparingInt((Match m) -> m.rule().severity().ordinal()).reversed())
                .thenComparing(Comparator.comparingInt(Match::end).reversed()));

        var sb = new StringBuilder(text.length());
        int cursor = 0;
        for (Match m : ordered) {
            if (m.start() < cursor) {
                continue; // already covered by a previous (higher-priority) span
            }
            sb.append(text, cursor, m.start());
            sb.append("[REDACTED:").append(m.rule().id().toUpperCase()).append(']');
            cursor = m.end();
        }
        sb.append(text, cursor, text.length());
        return sb.toString();
    }

    /** Highest severity among the given matches, or empty if there are none. */
    public static java.util.Optional<Finding.Severity> peakSeverity(List<Match> matches) {
        return matches.stream().map(m -> m.rule().severity()).max(Comparator.naturalOrder());
    }

    public static List<Finding> findings(List<Match> matches) {
        return matches.stream().map(Match::toFinding).toList();
    }
}
