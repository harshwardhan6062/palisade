package io.github.harshwardhan6062.palisade;

/**
 * A single piece of evidence produced by a guardrail.
 *
 * <p>{@code start}/{@code end} are character offsets into the inspected text,
 * or {@code -1} when the finding isn't positional (a rate-limit breach, a
 * denied tool name). Offsets are what let a UI highlight *why* something was
 * flagged instead of just asserting that it was.
 */
public record Finding(String rule, Severity severity, String detail, int start, int end) {

    public enum Severity {
        INFO,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    public Finding {
        java.util.Objects.requireNonNull(rule, "rule");
        java.util.Objects.requireNonNull(severity, "severity");
        java.util.Objects.requireNonNull(detail, "detail");
    }

    /** Non-positional finding. */
    public static Finding of(String rule, Severity severity, String detail) {
        return new Finding(rule, severity, detail, -1, -1);
    }

    /** Positional finding, spanning {@code [start, end)} of the inspected text. */
    public static Finding at(String rule, Severity severity, String detail, int start, int end) {
        return new Finding(rule, severity, detail, start, end);
    }

    public boolean positional() {
        return start >= 0 && end >= start;
    }

    @Override
    public String toString() {
        String span = positional() ? " [" + start + "," + end + ")" : "";
        return severity + " " + rule + ": " + detail + span;
    }
}
