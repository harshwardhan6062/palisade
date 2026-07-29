package io.github.harshwardhan6062.palisade;

/**
 * What one guardrail decided, and how long it took.
 *
 * <p>Timing is recorded per rail because guardrails sit in the request path.
 * A rail that is 2ms in tests and 200ms on real input is the kind of thing you
 * only find if you measure each one separately.
 */
public record Evaluation(String guardrail, Decision decision, long micros) {

    public Evaluation {
        java.util.Objects.requireNonNull(guardrail, "guardrail");
        java.util.Objects.requireNonNull(decision, "decision");
    }

    public double millis() {
        return micros / 1000.0;
    }

    @Override
    public String toString() {
        return "%s -> %s (%.2fms)".formatted(
                guardrail, decision.getClass().getSimpleName(), millis());
    }
}
