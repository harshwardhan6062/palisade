package io.github.harshwardhan6062.palisade;

import java.util.List;

/**
 * The result of running a pipeline.
 *
 * @param decision the most severe decision any guardrail returned
 * @param subject  the subject after any rewrites were applied
 * @param trail    every guardrail that ran, in order — the audit record
 */
public record Outcome<S>(Decision decision, S subject, List<Evaluation> trail) {

    public Outcome {
        java.util.Objects.requireNonNull(decision, "decision");
        java.util.Objects.requireNonNull(subject, "subject");
        trail = List.copyOf(trail);
    }

    /** True unless blocked. Note an approval-required outcome is <em>not</em> allowed to proceed unattended. */
    public boolean allowed() {
        return !(decision instanceof Decision.Block);
    }

    public boolean blocked() {
        return decision instanceof Decision.Block;
    }

    public boolean requiresApproval() {
        return decision instanceof Decision.NeedsApproval;
    }

    /** True when the subject was modified (redaction) rather than passed through. */
    public boolean rewritten() {
        return trail.stream().anyMatch(e -> e.decision() instanceof Decision.Rewrite);
    }

    /** Why it was blocked or escalated, if it was. */
    public java.util.Optional<String> reason() {
        return switch (decision) {
            case Decision.Block b -> java.util.Optional.of(b.reason());
            case Decision.NeedsApproval n -> java.util.Optional.of(n.reason());
            case Decision.Allow ignored -> java.util.Optional.empty();
            case Decision.Rewrite ignored -> java.util.Optional.empty();
        };
    }

    /** All findings from all rails that ran, flattened. */
    public List<Finding> findings() {
        return trail.stream().flatMap(e -> e.decision().findings().stream()).toList();
    }

    public long totalMicros() {
        return trail.stream().mapToLong(Evaluation::micros).sum();
    }
}
