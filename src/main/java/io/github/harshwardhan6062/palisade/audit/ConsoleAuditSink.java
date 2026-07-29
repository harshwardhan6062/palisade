package io.github.harshwardhan6062.palisade.audit;

import java.io.PrintStream;

import io.github.harshwardhan6062.palisade.Context;
import io.github.harshwardhan6062.palisade.Decision;
import io.github.harshwardhan6062.palisade.Outcome;

/**
 * Writes decisions to a {@link PrintStream}.
 *
 * <p>No logging framework, because the core of this library has zero runtime
 * dependencies and a security component is a bad place to introduce a
 * transitive dependency tree. Bridge to SLF4J/Log4j in your own application by
 * implementing {@link AuditSink} in three lines.
 *
 * <p>By default only non-{@code Allow} outcomes are printed — flip
 * {@code verbose} to see everything, which is how you tune a new rule before
 * you let it block anything.
 */
public final class ConsoleAuditSink implements AuditSink {

    private final PrintStream out;
    private final boolean verbose;

    public ConsoleAuditSink() {
        this(System.err, false);
    }

    public ConsoleAuditSink(PrintStream out, boolean verbose) {
        this.out = java.util.Objects.requireNonNull(out, "out");
        this.verbose = verbose;
    }

    /** Prints every decision, including allows. Use while tuning rules. */
    public static ConsoleAuditSink verbose() {
        return new ConsoleAuditSink(System.err, true);
    }

    @Override
    public void record(Context context, String stage, Outcome<?> outcome) {
        boolean interesting = !(outcome.decision() instanceof Decision.Allow a) || !a.findings().isEmpty();
        if (!interesting && !verbose) {
            return;
        }
        var sb = new StringBuilder()
                .append("palisade ")
                .append(verdict(outcome.decision()))
                .append(" stage=").append(stage)
                .append(" principal=").append(context.principal().id())
                .append(" session=").append(context.sessionId())
                .append(" took=").append("%.2fms".formatted(outcome.totalMicros() / 1000.0));

        outcome.reason().ifPresent(r -> sb.append(" reason=\"").append(r).append('"'));

        for (var finding : outcome.findings()) {
            sb.append("\n  - ").append(finding);
        }
        out.println(sb);
    }

    private static String verdict(Decision decision) {
        return switch (decision) {
            case Decision.Allow ignored -> "ALLOW";
            case Decision.Rewrite ignored -> "REWRITE";
            case Decision.NeedsApproval ignored -> "APPROVAL";
            case Decision.Block ignored -> "BLOCK";
        };
    }
}
