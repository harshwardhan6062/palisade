package io.github.harshwardhan6062.palisade;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BiFunction;

import io.github.harshwardhan6062.palisade.audit.AuditSink;

/**
 * The shared evaluation engine. Package-private on purpose: {@link TextPipeline}
 * and {@link ToolPipeline} are the public surface, and keeping the generic
 * machinery out of the API means callers never write a wildcard type.
 */
final class Pipelines {

    private Pipelines() {}

    /**
     * Run guardrails in order.
     *
     * <p>Semantics, in the order they matter:
     * <ol>
     *   <li><b>A thrown exception is a block, not a pass.</b> Fail closed. A rail
     *       that crashes on adversarial input must not become a bypass.
     *   <li><b>{@code Block} short-circuits.</b> Once refused there is nothing
     *       left to learn, and continuing costs latency in the request path.
     *   <li><b>{@code Rewrite} chains.</b> Each subsequent rail inspects the
     *       rewritten subject, so redaction composes — a rail can't be fooled by
     *       content an earlier rail already removed.
     *   <li><b>The final decision is the most severe one seen</b>, rebuilt at the
     *       end so a {@code Rewrite} verdict carries the fully-rewritten text and
     *       the union of all findings, not just the first rail's.
     * </ol>
     */
    static <S> Outcome<S> run(
            List<Guardrail<S>> rails,
            S subject,
            Context context,
            BiFunction<S, String, S> rewriter,
            AuditSink audit,
            String stage) {

        var trail = new ArrayList<Evaluation>(rails.size());
        var findings = new ArrayList<Finding>();
        S current = subject;

        Decision.Block block = null;
        Decision.NeedsApproval approval = null;
        boolean rewritten = false;

        for (Guardrail<S> rail : rails) {
            long started = System.nanoTime();
            Decision decision;
            try {
                decision = rail.inspect(current, context);
                if (decision == null) {
                    decision = failClosed(rail, "returned null");
                }
            } catch (RuntimeException e) {
                decision = failClosed(rail, e.getClass().getSimpleName() + ": " + e.getMessage());
            }
            long micros = (System.nanoTime() - started) / 1_000;

            trail.add(new Evaluation(rail.name(), decision, micros));
            findings.addAll(decision.findings());

            switch (decision) {
                case Decision.Rewrite r -> {
                    current = rewriter.apply(current, r.text());
                    rewritten = true;
                }
                case Decision.NeedsApproval n -> {
                    if (approval == null) approval = n;
                }
                case Decision.Block b -> block = b;
                case Decision.Allow ignored -> { /* nothing to do */ }
            }

            if (block != null) break;
        }

        Decision finalDecision;
        if (block != null) {
            finalDecision = new Decision.Block(block.reason(), List.copyOf(findings));
        } else if (approval != null) {
            finalDecision = new Decision.NeedsApproval(approval.reason(), List.copyOf(findings));
        } else if (rewritten) {
            finalDecision = new Decision.Rewrite(String.valueOf(contentOf(current)), List.copyOf(findings));
        } else {
            finalDecision = Decision.allowWith(List.copyOf(findings));
        }

        var outcome = new Outcome<>(finalDecision, current, trail);
        audit.record(context, stage, outcome);
        return outcome;
    }

    private static Decision failClosed(Guardrail<?> rail, String detail) {
        return new Decision.Block(
                "guardrail '" + rail.name() + "' failed; refusing (fail-closed)",
                List.of(Finding.of(rail.name(), Finding.Severity.CRITICAL, detail)));
    }

    /** Text subjects expose their content; anything else falls back to toString. */
    private static Object contentOf(Object subject) {
        return subject instanceof TextSubject t ? t.text() : subject;
    }
}
