package io.github.harshwardhan6062.palisade;

import java.util.List;

import io.github.harshwardhan6062.palisade.audit.AuditSink;

/**
 * An ordered chain of tool guardrails, evaluated before a tool call executes.
 *
 * <p>Tool rails never rewrite. Silently altering the arguments of an action the
 * model asked for produces a system whose behaviour can't be reasoned about from
 * either side — the model believes it did one thing, the host did another. The
 * only honest verdicts here are allow, escalate, or refuse.
 */
public final class ToolPipeline {

    private final List<Guardrail<ToolCall>> guardrails;
    private final AuditSink audit;

    private ToolPipeline(List<Guardrail<ToolCall>> guardrails, AuditSink audit) {
        this.guardrails = List.copyOf(guardrails);
        this.audit = java.util.Objects.requireNonNull(audit, "audit");
    }

    public static ToolPipeline of(AuditSink audit, List<Guardrail<ToolCall>> guardrails) {
        return new ToolPipeline(guardrails, audit);
    }

    @SafeVarargs
    @SuppressWarnings("varargs")
    public static ToolPipeline of(Guardrail<ToolCall>... guardrails) {
        return new ToolPipeline(List.of(guardrails), AuditSink.NONE);
    }

    public Outcome<ToolCall> run(ToolCall call, Context context) {
        return Pipelines.run(guardrails, call, context, ToolPipeline::rejectRewrite, audit, "tool");
    }

    private static ToolCall rejectRewrite(ToolCall call, String ignored) {
        throw new UnsupportedOperationException(
                "tool guardrails must not rewrite arguments; return Block or NeedsApproval instead");
    }

    public List<String> names() {
        return guardrails.stream().map(Guardrail::name).toList();
    }

    public int size() {
        return guardrails.size();
    }
}
