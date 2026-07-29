package io.github.harshwardhan6062.palisade;

import java.util.List;

import io.github.harshwardhan6062.palisade.audit.AuditSink;

/**
 * An ordered chain of text guardrails. Immutable and thread-safe once built;
 * construct one per direction at startup and reuse it.
 *
 * <p>Order is significant and is the caller's decision. Cheap structural checks
 * belong first (a length ceiling costs microseconds and can make every later
 * rail's worst case bounded), redaction before anything that inspects semantics.
 */
public final class TextPipeline {

    private final List<Guardrail<TextSubject>> guardrails;
    private final AuditSink audit;
    private final String stage;

    private TextPipeline(List<Guardrail<TextSubject>> guardrails, AuditSink audit, String stage) {
        this.guardrails = List.copyOf(guardrails);
        this.audit = java.util.Objects.requireNonNull(audit, "audit");
        this.stage = java.util.Objects.requireNonNull(stage, "stage");
    }

    public static TextPipeline of(String stage, AuditSink audit, List<Guardrail<TextSubject>> guardrails) {
        return new TextPipeline(guardrails, audit, stage);
    }

    @SafeVarargs
    @SuppressWarnings("varargs")
    public static TextPipeline of(String stage, Guardrail<TextSubject>... guardrails) {
        return new TextPipeline(List.of(guardrails), AuditSink.NONE, stage);
    }

    public Outcome<TextSubject> run(TextSubject subject, Context context) {
        return Pipelines.run(guardrails, subject, context, TextSubject::withText, audit, stage);
    }

    public List<String> names() {
        return guardrails.stream().map(Guardrail::name).toList();
    }

    public int size() {
        return guardrails.size();
    }
}
