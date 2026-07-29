package io.github.harshwardhan6062.palisade;

/**
 * One check. Implementations must be stateless with respect to the subject and
 * safe to call from many threads — pipelines are shared and reused.
 *
 * <p>{@link #inspect} must not throw for malformed input. Guardrails run on
 * adversarial data by definition; an exception escaping a rail is a bypass,
 * because the surrounding host almost always ends up catching it and continuing.
 * Return {@link Decision.Block} instead of throwing.
 *
 * @param <S> the subject type — {@link TextSubject} or {@link ToolCall}
 */
public interface Guardrail<S> {

    /** Stable identifier, used in findings and the audit trail. */
    String name();

    Decision inspect(S subject, Context context);
}
