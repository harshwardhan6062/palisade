package io.github.harshwardhan6062.palisade.audit;

import io.github.harshwardhan6062.palisade.Context;
import io.github.harshwardhan6062.palisade.Outcome;

/**
 * Where guardrail decisions go.
 *
 * <p>Auditing is not optional decoration on a guardrail layer — it's the only
 * way to answer the two questions you will actually be asked: "why was this
 * blocked?" and "how often would this new rule have fired?" Without a record of
 * allowed-but-flagged traffic you can never safely tighten a rule, because you
 * have no idea what it would break.
 *
 * <p>Implementations must not throw and must be safe for concurrent use. A sink
 * that fails should drop the record, never break the request.
 */
public interface AuditSink {

    /**
     * @param stage which pipeline produced this — {@code "text:INBOUND"},
     *              {@code "text:OUTBOUND"}, or {@code "tool"}
     */
    void record(Context context, String stage, Outcome<?> outcome);

    /** Discards everything. Fine for tests; a poor default in production. */
    AuditSink NONE = (context, stage, outcome) -> { };
}
