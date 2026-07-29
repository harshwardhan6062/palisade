package io.github.harshwardhan6062.palisade;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import io.github.harshwardhan6062.palisade.audit.InMemoryAuditSink;

/** The pipeline semantics everything else depends on. */
class PipelineTest {

    private static Guardrail<TextSubject> rail(String name, Decision decision, AtomicInteger calls) {
        return new Guardrail<>() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public Decision inspect(TextSubject subject, Context context) {
                calls.incrementAndGet();
                return decision;
            }
        };
    }

    @Test
    @DisplayName("a block short-circuits: later rails never run")
    void blockShortCircuits() {
        var first = new AtomicInteger();
        var second = new AtomicInteger();
        var pipeline = TextPipeline.of("test",
                rail("blocker", Decision.block("nope"), first),
                rail("never", Decision.allow(), second));

        var outcome = pipeline.run(TextSubject.inbound("hello"), Context.anonymous());

        assertTrue(outcome.blocked());
        assertEquals(1, first.get());
        assertEquals(0, second.get(), "rails after a block must not run");
        assertEquals(1, outcome.trail().size(), "trail records only rails that actually ran");
    }

    @Test
    @DisplayName("rewrites chain: each rail sees the previous rail's output")
    void rewritesChain() {
        Guardrail<TextSubject> upper = new Guardrail<>() {
            public String name() {
                return "upper";
            }

            public Decision inspect(TextSubject s, Context c) {
                return Decision.rewrite(s.text().toUpperCase());
            }
        };
        Guardrail<TextSubject> exclaim = new Guardrail<>() {
            public String name() {
                return "exclaim";
            }

            public Decision inspect(TextSubject s, Context c) {
                return Decision.rewrite(s.text() + "!");
            }
        };

        var outcome = TextPipeline.of("test", upper, exclaim)
                .run(TextSubject.inbound("abc"), Context.anonymous());

        assertEquals("ABC!", outcome.subject().text());
        assertInstanceOf(Decision.Rewrite.class, outcome.decision());
        assertEquals("ABC!", ((Decision.Rewrite) outcome.decision()).text(),
                "final decision must carry the fully-rewritten text, not the first rewrite");
    }

    @Test
    @DisplayName("a guardrail that throws fails closed")
    void throwingRailFailsClosed() {
        Guardrail<TextSubject> broken = new Guardrail<>() {
            public String name() {
                return "broken";
            }

            public Decision inspect(TextSubject s, Context c) {
                throw new IllegalStateException("boom");
            }
        };

        var outcome = TextPipeline.of("test", broken)
                .run(TextSubject.inbound("hello"), Context.anonymous());

        assertTrue(outcome.blocked(), "an exception must not be treated as a pass");
        assertTrue(outcome.reason().orElseThrow().contains("fail-closed"));
        assertEquals(Finding.Severity.CRITICAL, outcome.findings().get(0).severity());
    }

    @Test
    @DisplayName("a guardrail returning null fails closed")
    void nullDecisionFailsClosed() {
        Guardrail<TextSubject> sloppy = new Guardrail<>() {
            public String name() {
                return "sloppy";
            }

            public Decision inspect(TextSubject s, Context c) {
                return null;
            }
        };

        assertTrue(TextPipeline.of("test", sloppy)
                .run(TextSubject.inbound("x"), Context.anonymous())
                .blocked());
    }

    @Test
    @DisplayName("the most severe decision wins, and all findings are collected")
    void mostSevereWins() {
        var noop = new AtomicInteger();
        var pipeline = TextPipeline.of("test",
                rail("a", Decision.allowWith(Finding.of("a", Finding.Severity.LOW, "seen")), noop),
                rail("b", Decision.needsApproval("check me", Finding.of("b", Finding.Severity.MEDIUM, "hm")), noop),
                rail("c", Decision.allow(), noop));

        var outcome = pipeline.run(TextSubject.inbound("x"), Context.anonymous());

        assertTrue(outcome.requiresApproval());
        assertFalse(outcome.blocked());
        assertEquals("check me", outcome.reason().orElseThrow());
        assertEquals(2, outcome.findings().size(), "findings accumulate across rails");
        assertEquals(3, outcome.trail().size());
    }

    @Test
    @DisplayName("an approval-required outcome is not silently allowed")
    void approvalIsNotAllowed() {
        var outcome = TextPipeline.of("test",
                rail("a", Decision.needsApproval("human needed"), new AtomicInteger()))
                .run(TextSubject.inbound("x"), Context.anonymous());

        // allowed() is true (not blocked) but requiresApproval() must be checked
        // by the caller — this asserts the distinction exists.
        assertTrue(outcome.allowed());
        assertTrue(outcome.requiresApproval());
    }

    @Test
    @DisplayName("an empty pipeline allows, and says so honestly")
    void emptyPipelineAllows() {
        var outcome = TextPipeline.of("test").run(TextSubject.inbound("x"), Context.anonymous());
        assertTrue(outcome.allowed());
        assertEquals(0, outcome.trail().size());
        assertEquals(List.of(), outcome.findings());
    }

    @Test
    @DisplayName("every run is recorded to the audit sink")
    void auditReceivesEveryRun() {
        var sink = new InMemoryAuditSink();
        var pipeline = TextPipeline.of("text:INBOUND", sink,
                List.of(rail("a", Decision.block("no"), new AtomicInteger())));
        var ctx = Context.of(Principal.of("u1"));

        pipeline.run(TextSubject.inbound("x"), ctx);

        assertEquals(1, sink.size());
        var entry = sink.entries().get(0);
        assertEquals("text:INBOUND", entry.stage());
        assertEquals("u1", entry.principalId());
        assertEquals(ctx.sessionId(), entry.sessionId());
        assertTrue(entry.blocked());
    }

    @Test
    @DisplayName("the audit buffer is bounded and reports what it dropped")
    void auditBufferIsBounded() {
        var sink = new InMemoryAuditSink(2);
        var pipeline = TextPipeline.of("test", sink,
                List.of(rail("a", Decision.allow(), new AtomicInteger())));

        for (int i = 0; i < 5; i++) {
            pipeline.run(TextSubject.inbound("x"), Context.anonymous());
        }

        assertEquals(2, sink.size());
        assertEquals(3, sink.dropped(), "overflow must be counted, not silent");
    }

    @Test
    @DisplayName("timing is recorded per rail")
    void timingRecordedPerRail() {
        var outcome = TextPipeline.of("test",
                rail("a", Decision.allow(), new AtomicInteger()),
                rail("b", Decision.allow(), new AtomicInteger()))
                .run(TextSubject.inbound("x"), Context.anonymous());

        assertEquals(2, outcome.trail().size());
        assertTrue(outcome.trail().stream().allMatch(e -> e.micros() >= 0));
        assertEquals(outcome.totalMicros(),
                outcome.trail().stream().mapToLong(Evaluation::micros).sum());
    }
}
