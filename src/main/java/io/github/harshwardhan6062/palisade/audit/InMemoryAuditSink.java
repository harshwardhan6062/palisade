package io.github.harshwardhan6062.palisade.audit;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Objects;

import io.github.harshwardhan6062.palisade.Context;
import io.github.harshwardhan6062.palisade.Decision;
import io.github.harshwardhan6062.palisade.Outcome;

/**
 * A bounded, thread-safe in-memory ring buffer of decisions.
 *
 * <p>Bounded deliberately. An unbounded audit buffer in a long-running agent is
 * a memory leak with a respectable-sounding name; when it overflows, the oldest
 * record is dropped and {@link #dropped()} counts it so the loss is visible
 * rather than silent.
 *
 * <p>Suitable for tests, local development, and as the tail buffer behind a
 * real sink. Not durable — pair it with something that writes off-box.
 */
public final class InMemoryAuditSink implements AuditSink {

    /** One recorded decision. */
    public record Entry(
            Instant at,
            String sessionId,
            String principalId,
            String stage,
            Decision decision,
            List<String> guardrails,
            long micros) {

        public boolean blocked() {
            return decision instanceof Decision.Block;
        }
    }

    private final int capacity;
    private final ArrayDeque<Entry> entries;
    private long dropped;

    public InMemoryAuditSink() {
        this(1_000);
    }

    public InMemoryAuditSink(int capacity) {
        if (capacity < 1) {
            throw new IllegalArgumentException("capacity must be >= 1, got " + capacity);
        }
        this.capacity = capacity;
        this.entries = new ArrayDeque<>(Math.min(capacity, 256));
    }

    @Override
    public void record(Context context, String stage, Outcome<?> outcome) {
        Objects.requireNonNull(context, "context");
        var entry = new Entry(
                Instant.now(),
                context.sessionId(),
                context.principal().id(),
                stage,
                outcome.decision(),
                outcome.trail().stream()
                        .map(io.github.harshwardhan6062.palisade.Evaluation::guardrail)
                        .toList(),
                outcome.totalMicros());
        synchronized (this) {
            if (entries.size() == capacity) {
                entries.removeFirst();
                dropped++;
            }
            entries.addLast(entry);
        }
    }

    /** Snapshot, oldest first. */
    public synchronized List<Entry> entries() {
        return List.copyOf(entries);
    }

    public synchronized List<Entry> blocked() {
        return entries.stream().filter(Entry::blocked).toList();
    }

    public synchronized List<Entry> forSession(String sessionId) {
        return entries.stream().filter(e -> e.sessionId().equals(sessionId)).toList();
    }

    /** Records discarded because the buffer was full. */
    public synchronized long dropped() {
        return dropped;
    }

    public synchronized int size() {
        return entries.size();
    }

    public synchronized void clear() {
        entries.clear();
        dropped = 0;
    }
}
