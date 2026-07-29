package io.github.harshwardhan6062.palisade.tool;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

import io.github.harshwardhan6062.palisade.Context;
import io.github.harshwardhan6062.palisade.Decision;
import io.github.harshwardhan6062.palisade.Finding;
import io.github.harshwardhan6062.palisade.Finding.Severity;
import io.github.harshwardhan6062.palisade.Guardrail;
import io.github.harshwardhan6062.palisade.ToolCall;

/**
 * Per-principal token bucket over tool invocations.
 *
 * <p>The failure this exists for is not abuse — it's an agent stuck in a loop.
 * A model that misreads a tool result and retries, or two agents that trigger
 * each other, will issue the same call thousands of times without any single call
 * being objectionable. Correctness rails inspect calls one at a time and cannot
 * see that shape at all; only something with memory across calls can.
 *
 * <p>A bucket permits {@code capacity} calls in a burst and refills at
 * {@code refillPerSecond}. Burst tolerance is the point: agents are naturally
 * bursty (a fan-out of parallel reads is normal and healthy), so a flat
 * calls-per-second cap would block legitimate work while still allowing a slow
 * infinite loop.
 *
 * <p>The clock is injectable so the refill behaviour can be tested
 * deterministically instead of with sleeps. State is in-process — behind multiple
 * replicas you want a shared store, and the {@code Bucket} logic here ports to
 * one directly.
 */
public final class RateLimitGuardrail implements Guardrail<ToolCall> {

    private static final long NANOS_PER_SECOND = 1_000_000_000L;

    private final int capacity;
    private final double refillPerSecond;
    private final LongSupplier nanoClock;
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    public RateLimitGuardrail(int capacity, double refillPerSecond) {
        this(capacity, refillPerSecond, System::nanoTime);
    }

    public RateLimitGuardrail(int capacity, double refillPerSecond, LongSupplier nanoClock) {
        if (capacity < 1) {
            throw new IllegalArgumentException("capacity must be >= 1, got " + capacity);
        }
        if (refillPerSecond <= 0) {
            throw new IllegalArgumentException("refillPerSecond must be > 0, got " + refillPerSecond);
        }
        this.capacity = capacity;
        this.refillPerSecond = refillPerSecond;
        this.nanoClock = java.util.Objects.requireNonNull(nanoClock, "nanoClock");
    }

    /** 30-call burst, sustained 5 calls/second. */
    public static RateLimitGuardrail defaults() {
        return new RateLimitGuardrail(30, 5.0);
    }

    @Override
    public String name() {
        return "rate-limit";
    }

    @Override
    public Decision inspect(ToolCall call, Context context) {
        String key = context.principal().id();
        Bucket bucket = buckets.computeIfAbsent(key, k -> new Bucket(capacity, nanoClock.getAsLong()));

        if (bucket.tryConsume(nanoClock.getAsLong(), capacity, refillPerSecond)) {
            return Decision.allow();
        }
        return new Decision.Block(
                "rate limit exceeded for principal '%s'".formatted(key),
                List.of(Finding.of("rate_limit.exceeded", Severity.MEDIUM,
                        "burst capacity %d, refill %.1f/s, tool '%s'"
                                .formatted(capacity, refillPerSecond, call.name()))));
    }

    /** Number of principals currently tracked. Useful for leak checks in long runs. */
    public int trackedPrincipals() {
        return buckets.size();
    }

    /** Drop bucket state — primarily for tests. */
    public void reset() {
        buckets.clear();
    }

    /**
     * A single bucket. Synchronized rather than lock-free: contention is per
     * principal, the critical section is a handful of arithmetic operations, and
     * a correct-by-inspection implementation is worth more here than a clever one.
     */
    private static final class Bucket {
        private double tokens;
        private long lastRefillNanos;

        Bucket(int capacity, long nowNanos) {
            this.tokens = capacity;
            this.lastRefillNanos = nowNanos;
        }

        synchronized boolean tryConsume(long nowNanos, int capacity, double refillPerSecond) {
            long elapsed = nowNanos - lastRefillNanos;
            if (elapsed > 0) {
                tokens = Math.min(capacity, tokens + (elapsed / (double) NANOS_PER_SECOND) * refillPerSecond);
                lastRefillNanos = nowNanos;
            }
            if (tokens >= 1.0) {
                tokens -= 1.0;
                return true;
            }
            return false;
        }
    }
}
