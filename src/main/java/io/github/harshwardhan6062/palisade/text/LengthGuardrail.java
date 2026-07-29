package io.github.harshwardhan6062.palisade.text;

import io.github.harshwardhan6062.palisade.Context;
import io.github.harshwardhan6062.palisade.Decision;
import io.github.harshwardhan6062.palisade.Finding;
import io.github.harshwardhan6062.palisade.Guardrail;
import io.github.harshwardhan6062.palisade.TextSubject;

/**
 * Rejects text above a character ceiling.
 *
 * <p>Put this first. It is the cheapest rail there is, and once it has run every
 * later rail has a bounded worst case — which matters because regex-based
 * scanners are where a pathological input turns into CPU burn. A guardrail chain
 * with no length bound at the front has no latency bound at all.
 *
 * <p>The token estimate is deliberately crude (chars ÷ 3.5, floor). It exists to
 * make the limit legible to a human reading a log line, not to bill anyone. Real
 * token counts are model-specific and require the provider's tokenizer; do not
 * use this number for cost control.
 */
public final class LengthGuardrail implements Guardrail<TextSubject> {

    private static final double CHARS_PER_TOKEN = 3.5;

    private final int maxChars;

    public LengthGuardrail(int maxChars) {
        if (maxChars < 1) {
            throw new IllegalArgumentException("maxChars must be >= 1, got " + maxChars);
        }
        this.maxChars = maxChars;
    }

    /** 32k characters — roughly 9k tokens. A reasonable ceiling for a single user turn. */
    public static LengthGuardrail defaults() {
        return new LengthGuardrail(32_000);
    }

    @Override
    public String name() {
        return "length";
    }

    @Override
    public Decision inspect(TextSubject subject, Context context) {
        int length = subject.length();
        if (length <= maxChars) {
            return Decision.allow();
        }
        return Decision.block(
                "text is %d characters, limit is %d".formatted(length, maxChars),
                Finding.of("length.exceeded", Finding.Severity.MEDIUM,
                        "%d chars (~%d tokens) over a %d limit"
                                .formatted(length, estimateTokens(length), maxChars)));
    }

    public static long estimateTokens(int chars) {
        return (long) Math.floor(chars / CHARS_PER_TOKEN);
    }

    public int maxChars() {
        return maxChars;
    }
}
