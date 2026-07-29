package io.github.harshwardhan6062.palisade;

import java.util.List;

/**
 * The verdict a single {@link Guardrail} returns.
 *
 * <p>Sealed so that callers can exhaustively pattern-match without a default
 * branch — adding a new decision kind becomes a compile error at every call
 * site rather than a silently-ignored case. For a security component that is
 * the property you want.
 *
 * <p>Decisions are ordered by {@link #severity()}. A pipeline's final decision
 * is the most severe one any guardrail returned.
 */
public sealed interface Decision {

    /** Higher is more restrictive. Used to combine decisions across a pipeline. */
    int severity();

    /** Evidence supporting this decision. Empty for {@link Allow}. */
    List<Finding> findings();

    /**
     * Permitted.
     *
     * <p>Carries findings so a rail can record "I saw something and allowed it
     * anyway" — the observations you want in your logs long before you're
     * confident enough to block on them. A guardrail layer you can't tune from
     * evidence is one you'll end up disabling.
     */
    record Allow(List<Finding> findings) implements Decision {
        public Allow {
            findings = List.copyOf(findings);
        }

        @Override
        public int severity() {
            return 0;
        }
    }

    /**
     * Content was modified — typically redaction. The pipeline passes
     * {@code text} to every subsequent guardrail, so rails compose.
     */
    record Rewrite(String text, List<Finding> findings) implements Decision {
        public Rewrite {
            java.util.Objects.requireNonNull(text, "text");
            findings = List.copyOf(findings);
        }

        @Override
        public int severity() {
            return 1;
        }
    }

    /**
     * Cannot be decided automatically — escalate to a human.
     *
     * <p>Deliberately distinct from {@link Block}: "I won't do this" and "someone
     * should look at this" have different handling, and collapsing them is how
     * guardrail layers end up either too permissive or unusable.
     */
    record NeedsApproval(String reason, List<Finding> findings) implements Decision {
        public NeedsApproval {
            java.util.Objects.requireNonNull(reason, "reason");
            findings = List.copyOf(findings);
        }

        @Override
        public int severity() {
            return 2;
        }
    }

    /** Refused. Pipelines short-circuit here. */
    record Block(String reason, List<Finding> findings) implements Decision {
        public Block {
            java.util.Objects.requireNonNull(reason, "reason");
            findings = List.copyOf(findings);
        }

        @Override
        public int severity() {
            return 3;
        }
    }

    // ---- factories -------------------------------------------------------

    Allow ALLOW = new Allow(List.of());

    static Decision allow() {
        return ALLOW;
    }

    /** Permitted, but record what was seen. */
    static Decision allowWith(Finding... findings) {
        return findings.length == 0 ? ALLOW : new Allow(List.of(findings));
    }

    static Decision allowWith(List<Finding> findings) {
        return findings.isEmpty() ? ALLOW : new Allow(findings);
    }

    static Decision block(String reason, Finding... findings) {
        return new Block(reason, List.of(findings));
    }

    static Decision rewrite(String text, Finding... findings) {
        return new Rewrite(text, List.of(findings));
    }

    static Decision needsApproval(String reason, Finding... findings) {
        return new NeedsApproval(reason, List.of(findings));
    }
}
