package io.github.harshwardhan6062.palisade;

/**
 * Text on its way into or out of a model.
 *
 * <p>Direction is part of the subject rather than a pipeline-level setting
 * because the same rule often applies differently by direction: detecting a
 * credential in user input is a hygiene warning, while detecting one in model
 * output is a leak.
 */
public record TextSubject(String text, Direction direction) {

    public enum Direction {
        /** User (or upstream system) → model. */
        INBOUND,
        /** Model → user (or downstream system). */
        OUTBOUND
    }

    public TextSubject {
        java.util.Objects.requireNonNull(text, "text");
        java.util.Objects.requireNonNull(direction, "direction");
    }

    public static TextSubject inbound(String text) {
        return new TextSubject(text, Direction.INBOUND);
    }

    public static TextSubject outbound(String text) {
        return new TextSubject(text, Direction.OUTBOUND);
    }

    /** Same direction, replaced content — how a {@link Decision.Rewrite} is applied. */
    public TextSubject withText(String replacement) {
        return new TextSubject(replacement, direction);
    }

    public int length() {
        return text.length();
    }
}
