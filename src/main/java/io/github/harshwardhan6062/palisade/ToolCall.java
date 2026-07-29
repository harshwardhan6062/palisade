package io.github.harshwardhan6062.palisade;

import java.util.Map;
import java.util.Optional;

/**
 * A tool invocation the model has requested but which has <em>not</em> run.
 *
 * <p>This is the highest-leverage interception point in an agent. Text
 * guardrails police what is said; this policies what is <em>done</em>. The model
 * only ever emits a request — the host executes it — so everything an agent can
 * affect in the world passes through here first.
 *
 * @param name      the tool the model asked for
 * @param arguments decoded arguments, as supplied by the model
 */
public record ToolCall(String name, Map<String, Object> arguments) {

    public ToolCall {
        java.util.Objects.requireNonNull(name, "name");
        arguments = Map.copyOf(arguments);
    }

    public static ToolCall of(String name) {
        return new ToolCall(name, Map.of());
    }

    public static ToolCall of(String name, String key, Object value) {
        return new ToolCall(name, Map.of(key, value));
    }

    public Optional<String> stringArg(String key) {
        Object v = arguments.get(key);
        return v == null ? Optional.empty() : Optional.of(String.valueOf(v));
    }

    /** All argument values flattened to strings — what argument scanners inspect. */
    public Map<String, String> stringArgs() {
        var out = new java.util.LinkedHashMap<String, String>();
        arguments.forEach((k, v) -> out.put(k, String.valueOf(v)));
        return Map.copyOf(out);
    }
}
