package io.github.harshwardhan6062.palisade;

import java.util.Map;
import java.util.UUID;

/**
 * Ambient facts about the interaction being inspected — never derived from the
 * content itself.
 *
 * @param principal   who the agent is acting for
 * @param sessionId   correlates every decision in one agent run; the join key
 *                    for anything you do with the audit trail later
 * @param attributes  free-form host metadata (tenant, environment, request id)
 */
public record Context(Principal principal, String sessionId, Map<String, String> attributes) {

    public Context {
        java.util.Objects.requireNonNull(principal, "principal");
        java.util.Objects.requireNonNull(sessionId, "sessionId");
        attributes = Map.copyOf(attributes);
    }

    public static Context of(Principal principal) {
        return new Context(principal, UUID.randomUUID().toString(), Map.of());
    }

    public static Context anonymous() {
        return of(Principal.ANONYMOUS);
    }

    public Context with(String key, String value) {
        var next = new java.util.HashMap<>(attributes);
        next.put(key, value);
        return new Context(principal, sessionId, next);
    }
}
