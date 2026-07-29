package io.github.harshwardhan6062.palisade;

import java.util.Set;

/**
 * Who the agent is acting on behalf of.
 *
 * <p>Guardrails that vary by caller — rate limits, tool permissions — key off
 * this. Keeping identity out of the inspected payload and in the surrounding
 * {@link Context} is deliberate: it means a guardrail can never be tricked into
 * changing its own authorization by content it is inspecting.
 */
public record Principal(String id, Set<String> roles) {

    public static final Principal ANONYMOUS = new Principal("anonymous", Set.of());

    public Principal {
        java.util.Objects.requireNonNull(id, "id");
        roles = Set.copyOf(roles);
    }

    public static Principal of(String id, String... roles) {
        return new Principal(id, Set.of(roles));
    }

    public boolean hasRole(String role) {
        return roles.contains(role);
    }

    public boolean hasAnyRole(Set<String> candidates) {
        return candidates.stream().anyMatch(roles::contains);
    }
}
