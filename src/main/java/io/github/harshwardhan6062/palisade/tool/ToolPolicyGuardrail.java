package io.github.harshwardhan6062.palisade.tool;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import io.github.harshwardhan6062.palisade.Context;
import io.github.harshwardhan6062.palisade.Decision;
import io.github.harshwardhan6062.palisade.Finding;
import io.github.harshwardhan6062.palisade.Finding.Severity;
import io.github.harshwardhan6062.palisade.Guardrail;
import io.github.harshwardhan6062.palisade.ToolCall;

/**
 * Decides whether a tool may run at all, by name and caller role.
 *
 * <p>This is the control that actually contains a successful prompt injection.
 * Detection rails are probabilistic and will eventually be paraphrased around;
 * an agent that has no permission to call {@code delete_account} cannot be
 * talked into deleting an account regardless of how convincing the injected text
 * is. Capability limits hold when detection fails, which is why this rail matters
 * more than the pattern-based ones even though it is far simpler.
 *
 * <p><b>The default policy is DENY.</b> Allowlists fail closed when someone adds
 * a tool and forgets to add a rule — a denied new tool is a bug report, whereas a
 * silently-permitted one is an incident. Patterns are matched in the order they
 * were declared and the first match wins, so the config reads top-to-bottom like
 * a firewall rule set rather than depending on specificity heuristics.
 */
public final class ToolPolicyGuardrail implements Guardrail<ToolCall> {

    public enum Policy {
        ALLOW,
        DENY,
        REQUIRE_APPROVAL
    }

    private record Rule(String glob, Pattern pattern, Policy policy, Set<String> roles) {
        boolean matches(String toolName, Context context) {
            if (!pattern.matcher(toolName).matches()) {
                return false;
            }
            return roles.isEmpty() || context.principal().hasAnyRole(roles);
        }
    }

    private final List<Rule> rules;
    private final Policy defaultPolicy;

    private ToolPolicyGuardrail(List<Rule> rules, Policy defaultPolicy) {
        this.rules = List.copyOf(rules);
        this.defaultPolicy = java.util.Objects.requireNonNull(defaultPolicy, "defaultPolicy");
    }

    @Override
    public String name() {
        return "tool-policy";
    }

    @Override
    public Decision inspect(ToolCall call, Context context) {
        for (Rule rule : rules) {
            if (rule.matches(call.name(), context)) {
                return apply(rule.policy(), call, rule.glob());
            }
        }
        return apply(defaultPolicy, call, "<default>");
    }

    private Decision apply(Policy policy, ToolCall call, String matchedBy) {
        return switch (policy) {
            case ALLOW -> Decision.allow();
            case REQUIRE_APPROVAL -> new Decision.NeedsApproval(
                    "tool '%s' requires human approval".formatted(call.name()),
                    List.of(Finding.of("tool.approval_required", Severity.MEDIUM,
                            "matched policy rule '%s'".formatted(matchedBy))));
            case DENY -> new Decision.Block(
                    "tool '%s' is not permitted for this caller".formatted(call.name()),
                    List.of(Finding.of("tool.denied", Severity.HIGH,
                            "matched policy rule '%s'".formatted(matchedBy))));
        };
    }

    public Policy defaultPolicy() {
        return defaultPolicy;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Fail-closed default: everything not explicitly allowed is denied. */
    public static ToolPolicyGuardrail denyAll() {
        return builder().build();
    }

    public static final class Builder {
        private final List<Rule> rules = new ArrayList<>();
        private Policy defaultPolicy = Policy.DENY;

        /** Permit tools matching {@code glob} ({@code *} is a wildcard). */
        public Builder allow(String... globs) {
            return add(Policy.ALLOW, Set.of(), globs);
        }

        public Builder deny(String... globs) {
            return add(Policy.DENY, Set.of(), globs);
        }

        public Builder requireApproval(String... globs) {
            return add(Policy.REQUIRE_APPROVAL, Set.of(), globs);
        }

        /** Permit {@code glob} only for callers holding one of {@code roles}. */
        public Builder allowForRoles(String glob, Set<String> roles) {
            if (roles.isEmpty()) {
                throw new IllegalArgumentException("roles must not be empty; use allow() instead");
            }
            return add(Policy.ALLOW, roles, glob);
        }

        /**
         * What happens when no rule matches. Changing this to {@code ALLOW}
         * converts the rail from an allowlist to a blocklist and means a newly
         * added tool is permitted by default — do it deliberately or not at all.
         */
        public Builder defaultPolicy(Policy policy) {
            this.defaultPolicy = java.util.Objects.requireNonNull(policy, "policy");
            return this;
        }

        private Builder add(Policy policy, Set<String> roles, String... globs) {
            for (String glob : globs) {
                rules.add(new Rule(glob, globToPattern(glob), policy, Set.copyOf(roles)));
            }
            return this;
        }

        public ToolPolicyGuardrail build() {
            return new ToolPolicyGuardrail(rules, defaultPolicy);
        }
    }

    /**
     * Translate a {@code *}-glob to an anchored regex.
     *
     * <p>Everything except {@code *} is quoted, so a tool name containing regex
     * metacharacters can't smuggle in matching behaviour. Anchored, so
     * {@code read_*} does not match {@code unsafe_read_all}.
     */
    static Pattern globToPattern(String glob) {
        var sb = new StringBuilder("^");
        for (String segment : glob.split("\\*", -1)) {
            sb.append(Pattern.quote(segment)).append(".*");
        }
        sb.setLength(sb.length() - 2); // drop the trailing ".*" added after the last segment
        return Pattern.compile(sb.append('$').toString());
    }
}
