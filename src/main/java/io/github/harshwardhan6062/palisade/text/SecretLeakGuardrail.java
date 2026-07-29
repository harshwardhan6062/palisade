package io.github.harshwardhan6062.palisade.text;

import java.util.List;

import io.github.harshwardhan6062.palisade.Context;
import io.github.harshwardhan6062.palisade.Decision;
import io.github.harshwardhan6062.palisade.Finding;
import io.github.harshwardhan6062.palisade.Finding.Severity;
import io.github.harshwardhan6062.palisade.Guardrail;
import io.github.harshwardhan6062.palisade.TextSubject;

/**
 * Detects credentials in text.
 *
 * <p>The realistic failure this guards against is not a model inventing a secret
 * — it's an agent that read a {@code .env}, a CI config, or a stack trace with a
 * tool, and is now about to quote it back. Any agent with filesystem or shell
 * access has a path from "secret at rest" to "secret in a chat transcript", and
 * that transcript usually ends up in logs and an eval dataset.
 *
 * <p>Default is {@link Mode#BLOCK} outbound. Redaction is offered, but blocking
 * is the right default: a redacted response still tells the caller a live
 * credential exists at that path, and the agent has already read it into a
 * context window you are probably persisting.
 *
 * <p>These patterns are prefix-shaped, so precision is high — {@code AKIA…} and
 * {@code sk-ant-…} do not occur by accident. Recall is the weak side: a bare
 * high-entropy password matches nothing here.
 */
public final class SecretLeakGuardrail implements Guardrail<TextSubject> {

    public enum Mode {
        BLOCK,
        REDACT,
        REPORT
    }

    private static final List<PatternRule> RULES = List.of(
            PatternRule.of("secret.private_key",
                    "-----BEGIN\\s+(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)?\\s*PRIVATE KEY-----",
                    Severity.CRITICAL, "PEM private key block"),
            PatternRule.of("secret.aws_access_key",
                    "\\b(?:A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}\\b",
                    Severity.CRITICAL, "AWS access key id"),
            PatternRule.of("secret.anthropic_key",
                    "\\bsk-ant-[A-Za-z0-9_\\-]{16,}",
                    Severity.CRITICAL, "Anthropic API key"),
            PatternRule.of("secret.openai_key",
                    "\\bsk-(?:proj-)?[A-Za-z0-9_\\-]{32,}",
                    Severity.CRITICAL, "OpenAI-style API key"),
            PatternRule.of("secret.github_token",
                    "\\bgh[pousr]_[A-Za-z0-9]{30,}\\b",
                    Severity.CRITICAL, "GitHub access token"),
            PatternRule.of("secret.slack_token",
                    "\\bxox[baprse]-[A-Za-z0-9\\-]{10,}",
                    Severity.CRITICAL, "Slack token"),
            PatternRule.of("secret.stripe_key",
                    "\\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\\b",
                    Severity.CRITICAL, "Stripe secret key"),
            PatternRule.of("secret.google_api_key",
                    "\\bAIza[0-9A-Za-z_\\-]{35}\\b",
                    Severity.HIGH, "Google API key"),
            PatternRule.of("secret.jwt",
                    "\\beyJ[A-Za-z0-9_\\-]{8,}\\.[A-Za-z0-9_\\-]{8,}\\.[A-Za-z0-9_\\-]{8,}",
                    Severity.HIGH, "JSON web token"),
            PatternRule.of("secret.assigned_credential",
                    "(?i)\\b(?:api[_\\-]?key|secret|passwd|password|token|credential)\\s*[=:]\\s*"
                            + "[\"']?[A-Za-z0-9/+_\\-]{16,}[\"']?",
                    Severity.HIGH, "credential-shaped assignment"));

    private final Mode mode;

    public SecretLeakGuardrail(Mode mode) {
        this.mode = java.util.Objects.requireNonNull(mode, "mode");
    }

    public static SecretLeakGuardrail defaults() {
        return new SecretLeakGuardrail(Mode.BLOCK);
    }

    @Override
    public String name() {
        return "secret-leak";
    }

    @Override
    public Decision inspect(TextSubject subject, Context context) {
        var matches = PatternRule.scan(subject.text(), RULES);
        if (matches.isEmpty()) {
            return Decision.allow();
        }
        List<Finding> findings = PatternRule.findings(matches);
        String kinds = matches.stream()
                .map(m -> m.rule().id())
                .distinct()
                .sorted()
                .reduce((a, b) -> a + ", " + b)
                .orElse("unknown");

        return switch (mode) {
            case REPORT -> Decision.allowWith(findings);
            case REDACT -> new Decision.Rewrite(
                    PatternRule.redact(subject.text(), matches), findings);
            case BLOCK -> new Decision.Block(
                    "response withheld: appears to contain a credential (%s)".formatted(kinds),
                    findings);
        };
    }

    public static List<PatternRule> rules() {
        return RULES;
    }

    public Mode mode() {
        return mode;
    }
}
