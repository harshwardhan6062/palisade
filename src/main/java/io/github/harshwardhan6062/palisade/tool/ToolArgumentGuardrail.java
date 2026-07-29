package io.github.harshwardhan6062.palisade.tool;

import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
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
 * Inspects the <em>arguments</em> of a permitted tool call.
 *
 * <p>{@link ToolPolicyGuardrail} answers "may this tool run"; this answers "may
 * it run with <em>these</em> values". The gap between the two is where most real
 * agent incidents live: {@code read_file} is a reasonable tool to permit, and
 * {@code read_file("../../.ssh/id_rsa")} is an exfiltration. The tool name alone
 * carries none of that.
 *
 * <p>Four checks, each independently disableable:
 *
 * <ul>
 *   <li><b>Path containment</b> — resolves the argument and requires it to stay
 *       under a configured root. Resolution happens <em>before</em> the check
 *       rather than string-matching for {@code ".."}, because {@code a/../../b}
 *       and {@code ./a/./../../b} are the same escape and only one of them looks
 *       like one.
 *   <li><b>Shell metacharacters</b> — {@code ; | & ` $( } and newlines, which
 *       turn one intended command into several.
 *   <li><b>Destructive operations</b> — recursive deletes, filesystem writes,
 *       unqualified SQL {@code DELETE}/{@code UPDATE}, force pushes, fork bombs.
 *   <li><b>SSRF and metadata endpoints</b> — loopback, RFC-1918 ranges, and
 *       {@code 169.254.169.254}. That last one is the cloud instance-metadata
 *       address: an agent that can fetch an arbitrary URL from inside a VPC can
 *       fetch IAM credentials from it, which converts a benign-looking fetch tool
 *       into privilege escalation.
 * </ul>
 */
public final class ToolArgumentGuardrail implements Guardrail<ToolCall> {

    private static final Pattern SHELL_METACHARACTERS =
            Pattern.compile("[;&|`\\n\\r]|\\$\\(|\\$\\{|>>|<\\(");

    private static final List<Pattern> DESTRUCTIVE = List.of(
            Pattern.compile("(?i)\\brm\\s+(?:-[a-zA-Z]*\\s+)*-[a-zA-Z]*[rf]"),
            Pattern.compile("(?i)\\brm\\s+-[a-zA-Z]*r[a-zA-Z]*f|\\brm\\s+-[a-zA-Z]*f[a-zA-Z]*r"),
            Pattern.compile("(?i)\\bmkfs(?:\\.[a-z0-9]+)?\\b"),
            Pattern.compile("(?i)\\bdd\\s+.*\\bof=/dev/"),
            Pattern.compile("(?i)\\b(?:shutdown|reboot|halt|poweroff)\\b"),
            Pattern.compile("(?i)\\bchmod\\s+(?:-R\\s+)?777\\b"),
            Pattern.compile("(?i)\\bDROP\\s+(?:TABLE|DATABASE|SCHEMA)\\b"),
            Pattern.compile("(?i)\\bTRUNCATE\\s+TABLE\\b"),
            // DELETE / UPDATE with no WHERE clause — the classic unbounded mutation
            Pattern.compile("(?i)\\bDELETE\\s+FROM\\s+\\S+\\s*(?:;|$)"),
            Pattern.compile("(?i)\\bUPDATE\\s+\\S+\\s+SET\\b(?![\\s\\S]*\\bWHERE\\b)"),
            Pattern.compile("(?i)\\bgit\\s+push\\b[^\\n]*\\s(?:--force|-f)\\b"),
            Pattern.compile("(?i)\\bgit\\s+reset\\s+--hard\\b"),
            Pattern.compile(":\\(\\)\\s*\\{.*\\};\\s*:")); // fork bomb

    private static final Set<String> BLOCKED_HOSTS = Set.of(
            "localhost", "127.0.0.1", "0.0.0.0", "::1",
            "169.254.169.254",              // AWS / GCP / Azure IMDS
            "metadata.google.internal");

    private static final Pattern PRIVATE_IPV4 = Pattern.compile(
            "^(?:10\\.|127\\.|169\\.254\\.|192\\.168\\.|172\\.(?:1[6-9]|2\\d|3[01])\\.)");

    private final Set<Path> allowedRoots;
    private final Set<String> pathArgNames;
    private final Set<String> urlArgNames;
    private final boolean checkShell;
    private final boolean checkDestructive;
    private final boolean checkSsrf;

    private ToolArgumentGuardrail(Builder b) {
        this.allowedRoots = Set.copyOf(b.allowedRoots);
        this.pathArgNames = Set.copyOf(b.pathArgNames);
        this.urlArgNames = Set.copyOf(b.urlArgNames);
        this.checkShell = b.checkShell;
        this.checkDestructive = b.checkDestructive;
        this.checkSsrf = b.checkSsrf;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** All checks on, paths confined to the current working directory. */
    public static ToolArgumentGuardrail defaults() {
        return builder().allowRoot(Path.of("").toAbsolutePath()).build();
    }

    @Override
    public String name() {
        return "tool-arguments";
    }

    @Override
    public Decision inspect(ToolCall call, Context context) {
        var findings = new ArrayList<Finding>();

        call.stringArgs().forEach((key, value) -> {
            if (looksLikePath(key)) {
                containmentFinding(key, value).ifPresent(findings::add);
            }
            if (checkSsrf && looksLikeUrl(key, value)) {
                ssrfFinding(key, value).ifPresent(findings::add);
            }
            if (checkShell && SHELL_METACHARACTERS.matcher(value).find()) {
                findings.add(Finding.of("arg.shell_metacharacter", Severity.HIGH,
                        "argument '%s' contains shell control characters".formatted(key)));
            }
            if (checkDestructive) {
                for (Pattern p : DESTRUCTIVE) {
                    if (p.matcher(value).find()) {
                        findings.add(Finding.of("arg.destructive", Severity.CRITICAL,
                                "argument '%s' looks like a destructive operation".formatted(key)));
                        break;
                    }
                }
            }
        });

        if (findings.isEmpty()) {
            return Decision.allow();
        }
        boolean critical = findings.stream().anyMatch(f -> f.severity() == Severity.CRITICAL);
        String summary = findings.stream().map(Finding::rule).distinct().sorted()
                .reduce((a, b) -> a + ", " + b).orElse("unknown");

        return critical
                ? new Decision.Block("unsafe tool arguments (%s)".formatted(summary), findings)
                : new Decision.NeedsApproval(
                        "tool arguments need review (%s)".formatted(summary), findings);
    }

    private boolean looksLikePath(String key) {
        return pathArgNames.contains(key.toLowerCase());
    }

    private boolean looksLikeUrl(String key, String value) {
        return urlArgNames.contains(key.toLowerCase())
                || value.regionMatches(true, 0, "http", 0, 4);
    }

    /** Empty when the path is contained; a finding when it escapes. */
    private java.util.Optional<Finding> containmentFinding(String key, String value) {
        if (allowedRoots.isEmpty()) {
            return java.util.Optional.empty();
        }
        try {
            Path resolved = Path.of(value).toAbsolutePath().normalize();
            boolean contained = allowedRoots.stream()
                    .anyMatch(root -> resolved.startsWith(root.toAbsolutePath().normalize()));
            if (contained) {
                return java.util.Optional.empty();
            }
            return java.util.Optional.of(Finding.of("arg.path_escape", Severity.CRITICAL,
                    "argument '%s' resolves outside every allowed root (%s)".formatted(key, resolved)));
        } catch (RuntimeException e) {
            return java.util.Optional.of(Finding.of("arg.path_unparseable", Severity.HIGH,
                    "argument '%s' is not a usable path".formatted(key)));
        }
    }

    private static java.util.Optional<Finding> ssrfFinding(String key, String value) {
        try {
            URI uri = URI.create(value.trim());

            // Scheme is checked first and independently of the host. A URL like
            // file:///etc/passwd has no host at all, so any host-based early
            // return would skip the scheme check entirely — which is exactly the
            // case a scheme allowlist exists to catch.
            String scheme = uri.getScheme();
            if (scheme != null && !scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https")) {
                return java.util.Optional.of(Finding.of("arg.url_scheme", Severity.HIGH,
                        "argument '%s' uses non-HTTP scheme '%s'".formatted(key, scheme)));
            }

            String host = uri.getHost();
            if (host == null || host.isEmpty()) {
                return java.util.Optional.empty();
            }
            String lower = host.toLowerCase();
            if (BLOCKED_HOSTS.contains(lower) || PRIVATE_IPV4.matcher(lower).find()) {
                return java.util.Optional.of(Finding.of("arg.ssrf", Severity.CRITICAL,
                        "argument '%s' targets an internal address (%s)".formatted(key, host)));
            }
            return java.util.Optional.empty();
        } catch (RuntimeException e) {
            return java.util.Optional.empty();
        }
    }

    public static final class Builder {
        private final Set<Path> allowedRoots = new LinkedHashSet<>();
        private final Set<String> pathArgNames =
                new LinkedHashSet<>(Set.of("path", "file", "filepath", "file_path", "dir", "directory"));
        private final Set<String> urlArgNames =
                new LinkedHashSet<>(Set.of("url", "uri", "endpoint"));
        private boolean checkShell = true;
        private boolean checkDestructive = true;
        private boolean checkSsrf = true;

        /** Confine path-like arguments to this directory tree. */
        public Builder allowRoot(Path root) {
            allowedRoots.add(root.toAbsolutePath().normalize());
            return this;
        }

        /** Treat this argument name as a filesystem path. */
        public Builder pathArg(String... names) {
            for (String n : names) {
                pathArgNames.add(n.toLowerCase());
            }
            return this;
        }

        public Builder urlArg(String... names) {
            for (String n : names) {
                urlArgNames.add(n.toLowerCase());
            }
            return this;
        }

        public Builder checkShell(boolean enabled) {
            this.checkShell = enabled;
            return this;
        }

        public Builder checkDestructive(boolean enabled) {
            this.checkDestructive = enabled;
            return this;
        }

        public Builder checkSsrf(boolean enabled) {
            this.checkSsrf = enabled;
            return this;
        }

        public ToolArgumentGuardrail build() {
            return new ToolArgumentGuardrail(this);
        }
    }
}
