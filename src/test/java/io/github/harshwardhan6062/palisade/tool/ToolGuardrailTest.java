package io.github.harshwardhan6062.palisade.tool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.harshwardhan6062.palisade.Context;
import io.github.harshwardhan6062.palisade.Decision;
import io.github.harshwardhan6062.palisade.Principal;
import io.github.harshwardhan6062.palisade.ToolCall;

class ToolGuardrailTest {

    private static final Context ANON = Context.anonymous();

    @Nested
    @DisplayName("ToolPolicyGuardrail")
    class Policy {

        @Test
        @DisplayName("denies by default — an unlisted tool is refused, not permitted")
        void deniesByDefault() {
            var decision = ToolPolicyGuardrail.denyAll().inspect(ToolCall.of("anything"), ANON);
            assertInstanceOf(Decision.Block.class, decision);
        }

        @Test
        void allowsExplicitlyListedTools() {
            var rail = ToolPolicyGuardrail.builder().allow("read_file").build();
            assertInstanceOf(Decision.Allow.class, rail.inspect(ToolCall.of("read_file"), ANON));
            assertInstanceOf(Decision.Block.class, rail.inspect(ToolCall.of("write_file"), ANON));
        }

        @Test
        @DisplayName("globs match a prefix but stay anchored")
        void globsAreAnchored() {
            var rail = ToolPolicyGuardrail.builder().allow("read_*").build();
            assertInstanceOf(Decision.Allow.class, rail.inspect(ToolCall.of("read_file"), ANON));
            assertInstanceOf(Decision.Allow.class, rail.inspect(ToolCall.of("read_"), ANON));
            assertInstanceOf(Decision.Block.class, rail.inspect(ToolCall.of("unsafe_read_file"), ANON),
                    "an unanchored glob would wrongly permit this");
        }

        @Test
        @DisplayName("regex metacharacters in a tool name are literal, not patterns")
        void metacharactersAreQuoted() {
            var rail = ToolPolicyGuardrail.builder().allow("get.data").build();
            assertInstanceOf(Decision.Allow.class, rail.inspect(ToolCall.of("get.data"), ANON));
            assertInstanceOf(Decision.Block.class, rail.inspect(ToolCall.of("getXdata"), ANON),
                    "'.' must not act as a regex wildcard");
        }

        @Test
        @DisplayName("first matching rule wins, so order is the config")
        void firstMatchWins() {
            var rail = ToolPolicyGuardrail.builder()
                    .deny("delete_everything")
                    .allow("delete_*")
                    .build();
            assertInstanceOf(Decision.Block.class, rail.inspect(ToolCall.of("delete_everything"), ANON));
            assertInstanceOf(Decision.Allow.class, rail.inspect(ToolCall.of("delete_one"), ANON));
        }

        @Test
        void requireApprovalEscalates() {
            var rail = ToolPolicyGuardrail.builder().requireApproval("write_*").build();
            assertInstanceOf(Decision.NeedsApproval.class, rail.inspect(ToolCall.of("write_file"), ANON));
        }

        @Test
        @DisplayName("role-scoped rules only match callers holding the role")
        void roleScopedRules() {
            var rail = ToolPolicyGuardrail.builder()
                    .allowForRoles("admin_*", Set.of("admin"))
                    .build();

            var admin = Context.of(Principal.of("u1", "admin"));
            var user = Context.of(Principal.of("u2", "engineer"));

            assertInstanceOf(Decision.Allow.class, rail.inspect(ToolCall.of("admin_reset"), admin));
            assertInstanceOf(Decision.Block.class, rail.inspect(ToolCall.of("admin_reset"), user),
                    "falls through the role-scoped rule to the deny default");
        }

        @Test
        @DisplayName("switching the default to ALLOW turns it into a blocklist")
        void defaultPolicyCanBeInverted() {
            var rail = ToolPolicyGuardrail.builder()
                    .deny("dangerous_*")
                    .defaultPolicy(ToolPolicyGuardrail.Policy.ALLOW)
                    .build();
            assertInstanceOf(Decision.Block.class, rail.inspect(ToolCall.of("dangerous_op"), ANON));
            assertInstanceOf(Decision.Allow.class, rail.inspect(ToolCall.of("benign"), ANON));
        }
    }

    @Nested
    @DisplayName("ToolArgumentGuardrail")
    class Arguments {

        private final ToolArgumentGuardrail rail = ToolArgumentGuardrail.builder()
                .allowRoot(Path.of("/workspace"))
                .build();

        @Test
        void allowsPathsInsideTheRoot() {
            var call = new ToolCall("read_file", Map.of("path", "/workspace/src/main.java"));
            assertInstanceOf(Decision.Allow.class, rail.inspect(call, ANON));
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "/workspace/../etc/passwd",
                "/workspace/./../../root/.ssh/id_rsa",
                "/etc/shadow",
                "/workspace/a/b/../../../secrets.env"
        })
        @DisplayName("blocks paths that resolve outside the root, however they're spelled")
        void blocksEscapes(String path) {
            var call = new ToolCall("read_file", Map.of("path", path));
            assertInstanceOf(Decision.Block.class, rail.inspect(call, ANON),
                    () -> "expected a block for: " + path);
        }

        @Test
        @DisplayName("normalisation happens before the check, so a benign '..' is fine")
        void benignDotDotIsAllowed() {
            var call = new ToolCall("read_file", Map.of("path", "/workspace/a/../b/file.txt"));
            assertInstanceOf(Decision.Allow.class, rail.inspect(call, ANON),
                    "this resolves to /workspace/b/file.txt and is contained");
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://localhost:8080/admin",
                "http://127.0.0.1/",
                "http://10.0.0.5/internal",
                "http://192.168.1.1/router",
                "http://metadata.google.internal/computeMetadata/v1/"
        })
        @DisplayName("blocks internal and metadata addresses")
        void blocksSsrf(String url) {
            var call = new ToolCall("fetch_url", Map.of("url", url));
            assertInstanceOf(Decision.Block.class, rail.inspect(call, ANON),
                    () -> "expected a block for: " + url);
        }

        @Test
        void allowsPublicUrls() {
            var call = new ToolCall("fetch_url", Map.of("url", "https://api.example.com/v1/items"));
            assertInstanceOf(Decision.Allow.class, rail.inspect(call, ANON));
        }

        @Test
        @DisplayName("non-HTTP schemes escalate")
        void nonHttpSchemeEscalates() {
            var call = new ToolCall("fetch_url", Map.of("url", "file:///etc/passwd"));
            var decision = rail.inspect(call, ANON);
            assertTrue(decision instanceof Decision.NeedsApproval
                    || decision instanceof Decision.Block);
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "rm -rf /",
                "rm -fr node_modules",
                "DROP TABLE users",
                "DELETE FROM accounts",
                "UPDATE users SET admin = true",
                "git push --force origin main",
                "git reset --hard HEAD~5",
                "chmod -R 777 /",
                "mkfs.ext4 /dev/sda1",
                "dd if=/dev/zero of=/dev/sda"
        })
        @DisplayName("blocks destructive operations")
        void blocksDestructive(String command) {
            var call = new ToolCall("run_shell", Map.of("command", command));
            assertInstanceOf(Decision.Block.class, rail.inspect(call, ANON),
                    () -> "expected a block for: " + command);
        }

        @Test
        @DisplayName("a qualified UPDATE is not treated as unbounded")
        void qualifiedUpdateAllowed() {
            var call = new ToolCall("run_query",
                    Map.of("command", "UPDATE users SET name = 'x' WHERE id = 7"));
            assertInstanceOf(Decision.Allow.class, rail.inspect(call, ANON));
        }

        @Test
        @DisplayName("shell metacharacters escalate for review")
        void shellMetacharactersEscalate() {
            var call = new ToolCall("run_shell", Map.of("command", "ls -la; whoami"));
            var decision = rail.inspect(call, ANON);
            assertTrue(decision instanceof Decision.NeedsApproval
                    || decision instanceof Decision.Block);
        }

        @Test
        void allowsOrdinaryCommands() {
            var call = new ToolCall("run_shell", Map.of("command", "ls -la /workspace"));
            assertInstanceOf(Decision.Allow.class, rail.inspect(call, ANON));
        }

        @Test
        @DisplayName("individual checks can be turned off")
        void checksAreIndependentlyDisableable() {
            var lenient = ToolArgumentGuardrail.builder()
                    .checkDestructive(false)
                    .checkShell(false)
                    .checkSsrf(false)
                    .build();
            var call = new ToolCall("run_shell", Map.of("command", "rm -rf /"));
            assertInstanceOf(Decision.Allow.class, lenient.inspect(call, ANON));
        }
    }

    @Nested
    @DisplayName("RateLimitGuardrail")
    class RateLimit {

        @Test
        @DisplayName("permits a burst up to capacity, then blocks")
        void burstThenBlock() {
            var clock = new AtomicLong(0);
            var rail = new RateLimitGuardrail(3, 1.0, clock::get);
            var ctx = Context.of(Principal.of("u1"));

            for (int i = 0; i < 3; i++) {
                assertInstanceOf(Decision.Allow.class, rail.inspect(ToolCall.of("t"), ctx),
                        "call " + i + " should be within the burst");
            }
            assertInstanceOf(Decision.Block.class, rail.inspect(ToolCall.of("t"), ctx));
        }

        @Test
        @DisplayName("refills over time — verified with a fake clock, not a sleep")
        void refillsOverTime() {
            var clock = new AtomicLong(0);
            var rail = new RateLimitGuardrail(2, 10.0, clock::get);
            var ctx = Context.of(Principal.of("u1"));

            rail.inspect(ToolCall.of("t"), ctx);
            rail.inspect(ToolCall.of("t"), ctx);
            assertInstanceOf(Decision.Block.class, rail.inspect(ToolCall.of("t"), ctx));

            clock.addAndGet(200_000_000L); // 0.2s at 10/s == 2 tokens
            assertInstanceOf(Decision.Allow.class, rail.inspect(ToolCall.of("t"), ctx));
        }

        @Test
        @DisplayName("buckets are per principal, so one caller can't exhaust another")
        void bucketsArePerPrincipal() {
            var clock = new AtomicLong(0);
            var rail = new RateLimitGuardrail(1, 1.0, clock::get);
            var a = Context.of(Principal.of("a"));
            var b = Context.of(Principal.of("b"));

            assertInstanceOf(Decision.Allow.class, rail.inspect(ToolCall.of("t"), a));
            assertInstanceOf(Decision.Block.class, rail.inspect(ToolCall.of("t"), a));
            assertInstanceOf(Decision.Allow.class, rail.inspect(ToolCall.of("t"), b));
            assertEquals(2, rail.trackedPrincipals());
        }

        @Test
        @DisplayName("refill is capped at capacity — idle time doesn't bank unlimited credit")
        void refillCapsAtCapacity() {
            var clock = new AtomicLong(0);
            var rail = new RateLimitGuardrail(2, 1.0, clock::get);
            var ctx = Context.of(Principal.of("u1"));

            clock.addAndGet(3_600_000_000_000L); // an hour idle
            assertInstanceOf(Decision.Allow.class, rail.inspect(ToolCall.of("t"), ctx));
            assertInstanceOf(Decision.Allow.class, rail.inspect(ToolCall.of("t"), ctx));
            assertInstanceOf(Decision.Block.class, rail.inspect(ToolCall.of("t"), ctx),
                    "capacity is the ceiling regardless of idle duration");
        }

        @Test
        void rejectsNonsenseConfiguration() {
            org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                    () -> new RateLimitGuardrail(0, 1.0));
            org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                    () -> new RateLimitGuardrail(1, 0.0));
        }
    }
}
