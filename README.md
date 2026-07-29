# Palisade

**Guardrails for LLM agents on the JVM.** Inspect what goes into a model, what comes out of it, and — most importantly — what it is about to *do*.

[![CI](https://github.com/harshwardhan6062/palisade/actions/workflows/ci.yml/badge.svg)](https://github.com/harshwardhan6062/palisade/actions/workflows/ci.yml)
[![Java 21+](https://img.shields.io/badge/Java-21%2B-blue)](https://openjdk.org/projects/jdk/21/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Zero runtime dependencies. 105 tests. Java 21.

---

## Why

An agent loop has exactly three moments where a host can intervene:

```
user text ──► [ inbound ] ──► model ──► tool request ──► [ tool gate ] ──► execution
                                  │
                                  └──► model text ──► [ outbound ] ──► user
```

Most guardrail discussion focuses on the text boundaries. The tool gate matters more. Text rails are pattern- or classifier-based, so they are probabilistic and will eventually be paraphrased around. An agent that has no permission to call `delete_account` cannot be talked into deleting an account no matter how convincing the injected instruction is.

**Capability limits hold when detection fails.** Palisade covers all three points, but that asymmetry is the design's central claim.

## Install

Not published to Maven Central yet. Build locally:

```bash
git clone https://github.com/harshwardhan6062/palisade.git
cd palisade
mvn install
```

```xml
<dependency>
  <groupId>io.github.harshwardhan6062</groupId>
  <artifactId>palisade</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

## Quickstart

```java
var palisade = Palisade.builder()
        .audit(new ConsoleAuditSink())
        .toolPolicy(ToolPolicyGuardrail.builder()
                .allow("read_file", "search_*")
                .requireApproval("write_file")
                .build())
        .build();

var ctx = Context.of(Principal.of("user-42", "engineer"));

// 1. Inbound — before the model sees it
var in = palisade.checkInput(userMessage, ctx);
if (in.blocked()) {
    return refuse(in.reason().orElseThrow());
}
String safeInput = in.subject().text();   // PII already redacted

// 2. Tool gate — after the model asks, before you execute
var call = palisade.checkToolCall(ToolCall.of("read_file", "path", path), ctx);
if (call.blocked())          return toolError(call.reason().orElseThrow());
if (call.requiresApproval()) return escalateToHuman(call);

// 3. Outbound — before the user sees it
var out = palisade.checkOutput(modelText, ctx);
return out.blocked() ? genericError() : out.subject().text();
```

Every call returns an `Outcome` carrying the decision, the (possibly rewritten) subject, and a per-rail trail with timings and findings.

## Decisions

Four verdicts, in a `sealed interface` so a `switch` over them is exhaustive at compile time:

| Verdict | Meaning |
|---|---|
| `Allow` | Permitted. May still carry findings — "saw something, allowed it anyway". |
| `Rewrite` | Content modified, typically redaction. Chains through later rails. |
| `NeedsApproval` | Cannot be decided automatically. Escalate to a human. |
| `Block` | Refused. Short-circuits the pipeline. |

`NeedsApproval` is deliberately distinct from `Block`. "I won't do this" and "someone should look at this" need different handling, and collapsing them produces a layer that is either too permissive or too annoying to keep switched on.

## What's included

**Text rails**

| Rail | Does |
|---|---|
| `LengthGuardrail` | Character ceiling. Put it first — it bounds every later rail's worst case. |
| `PromptInjectionGuardrail` | Instruction override, forged role markers, prompt exfiltration, jailbreak framing, bidi/zero-width obfuscation, base64 payloads. |
| `PiiGuardrail` | Email, payment cards (Luhn-validated), SSN, Aadhaar, phone numbers, IPv4. Redact / block / report. |
| `SecretLeakGuardrail` | AWS, GitHub, Anthropic, OpenAI, Slack, Stripe, Google keys; PEM blocks; JWTs; credential-shaped assignments. |

**Tool rails**

| Rail | Does |
|---|---|
| `ToolPolicyGuardrail` | Allow / deny / require-approval by glob and caller role. **Denies by default.** |
| `ToolArgumentGuardrail` | Path containment, shell metacharacters, destructive operations, SSRF including cloud metadata endpoints. |
| `RateLimitGuardrail` | Per-principal token bucket. Catches runaway loops, which per-call rails structurally cannot see. |

**Audit** — `AuditSink` with bounded in-memory and console implementations. Every decision, allowed ones included, because you cannot safely tighten a rule you have never measured.

## Design decisions worth knowing

- **Fail closed.** A guardrail that throws is treated as a `Block`, never a pass. Rails run on adversarial input by definition, and hosts tend to catch-and-continue.
- **Deny by default.** A newly added tool with no policy rule is refused. A denied new tool is a bug report; a silently permitted one is an incident.
- **Tool rails never rewrite.** Silently editing the arguments of a requested action gives you a system where the model believes it did one thing and the host did another.
- **Rewrites chain.** Each rail inspects the previous rail's output, so a rail cannot be fooled by content an earlier rail already removed.
- **Order is the config.** Policy rules match top-to-bottom, first match wins — like a firewall rule set, not a specificity heuristic.
- **No runtime dependencies.** This sits in the request path of everything the agent does. Adding a transitive dependency tree to the component whose job is narrowing attack surface is the wrong trade.

Longer rationale, including the paths not taken, is in [DESIGN.md](DESIGN.md).

## Limitations

Read this part. A guardrail library that oversells itself is worse than none, because someone will rely on it.

- **Pattern matching has limited recall.** The text rails catch known shapes. A competent attacker paraphrases and gets through. This is not a tuning problem; it is a property of the approach. Layer a model-based classifier above these rails, and treat the tool policy as the control that actually contains a successful injection.
- **PII and injection patterns are English- and India/US-centric.** Other locales will need rules added.
- **Path containment does not resolve symlinks.** It normalises and compares against configured roots. A symlink inside an allowed root that points outside it will pass. Use OS-level confinement for untrusted code.
- **Rate limiting is in-process.** Behind multiple replicas each instance has its own buckets. The bucket logic ports to a shared store directly, but that is not included.
- **Nothing here enforces anything.** These are decisions; the host applies them. A tool that is not routed through `checkToolCall` is not protected. Wire the integration once, centrally.
- **v0.1.** The API will change.

## Building

```bash
mvn test        # 105 tests
mvn verify
```

Requires JDK 21+.

## Licence

MIT — see [LICENSE](LICENSE).
