# Design notes

Why Palisade is shaped the way it is, including the alternatives rejected and the known weaknesses. If you are evaluating this library, this file is more useful than the README.

---

## 1. Three interception points, unequal in value

An agent turn offers exactly three places a host can intervene: inbound text, the tool request, and outbound text. Palisade names all three so none gets skipped.

They are not equally valuable, and the asymmetry drove most other decisions.

Text rails are **detection**: probabilistic, tunable, and defeated by paraphrase. Tool rails are **capability limits**: deterministic, and they hold regardless of how the model was manipulated. If an injection succeeds and the model genuinely wants to exfiltrate a database, a deny-by-default tool policy stops it; a cleverer regex does not.

So: the tool policy is the load-bearing control, and the text rails are defence in depth around it. A library that shipped only text rails would be selling the weaker half.

## 2. `sealed interface Decision`, not an enum or a boolean

A boolean (`allowed`) can't carry a redacted rewrite or a reason. An enum can't carry per-verdict payloads. A sealed interface gives four verdicts that each hold exactly what they need, and makes a `switch` over them exhaustive **at compile time** — adding a fifth verdict becomes a compile error at every call site rather than a silently-unhandled case.

For a security component that property is worth the extra ceremony. The whole failure mode of guardrail code is the case nobody thought about.

**`NeedsApproval` is separate from `Block` on purpose.** Most libraries collapse these. "Refuse" and "ask a human" have different handling, different UX, and different audit meaning; merging them forces you to pick between a layer that blocks legitimate work and one that permits risky work.

**`Allow` carries findings.** Non-obvious but important: you need a record of "saw something suspicious, permitted it anyway" *before* you are confident enough to block on it. Without allowed-but-flagged data you can never measure a new rule's false-positive rate, so you can never safely tighten it — and an untunable guardrail layer gets switched off in week two. `PromptInjectionGuardrail.observeOnly()` and `ConsoleAuditSink.verbose()` exist for the same reason.

## 3. Fail closed

`Pipelines.run` catches `RuntimeException` from every rail and converts it to a `Block`. A rail that returns `null` is also a `Block`.

Guardrails run on adversarial input by definition. Some input will eventually hit a pathological regex path or an unexpected `URI` parse. If that exception propagates, the surrounding host almost always catches it at a request boundary and continues — meaning **a crash becomes a bypass**. Failing closed converts a availability bug into a correctness one, which is the right direction for this component.

One deliberate exception: a tool rail returning `Rewrite` throws `UnsupportedOperationException` and is *not* caught. That is a programmer error in a rail implementation, not adversarial input. Adversarial input fails closed; programmer error fails loud.

## 4. Deny by default

`ToolPolicyGuardrail`'s default policy is `DENY`, and `Palisade.secureDefaults()` is therefore not drop-in usable — you must name your tools.

That friction is the feature. Allowlists fail closed when someone adds a tool and forgets the rule: a denied new tool produces a bug report on day one, whereas a silently permitted one produces an incident later. `defaultPolicy(ALLOW)` exists for teams that want a blocklist, and its javadoc says plainly what it converts the rail into.

## 5. Order is the configuration

Policy rules are matched in declaration order, first match wins. Rejected alternative: longest-prefix or specificity-based matching.

Specificity heuristics read well in a single example and become unpredictable once rules overlap — you end up reasoning about which of two globs is "more specific" instead of reading the list. Firewall rule sets settled on ordered-first-match for the same reason. It makes `deny("delete_everything")` before `allow("delete_*")` mean exactly what it looks like.

Pipeline order is likewise the caller's. `LengthGuardrail` belongs first: it costs microseconds and, once it has run, every subsequent regex rail has a bounded worst case. A chain with no length bound at the front has no latency bound at all.

## 6. Rewrites chain; tool arguments never do

Text rails compose: each sees the previous rail's output, so a rail cannot be fooled by content an earlier rail already redacted. The final `Rewrite` verdict is rebuilt at the end of the pipeline so it carries the fully-rewritten text and the union of all findings, not just the first rail's — an easy bug to ship, since the intermediate decision looks correct in isolation.

Tool rails deliberately cannot rewrite. Quietly changing the arguments of an action the model requested produces a system whose behaviour can't be reconstructed from either side: the model's context says it read `/a`, the host read `/b`, and the audit log has to pick one. Allow, escalate, or refuse are the only honest verdicts.

## 7. Luhn validation is what makes the PII rail survivable

`\b(?:\d[ -]?){12,18}\d\b` matches order numbers, tracking IDs, and any long digit run. A card rail with that false-positive rate gets disabled within a week.

Validating the Luhn checksum before reporting turns it into a rule that fires on actual card numbers. This is the general lesson for pattern-based rails: **precision determines whether the rule survives contact with production**, and cheap structural validation buys more precision than more elaborate regex.

Similarly, the secret patterns are prefix-shaped (`AKIA…`, `ghp_…`, `sk-ant-…`) because those don't occur by accident. Their weakness is recall — a bare high-entropy password matches nothing — which is stated in the README rather than papered over.

## 8. Overlap resolution in redaction

Naively replacing matches one at a time corrupts offsets and can leave fragments of the original value behind — a 16-digit string matching both a card rule and a phone rule is the common case. `PatternRule.redact` sorts matches, lets higher severity win a conflict, and rebuilds the string once from non-overlapping spans.

This is the kind of detail that only shows up under overlapping rules, which is why there's a test asserting no stray digits survive.

## 9. Rate limiting is a token bucket, and it's the only stateful rail

Every other rail inspects one subject in isolation. A runaway agent loop — a model that misreads a tool result and retries forever — has no single objectionable call, so a stateless rail structurally cannot see it. Detecting that shape requires memory across calls.

Token bucket rather than a flat rate cap because agents are legitimately bursty: a fan-out of parallel reads is healthy. A flat cap blocks that while still permitting a slow infinite loop, which is exactly backwards.

The clock is injectable (`LongSupplier`) so refill behaviour is tested with a fake clock rather than `Thread.sleep`. Buckets are `synchronized` rather than lock-free: contention is per principal, the critical section is a few arithmetic operations, and correct-by-inspection beats clever here.

## 10. No runtime dependencies

Not asceticism. This component sits in the request path of everything the agent does, and its job is to narrow attack surface — adding a transitive dependency tree to it works against that, and a supply-chain issue in a logging library becomes a supply-chain issue in your security layer.

Consequence: `ConsoleAuditSink` writes to a `PrintStream` instead of using SLF4J. Bridging to a real logger is a three-line `AuditSink` implementation, which is the right place for that choice to live.

## 11. `Pipelines` is package-private

`TextPipeline` and `ToolPipeline` are two small concrete classes over one shared generic engine.

The rejected alternative was a single public `Pipeline<S extends Subject<S>>` with a recursive generic bound. It unifies the two, at the cost of every caller writing a self-referential type parameter and `ToolCall` having to implement a `withContent` method that throws. Two concrete classes and a hidden engine is less clever and easier to use; the generic machinery stays out of the public API entirely.

## 12. What this does not do

- **No model-based classification.** A local classifier would improve recall substantially and would also mean a model dependency, inference latency in the request path, and a second thing to evaluate. Out of scope for v0.1; the `Guardrail` interface is the extension point.
- **No enforcement.** Palisade returns decisions. A tool the host forgets to route through `checkToolCall` is unprotected. Wrapping execution would mean owning the caller's call path, which a guardrail library shouldn't; the cost is that the integration point is a place you can get wrong.
- **No sandboxing.** Deciding a shell command looks safe is not the same as running it safely. Pair this with OS-level confinement — container, seccomp, a microVM — for anything executing untrusted code.
- **No distributed state.** In-process rate limits only.
- **Path containment does not resolve symlinks.** Normalise-and-compare catches `../` escapes in every spelling; it does not catch a symlink inside an allowed root pointing out of it.

## 13. Testing approach

105 tests. Three things they try to do beyond line coverage:

1. **Assert the absence of false positives, not just the presence of true ones.** Every text rail has a parametrised set of benign inputs, including ones sharing vocabulary with attacks (`"Can you ignore the whitespace when parsing this CSV?"`). A detection rail's failure mode in production is over-firing.
2. **Assert semantics, not implementation.** Short-circuiting, rewrite chaining, fail-closed, per-rail timing, bounded audit with a visible drop count.
3. **Use a fake clock instead of sleeping**, so the rate-limit refill tests are deterministic and fast.

The SSRF scheme check exists in its current form because a test caught it: `URI.create("file:///etc/passwd").getHost()` returns `null`, so an early host-based return skipped the scheme check entirely — precisely the case a scheme allowlist is for. Scheme is now validated independently of host.
