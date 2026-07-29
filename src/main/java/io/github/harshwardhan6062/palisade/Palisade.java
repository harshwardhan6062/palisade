package io.github.harshwardhan6062.palisade;

import java.util.ArrayList;
import java.util.List;

import io.github.harshwardhan6062.palisade.audit.AuditSink;
import io.github.harshwardhan6062.palisade.text.LengthGuardrail;
import io.github.harshwardhan6062.palisade.text.PiiGuardrail;
import io.github.harshwardhan6062.palisade.text.PromptInjectionGuardrail;
import io.github.harshwardhan6062.palisade.text.SecretLeakGuardrail;
import io.github.harshwardhan6062.palisade.tool.RateLimitGuardrail;
import io.github.harshwardhan6062.palisade.tool.ToolArgumentGuardrail;
import io.github.harshwardhan6062.palisade.tool.ToolPolicyGuardrail;

/**
 * The three interception points of an agent turn, in one object.
 *
 * <p>An agent loop has exactly three moments where a host can intervene, and
 * this class names all three so none is quietly skipped:
 *
 * <pre>{@code
 * var palisade = Palisade.builder()
 *         .audit(new ConsoleAuditSink())
 *         .toolPolicy(ToolPolicyGuardrail.builder()
 *                 .allow("read_file", "search_*")
 *                 .requireApproval("write_file")
 *                 .build())
 *         .build();
 *
 * var ctx = Context.of(Principal.of("user-42", "engineer"));
 *
 * var in = palisade.checkInput(userMessage, ctx);
 * if (in.blocked()) return refuse(in.reason().orElseThrow());
 * String safeInput = in.subject().text();          // redactions applied
 *
 * var call = palisade.checkToolCall(ToolCall.of("read_file", "path", p), ctx);
 * if (call.blocked()) return toolError(call.reason().orElseThrow());
 * if (call.requiresApproval()) return askHuman(call);
 *
 * var out = palisade.checkOutput(modelText, ctx);
 * return out.blocked() ? genericError() : out.subject().text();
 * }</pre>
 *
 * <p>Note what the caller still has to do: this returns decisions, it does not
 * enforce them. Nothing here can intercept a tool the host forgets to route
 * through {@link #checkToolCall}. That is a deliberate boundary — a library that
 * silently wrapped execution would have to own your call path — but it means the
 * integration point is a place you can get wrong, so wire it once, centrally.
 */
public final class Palisade {

    private final TextPipeline inbound;
    private final TextPipeline outbound;
    private final ToolPipeline tools;

    private Palisade(TextPipeline inbound, TextPipeline outbound, ToolPipeline tools) {
        this.inbound = java.util.Objects.requireNonNull(inbound, "inbound");
        this.outbound = java.util.Objects.requireNonNull(outbound, "outbound");
        this.tools = java.util.Objects.requireNonNull(tools, "tools");
    }

    /** User (or upstream) text on its way to the model. */
    public Outcome<TextSubject> checkInput(String text, Context context) {
        return inbound.run(TextSubject.inbound(text), context);
    }

    /** Model text on its way back to the caller. */
    public Outcome<TextSubject> checkOutput(String text, Context context) {
        return outbound.run(TextSubject.outbound(text), context);
    }

    /** A tool the model requested, before the host executes it. */
    public Outcome<ToolCall> checkToolCall(ToolCall call, Context context) {
        return tools.run(call, context);
    }

    public List<String> inboundRails() {
        return inbound.names();
    }

    public List<String> outboundRails() {
        return outbound.names();
    }

    public List<String> toolRails() {
        return tools.names();
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Secure-by-default configuration: length ceiling, injection detection, PII
     * redaction inbound; secret-leak blocking and PII redaction outbound;
     * deny-all tool policy with argument scanning and rate limiting.
     *
     * <p>The tool policy denies everything, so this is not drop-in usable — you
     * must name the tools you want. That friction is intentional; a default that
     * permitted tools would be the one setting most likely to be shipped
     * unexamined.
     */
    public static Palisade secureDefaults(AuditSink audit) {
        return builder().audit(audit).build();
    }

    public static final class Builder {
        private AuditSink audit = AuditSink.NONE;
        private final List<Guardrail<TextSubject>> inbound = new ArrayList<>();
        private final List<Guardrail<TextSubject>> outbound = new ArrayList<>();
        private final List<Guardrail<ToolCall>> tools = new ArrayList<>();
        private ToolPolicyGuardrail toolPolicy;
        private boolean defaultsApplied = true;

        public Builder audit(AuditSink audit) {
            this.audit = java.util.Objects.requireNonNull(audit, "audit");
            return this;
        }

        public Builder toolPolicy(ToolPolicyGuardrail policy) {
            this.toolPolicy = java.util.Objects.requireNonNull(policy, "policy");
            return this;
        }

        public Builder inbound(Guardrail<TextSubject> rail) {
            inbound.add(rail);
            return this;
        }

        public Builder outbound(Guardrail<TextSubject> rail) {
            outbound.add(rail);
            return this;
        }

        public Builder tool(Guardrail<ToolCall> rail) {
            tools.add(rail);
            return this;
        }

        /**
         * Build with only the rails explicitly added — no defaults.
         *
         * <p>Named awkwardly on purpose. An empty guardrail layer that reports
         * "allowed" for everything is worse than none at all, because it looks
         * like protection in a code review.
         */
        public Builder withoutDefaults() {
            this.defaultsApplied = false;
            return this;
        }

        public Palisade build() {
            var in = new ArrayList<Guardrail<TextSubject>>();
            var out = new ArrayList<Guardrail<TextSubject>>();
            var tl = new ArrayList<Guardrail<ToolCall>>();

            if (defaultsApplied) {
                // Order matters: cheap bound first, then detection, then redaction.
                in.add(LengthGuardrail.defaults());
                in.add(PromptInjectionGuardrail.defaults());
                in.add(PiiGuardrail.defaults());

                out.add(SecretLeakGuardrail.defaults());
                out.add(PiiGuardrail.defaults());

                tl.add(toolPolicy != null ? toolPolicy : ToolPolicyGuardrail.denyAll());
                tl.add(ToolArgumentGuardrail.defaults());
                tl.add(RateLimitGuardrail.defaults());
            } else if (toolPolicy != null) {
                tl.add(toolPolicy);
            }

            in.addAll(inbound);
            out.addAll(outbound);
            tl.addAll(tools);

            return new Palisade(
                    TextPipeline.of("text:INBOUND", audit, in),
                    TextPipeline.of("text:OUTBOUND", audit, out),
                    ToolPipeline.of(audit, tl));
        }
    }
}
