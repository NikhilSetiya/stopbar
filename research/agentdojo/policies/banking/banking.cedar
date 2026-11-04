// AgentDojo banking pilot policy, v1 (pre-registration §3.4 as amended by
// Amendment 2). Deliberately blunt: session-level taint, no argument
// inspection; the only blocking rule is tainted-state-change. Every rule is
// justified from tool definitions in README.md. No rule names an IBAN,
// amount, file, string or task.

@id("permit-declared-tools")
@message("Tool is declared in the frozen trust map")
permit (principal, action == Stopbar::Action::"tool_call", resource);

@id("tainted-state-change") @outcome("deny")
@message("State-changing tool called after this session read content not written by the user")
forbid (principal, action == Stopbar::Action::"tool_call", resource)
when { context.state_changing && context.taint.contains("untrusted_tool_output") };
