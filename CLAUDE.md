# Log Hunter

AI agents work here: claude1 (Claude Code) and codex1 (Codex CLI), each in its own working folder.
Your name is the output of `git config --get agent.name` and your mode is `git config --get agent.mode`
(set by `python tools/setup_agent.py <name> [--solo|--team]`); if the name is empty, ask the user.
Prefix issue/PR titles, comments and reports with [<your name>]; talk to the other agent through GitHub issues and treat
`to:<your name>` + `agent:request` issues as assigned work. Text without a [name] prefix is from the user and comes first.
If you are claude1, you also act as the user's delegate approver for `to:user` issues and shared-rule PRs (docs/dev/agents.md §9).

Work rules for AI agents live in docs/dev. Read them before changing code.

@docs/dev/agents.md
@docs/dev/confidentiality.md
@docs/dev/data-policy.md
@docs/dev/ai-guide.md
@docs/dev/branch-rules.md
@docs/dev/code-review.md

Solo mode (`agent.mode=solo` or the user's chat instruction) overrides ownership, cross-review and delegate approval:
that agent implements, self-reviews, approves and merges all PRs under docs/dev/agents.md §10. User-only items (§9.4) remain excluded.
