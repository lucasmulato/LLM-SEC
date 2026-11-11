# AGENT INSTRUCTIONS: TOKEN EFFICIENCY & QUALITY GATES

## 1. TOKEN SAVING RULES (STRICT CONTEXT BUDGET)
- **Compact Responses:** Do not repeat the prompt, echo file contents, or write unnecessary intros/outros. Jump directly to code changes and execution results.
- **Diff-Only Code Outputs:** When editing existing files, output ONLY line-level diffs or targeted code replacements instead of re-printing complete 500+ line files.
- **Targeted File Inspection:** Inspect specific line ranges or grep pattern matches instead of dumping full source files into context.
- **Batch Tool Calls:** Execute related file inspections, terminal commands, or branch operations in a single batched step whenever possible.

## 2. WORK QUALITY & RELIABILITY GATES
- **Zero Hallucination:** Rely strictly on local repo state and verified workspace dependencies. Do not guess API methods.
- **Fail-Fast Validation:** Run linter checks, type checks, or unit tests immediately after every file modification to catch errors instantly.
- **Modular Boundaries:** Keep functions focused, strictly typed, and isolated. Avoid monolithic functions and unnecessary external dependencies.
- **Clean Git State:** Work in isolated feature branches or Git worktrees (`branch` mode) to maintain a clean git history and fast rollbacks.
