# Hadrian LLM-assisted planner (agent reference)

Relocated from `AGENTS.md` (ENG-6805).

## LLM-Assisted Planner

The planner (`pkg/planner/`) uses an LLM to generate a prioritized attack plan before execution. Instead of brute-forcing every operation × template × role combination, the LLM analyzes the API spec and selects the most likely vulnerability targets. The planner flags are registered on the REST subcommand only (`pkg/runner/rest.go`); `test graphql` and `test grpc` do not expose them.

### Usage

```bash
# Plan + brute-force (recommended): LLM steps first, then remaining combos
./hadrian test rest --api spec.json --roles roles.yaml --auth auth.yaml --planner

# Plan only: run ONLY what the LLM chose (--planner-only requires --planner)
./hadrian test rest --api spec.json --roles roles.yaml --auth auth.yaml --planner --planner-only

# Steer the planner with custom context
./hadrian test rest ... --planner --planner-context "Focus on BOLA attacks on payment endpoints"
```

### Providers

Set the appropriate env var and use `--planner-provider`:

| Provider | Flag | Env Var | Default Model |
|----------|------|---------|---------------|
| OpenAI | `--planner-provider openai` (default) | `OPENAI_API_KEY` | gpt-4o |
| Anthropic | `--planner-provider anthropic` | `ANTHROPIC_API_KEY` | claude-sonnet-4-20250514 |
| Ollama | `--planner-provider ollama` | `OLLAMA_HOST` (optional) | llama3.2:latest |

These are the planner defaults (`pkg/planner/`). Triage (`--llm-provider`, `pkg/llm/`) defaults to `ollama`, and its Anthropic default model is `claude-sonnet-4-6`.

### Programmatic Usage

For platform integration, inject an `LLMClient` via `Config.PlannerLLMClient` (`pkg/runner/rest.go`; consumed in `pkg/runner/library.go`):

```go
config := runner.Config{
    PlannerEnabled:   true,
    PlannerLLMClient: myPlatformLLMClient, // implements planner.LLMClient
}
```
