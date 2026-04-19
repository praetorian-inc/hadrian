package planner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/praetorian-inc/hadrian/pkg/log"
)

// Planner produces an AttackPlan from the given input.
type Planner interface {
	Plan(ctx context.Context, input *PlannerInput) (*AttackPlan, error)
}

// LLMClient is the minimal LLM capability the planner needs.
// Any provider (OpenAI, Anthropic, Ollama) can implement this.
type LLMClient interface {
	Generate(ctx context.Context, prompt string) (string, error)
}

// llmPlanner uses an LLM to produce attack plans.
type llmPlanner struct {
	client LLMClient
}

// NewPlanner creates a Planner backed by the given LLM client.
func NewPlanner(client LLMClient) Planner {
	return &llmPlanner{client: client}
}

func (p *llmPlanner) Plan(ctx context.Context, input *PlannerInput) (*AttackPlan, error) {
	prompt := buildPrompt(input)

	log.Debug("Sending planning prompt to LLM (%d bytes)", len(prompt))

	raw, err := RetryGenerate(ctx, p.client, prompt)
	if err != nil {
		return nil, fmt.Errorf("LLM generation failed: %w", err)
	}

	plan, err := parsePlan(raw)
	if err != nil {
		preview := sanitizeForLog(raw, 200)
		log.Debug("Raw LLM response: %s", preview)
		return nil, fmt.Errorf("failed to parse LLM response into attack plan: %w", err)
	}

	plan = validatePlan(plan, input)

	return plan, nil
}

// parsePlan extracts an AttackPlan from the LLM's raw JSON response.
func parsePlan(raw string) (*AttackPlan, error) {
	raw = stripCodeFences(raw)

	// Try parsing as full AttackPlan first (includes empty steps arrays)
	var plan AttackPlan
	planErr := json.Unmarshal([]byte(raw), &plan)
	if planErr == nil {
		return &plan, nil
	}

	// Try parsing as bare array of steps
	var steps []AttackStep
	if err := json.Unmarshal([]byte(raw), &steps); err == nil {
		return &AttackPlan{Steps: steps}, nil
	}

	return nil, fmt.Errorf("could not parse LLM response as AttackPlan or []AttackStep: %w", planErr)
}

// stripCodeFences removes markdown code fences that LLMs sometimes wrap around JSON.
func stripCodeFences(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		// Remove opening fence (```json or ```)
		if idx := strings.Index(s, "\n"); idx != -1 {
			s = s[idx+1:]
		}
		// Remove closing fence
		if idx := strings.LastIndex(s, "```"); idx != -1 {
			s = s[:idx]
		}
		s = strings.TrimSpace(s)
	}
	return s
}

// validatePlan filters out steps that reference non-existent templates or roles.
func validatePlan(plan *AttackPlan, input *PlannerInput) *AttackPlan {
	templateIDs := make(map[string]bool)
	for _, t := range input.Templates {
		templateIDs[t.ID] = true
	}

	roleNames := make(map[string]bool)
	if input.Roles != nil {
		for _, r := range input.Roles.Roles {
			roleNames[r.Name] = true
		}
	}

	var valid []AttackStep
	for _, step := range plan.Steps {
		if !templateIDs[step.TemplateID] {
			log.Debug("Planner: dropping step %s — unknown template %q", step.ID, step.TemplateID)
			continue
		}
		if !roleNames[step.AttackerRole] {
			log.Debug("Planner: dropping step %s — unknown attacker role %q", step.ID, step.AttackerRole)
			continue
		}
		if step.VictimRole != "" && !roleNames[step.VictimRole] {
			log.Debug("Planner: dropping step %s — unknown victim role %q", step.ID, step.VictimRole)
			continue
		}
		valid = append(valid, step)
	}

	return &AttackPlan{
		Steps:     valid,
		Reasoning: plan.Reasoning,
	}
}

// sanitizeForLog strips control/ANSI characters and truncates for safe logging.
func sanitizeForLog(s string, maxLen int) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r != 127 {
			b.WriteRune(r)
		}
	}
	result := b.String()
	if len(result) > maxLen {
		result = result[:maxLen] + "..."
	}
	return result
}
