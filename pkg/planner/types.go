package planner

import (
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/roles"
	"github.com/praetorian-inc/hadrian/pkg/templates"
)

// PlannerInput is everything the planner needs to produce an attack plan.
type PlannerInput struct {
	Spec         *model.APISpec
	Roles        *roles.RoleConfig
	Templates    []*templates.CompiledTemplate
	PriorResults []*model.Finding
	Options      PlannerOptions
}

// PlannerOptions configures planner behavior.
type PlannerOptions struct {
	MaxSteps        int
	FocusCategories []string
	FocusEndpoints  []string
	CustomContext   string // Additional user-provided context appended to the prompt
}

// AttackPlan is the LLM's output: a flat ordered list of attack steps.
type AttackPlan struct {
	Steps     []AttackStep `json:"steps"`
	Reasoning string       `json:"reasoning"`
}

// AttackStep is a single test action the planner wants executed.
// The LLM reasons about WHAT to test, not HOW to send requests.
type AttackStep struct {
	ID              string            `json:"id"`
	Method          string            `json:"method"`
	Path            string            `json:"path"`
	TemplateID      string            `json:"template_id"`
	Parameter       string            `json:"parameter,omitempty"`
	AttackerRole    string            `json:"attacker_role"`
	VictimRole      string            `json:"victim_role,omitempty"`
	OOB             bool              `json:"oob,omitempty"`
	DependsOn       []string          `json:"depends_on,omitempty"`
	Extract         map[string]string `json:"extract,omitempty"`
	DetectionMethod string            `json:"detection_method,omitempty"`
	Rationale       string            `json:"rationale,omitempty"`
}
