package backups

import (
	"errors"
	"testing"
)

func TestCreatePlanParamsValidate(t *testing.T) {
	valid := CreatePlanParams{
		ProjectID:       "p1",
		ServerID:        "s1",
		Name:            "Nightly",
		Slug:            "nightly",
		ScopeType:       ScopeProject,
		DestinationType: DestLocal,
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("valid params rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(p *CreatePlanParams)
	}{
		{"missing project", func(p *CreatePlanParams) { p.ProjectID = "" }},
		{"missing server", func(p *CreatePlanParams) { p.ServerID = "" }},
		{"bad slug (hyphen)", func(p *CreatePlanParams) { p.Slug = "bad-slug" }},
		{"bad slug (uppercase)", func(p *CreatePlanParams) { p.Slug = "BadSlug" }},
		{"slug too short", func(p *CreatePlanParams) { p.Slug = "x" }},
		{"empty name", func(p *CreatePlanParams) { p.Name = "" }},
		{"bad scope", func(p *CreatePlanParams) { p.ScopeType = "mailbox" }},
		{"bad destination", func(p *CreatePlanParams) { p.DestinationType = "ftp" }},
	}
	for _, tc := range cases {
		p := valid
		tc.mutate(&p)
		if err := p.validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", tc.name, err)
		}
	}
}

func TestCreateRunParamsValidate(t *testing.T) {
	valid := CreateRunParams{
		ProjectID:       "p1",
		ServerID:        "s1",
		Trigger:         TriggerManual,
		RequestedByType: "user",
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("valid params rejected: %v", err)
	}

	bad := valid
	bad.Trigger = "hourly"
	if err := bad.validate(); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad trigger: got %v, want ErrInvalid", err)
	}

	bad = valid
	bad.RequestedByType = "robot"
	if err := bad.validate(); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad requested_by_type: got %v, want ErrInvalid", err)
	}
}

func TestPlanLivePredicate(t *testing.T) {
	p := Plan{}
	if !p.Live() {
		t.Error("zero plan should be live (no DeletedAt)")
	}
}
