package hostperm

import "testing"

func TestEvaluateHasRequiredRows(t *testing.T) {
	r := Evaluate()
	if len(r.Items) == 0 {
		t.Fatal("empty catalog")
	}
	var spool bool
	for _, it := range r.Items {
		if it.ID == IDSpool {
			spool = true
			if !it.Required {
				t.Fatal("spool must be required")
			}
		}
		if it.ID == "" || it.Title == "" {
			t.Fatalf("incomplete item %+v", it)
		}
	}
	if !spool {
		t.Fatal("missing spool row")
	}
}

func TestIsGrantID(t *testing.T) {
	if !IsGrantID(IDFDA) || !IsGrantID(IDFirewall) || !IsGrantID(IDCaps) {
		t.Fatal("grant ids")
	}
	if IsGrantID(IDBootStart) || IsGrantID(IDSpool) || IsGrantID(IDService) || IsGrantID(IDLoginUI) {
		t.Fatal("persistence is not a grant")
	}
}

func TestPromptItemsIncludesLogin(t *testing.T) {
	if !IsPromptID(IDFDA) || !IsPromptID(IDLoginUI) {
		t.Fatal("FDA and login items must be promptable")
	}
	if IsPromptID(IDBootStart) || IsPromptID(IDSpool) {
		t.Fatal("boot/spool stay on preflight")
	}
	r := Report{Items: []Item{
		{ID: IDFDA, Required: true, Status: StatusAction},
		{ID: IDLoginUI, Required: false, Status: StatusAction},
		{ID: IDSpool, Required: true, Status: StatusOK},
	}}
	got := PromptItems(r)
	if len(got) != 2 || got[0].ID != IDFDA || got[1].ID != IDLoginUI {
		t.Fatalf("%+v", got)
	}
	if !GrantsReady(Report{Items: r.Items[1:]}) {
		t.Fatal("optional login item must not block Start")
	}
}

func TestGrantsReadyIgnoresBoot(t *testing.T) {
	r := Report{Items: []Item{
		{ID: IDFDA, Required: true, Status: StatusOK},
		{ID: IDBootStart, Required: true, Status: StatusAction},
		{ID: IDSpool, Required: true, Status: StatusFail},
	}}
	if !GrantsReady(r) {
		t.Fatal("boot/spool must not block OS grants")
	}
	r.Items[0].Status = StatusAction
	if GrantsReady(r) {
		t.Fatal("FDA action must block")
	}
}

func TestRequiredIDs(t *testing.T) {
	r := Report{Items: []Item{
		{ID: "a", Required: true, Status: StatusOK},
		{ID: "b", Required: true, Status: StatusAction},
		{ID: "c", Required: false, Status: StatusFail},
	}}
	got := RequiredIDs(r)
	if len(got) != 1 || got[0] != "b" {
		t.Fatalf("%v", got)
	}
}

func TestSensorBinaryHintNonEmpty(t *testing.T) {
	if SensorBinaryHint() == "" {
		t.Fatal("empty hint")
	}
}
