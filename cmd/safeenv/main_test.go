package main

import (
	"context"
	"testing"
)

func TestConfirmer_Modes(t *testing.T) {
	ctx := context.Background()

	// default ("") dan "off" -> auto-approve.
	if !(&confirmer{mode: ""}).Confirm(ctx, "curl https://x", []string{"x"}) {
		t.Fatal("default harus auto-approve")
	}
	if !(&confirmer{mode: "off"}).Confirm(ctx, "cmd", nil) {
		t.Fatal("mode off harus auto-approve")
	}

	// deny -> selalu tolak.
	if (&confirmer{mode: "deny"}).Confirm(ctx, "curl https://x", []string{"x"}) {
		t.Fatal("mode deny harus menolak")
	}

	// elicit tanpa server ref -> fail-closed (tolak), tidak panic.
	if (&confirmer{mode: "elicit", srv: nil}).Confirm(ctx, "cmd", nil) {
		t.Fatal("mode elicit tanpa srv harus fail-closed (tolak)")
	}

	// confirmationOff: true untuk default/off, false untuk elicit/deny.
	if !(&confirmer{mode: ""}).confirmationOff() || !(&confirmer{mode: "off"}).confirmationOff() {
		t.Fatal("confirmationOff harus true untuk default/off")
	}
	if (&confirmer{mode: "elicit"}).confirmationOff() || (&confirmer{mode: "deny"}).confirmationOff() {
		t.Fatal("confirmationOff harus false untuk elicit/deny")
	}
}
