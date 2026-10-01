// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mempool

import (
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// createDustSpendingTx creates a signed transaction that spends the provided
// output and sends the entire amount to a single 1-satoshi dust output
// (forfeiting the remainder as fees).  The transaction is well-formed and
// correctly signed, so it is only rejected by standardness checks once its
// parent becomes available.
func (p *poolHarness) createDustSpendingTx(input spendableOutput) (*btcutil.Tx, error) {
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: input.outPoint,
		Sequence:         wire.MaxTxInSequenceNum,
	})
	tx.AddTxOut(&wire.TxOut{
		PkScript: p.payScript,
		Value:    1,
	})

	sigScript, err := txscript.SignatureScript(tx, 0, p.payScript,
		txscript.SigHashAll, p.signKey, true)
	if err != nil {
		return nil, err
	}
	tx.TxIn[0].SignatureScript = sigScript

	return btcutil.NewTx(tx), nil
}

// assertOrphanRejectTrace checks that the most recent orphan rejection trace
// for the passed transaction matches the expected fields.
func assertOrphanRejectTrace(t *testing.T, mp *TxPool, hash chainhash.Hash,
	reason OrphanRejectReason, temporary bool, code wire.RejectCode,
	tag Tag) OrphanRejectTrace {

	t.Helper()

	trace, exists := mp.OrphanRejectTraceForTx(&hash)
	if !exists {
		t.Fatalf("expected an orphan rejection trace for tx %v, none "+
			"recorded", &hash)
	}
	if trace.Reason != reason {
		t.Fatalf("unexpected reject reason -- got %v, want %v",
			trace.Reason, reason)
	}
	if trace.Temporary != temporary {
		t.Fatalf("unexpected temporary flag -- got %v, want %v",
			trace.Temporary, temporary)
	}
	if trace.RejectCode != code {
		t.Fatalf("unexpected reject code -- got %v, want %v",
			trace.RejectCode, code)
	}
	if trace.Tag != tag {
		t.Fatalf("unexpected tag -- got %d, want %d", trace.Tag, tag)
	}
	if trace.Time.IsZero() {
		t.Fatalf("expected trace timestamp to be set")
	}
	return trace
}

// TestOrphanRejectTracing exercises the "orphan rejection tracing" added to
// orphan acceptance.  It constructs the missing-parent, parent-filled and
// policy rejection scenarios and verifies both the rejection traces and the
// resulting pool state.  In particular it ensures a temporarily missing parent
// is never misreported as a permanent invalidity while an orphan that fails
// validation once its parent arrives is reported as permanently invalid.
func TestOrphanRejectTracing(t *testing.T) {
	t.Parallel()

	const testTag Tag = 42

	// Scenario 1: missing parent with allowOrphan=false.  The rejection
	// must be traced as a temporary missing-parent rejection listing the
	// unknown parent, and neither pool may be modified.
	t.Run("missing_parent", func(t *testing.T) {
		harness, outputs, err := newPoolHarness(&chaincfg.MainNetParams)
		if err != nil {
			t.Fatalf("unable to create test pool: %v", err)
		}
		tc := &testContext{t, harness}
		mp := harness.txPool

		// Build a parent/child pair without processing either tx.
		chain, err := harness.CreateTxChain(outputs[0], 2)
		if err != nil {
			t.Fatalf("unable to create transaction chain: %v", err)
		}
		parent, child := chain[0], chain[1]

		// Reject the child since orphan acceptance is disabled.
		accepted, err := mp.ProcessTransaction(child, false, false,
			testTag)
		if err == nil {
			t.Fatalf("expected missing-parent rejection, got nil")
		}
		if len(accepted) != 0 {
			t.Fatalf("expected no accepted txns, got %d",
				len(accepted))
		}

		// Neither transaction is in the orphan or main pool.
		testPoolMembership(tc, child, false, false)
		testPoolMembership(tc, parent, false, false)

		// The trace must be marked temporary (missing parents), not
		// permanently invalid, and must name the missing parent.
		trace := assertOrphanRejectTrace(t, mp, *child.Hash(),
			OrphanRejectMissingParent, true, wire.RejectDuplicate,
			testTag)
		if len(trace.MissingParents) != 1 ||
			trace.MissingParents[0] != *parent.Hash() {

			t.Fatalf("unexpected missing parents %v, want [%v]",
				trace.MissingParents, parent.Hash())
		}

		// Only this single rejection should be on record.
		if traces := mp.OrphanRejectTraces(); len(traces) != 1 {
			t.Fatalf("expected 1 trace, got %d", len(traces))
		}
	})

	// Scenario 2: missing parent is filled afterwards.  The temporary
	// orphan must first be admitted to the orphan pool without any
	// rejection trace and must then move to the main pool once its parent
	// arrives, still without producing a rejection trace.
	t.Run("parent_filled", func(t *testing.T) {
		harness, outputs, err := newPoolHarness(&chaincfg.MainNetParams)
		if err != nil {
			t.Fatalf("unable to create test pool: %v", err)
		}
		tc := &testContext{t, harness}
		mp := harness.txPool

		chain, err := harness.CreateTxChain(outputs[0], 2)
		if err != nil {
			t.Fatalf("unable to create transaction chain: %v", err)
		}
		parent, child := chain[0], chain[1]

		// Child is admitted as a temporary orphan; no error and no
		// rejection trace.
		accepted, err := mp.ProcessTransaction(child, true, false,
			testTag)
		if err != nil {
			t.Fatalf("unexpected error admitting orphan: %v", err)
		}
		if len(accepted) != 0 {
			t.Fatalf("expected no accepted txns yet, got %d",
				len(accepted))
		}
		testPoolMembership(tc, child, true, false)
		if _, exists := mp.OrphanRejectTraceForTx(child.Hash()); exists {
			t.Fatalf("temporary orphan must not be traced as " +
				"rejected")
		}

		// Deliver the parent; both must end up in the main pool.
		accepted, err = mp.ProcessTransaction(parent, false, false,
			testTag)
		if err != nil {
			t.Fatalf("unexpected error processing parent: %v", err)
		}
		if len(accepted) != 2 {
			t.Fatalf("expected parent+child accepted, got %d",
				len(accepted))
		}
		testPoolMembership(tc, parent, false, true)
		testPoolMembership(tc, child, false, true)

		// No rejection trace must have been produced at any point; the
		// temporary orphan was never permanently invalid.
		if traces := mp.OrphanRejectTraces(); len(traces) != 0 {
			t.Fatalf("expected no rejection traces, got %d: %+v",
				len(traces), traces)
		}
	})

	// Scenario 3a: policy rejection due to orphan size limit.
	t.Run("policy_oversized", func(t *testing.T) {
		harness, outputs, err := newPoolHarness(&chaincfg.MainNetParams)
		if err != nil {
			t.Fatalf("unable to create test pool: %v", err)
		}
		tc := &testContext{t, harness}
		mp := harness.txPool

		// Shrink the allowed orphan size below the child's size.
		mp.cfg.Policy.MaxOrphanTxSize = 100

		chain, err := harness.CreateTxChain(outputs[0], 2)
		if err != nil {
			t.Fatalf("unable to create transaction chain: %v", err)
		}
		parent, child := chain[0], chain[1]

		_, err = mp.ProcessTransaction(child, true, false, testTag)
		if err == nil {
			t.Fatalf("expected oversized orphan to be rejected")
		}

		// Policy rejections are permanent, never "missing parent".
		trace := assertOrphanRejectTrace(t, mp, *child.Hash(),
			OrphanRejectPolicy, false, wire.RejectNonstandard,
			testTag)
		if !strings.Contains(trace.Detail, "larger than max allowed") {
			t.Fatalf("unexpected detail: %q", trace.Detail)
		}
		if len(trace.MissingParents) != 0 {
			t.Fatalf("policy trace must not list missing parents")
		}
		testPoolMembership(tc, child, false, false)
		testPoolMembership(tc, parent, false, false)
	})

	// Scenario 3b: policy rejection due to the orphan pool being disabled.
	t.Run("policy_disabled", func(t *testing.T) {
		harness, outputs, err := newPoolHarness(&chaincfg.MainNetParams)
		if err != nil {
			t.Fatalf("unable to create test pool: %v", err)
		}
		tc := &testContext{t, harness}
		mp := harness.txPool

		mp.cfg.Policy.MaxOrphanTxs = 0

		chain, err := harness.CreateTxChain(outputs[0], 2)
		if err != nil {
			t.Fatalf("unable to create transaction chain: %v", err)
		}
		parent, child := chain[0], chain[1]

		// Historical behavior: a disabled orphan pool silently drops
		// the tx (nil error), but the rejection is now traced.
		if _, err := mp.ProcessTransaction(child, true, false,
			testTag); err != nil {

			t.Fatalf("expected nil error for disabled orphan "+
				"pool, got %v", err)
		}

		trace := assertOrphanRejectTrace(t, mp, *child.Hash(),
			OrphanRejectPolicy, false, wire.RejectNonstandard,
			testTag)
		if !strings.Contains(trace.Detail, "disabled") {
			t.Fatalf("unexpected detail: %q", trace.Detail)
		}
		testPoolMembership(tc, child, false, false)
		testPoolMembership(tc, parent, false, false)
	})

	// Scenario 4 (boundary): an orphan that is valid while its parent is
	// missing but permanently fails validation once the parent arrives
	// must be traced as a permanent invalidity (not missing parent, not
	// temporary) and removed from the orphan pool, while the already
	// accepted parent remains untouched in the main pool.
	t.Run("invalid_once_parent_arrives", func(t *testing.T) {
		harness, outputs, err := newPoolHarness(&chaincfg.MainNetParams)
		if err != nil {
			t.Fatalf("unable to create test pool: %v", err)
		}
		tc := &testContext{t, harness}
		mp := harness.txPool

		// Create and admit a valid parent (not processed yet).
		parent, err := harness.CreateSignedTx(
			[]spendableOutput{outputs[0]}, 1, 1000, false)
		if err != nil {
			t.Fatalf("unable to create parent: %v", err)
		}
		parentOut := txOutToSpendableOut(parent, 0)

		// Child pays a dust output: correctly signed and well formed,
		// but non-standard.
		child, err := harness.createDustSpendingTx(parentOut)
		if err != nil {
			t.Fatalf("unable to create child: %v", err)
		}

		// While the parent is missing the child is a plain temporary
		// orphan: admitted, no rejection trace.
		if _, err := mp.ProcessTransaction(child, true, false,
			testTag); err != nil {

			t.Fatalf("unexpected error admitting orphan: %v", err)
		}
		testPoolMembership(tc, child, true, false)
		if _, exists := mp.OrphanRejectTraceForTx(child.Hash()); exists {
			t.Fatalf("temporary orphan must not be traced as " +
				"rejected while its parent is missing")
		}

		// Deliver the parent.  The child is now fully validated,
		// fails standardness, is removed from the orphan pool and
		// produces a permanent invalidity trace.
		accepted, err := mp.ProcessTransaction(parent, false, false,
			testTag)
		if err != nil {
			t.Fatalf("unexpected error processing parent: %v", err)
		}
		if len(accepted) != 1 {
			t.Fatalf("expected only the parent to be accepted, "+
				"got %d", len(accepted))
		}

		// Parent stays in the main pool; the child is gone from both
		// pools.
		testPoolMembership(tc, parent, false, true)
		testPoolMembership(tc, child, false, false)

		trace := assertOrphanRejectTrace(t, mp, *child.Hash(),
			OrphanRejectInvalid, false, wire.RejectDust,
			testTag)
		if !strings.Contains(strings.ToLower(trace.Detail), "dust") {
			t.Fatalf("expected dust-related detail, got %q",
				trace.Detail)
		}
		if len(trace.MissingParents) != 0 {
			t.Fatalf("invalidity trace must not list missing " +
				"parents")
		}
	})
}
