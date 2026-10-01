// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2"
)

// TestReorgReport exercises the read-only reorganization height difference
// report that is generated at the chain reorganization decision point.  It
// uses an in-memory short chain and a fork chain to test a successful
// reorganization as well as extending the same chain (which must not publish
// a report).
func TestReorgReport(t *testing.T) {
	// Create an in-memory short chain on the regression network with a
	// coinbase maturity of 1 block.
	chain, params, tearDown := utxoCacheTestChain("TestReorgReport")
	defer tearDown()

	tip := btcutil.NewBlock(params.GenesisBlock)
	tip.SetHeight(0)

	// A fresh chain that has never reorganalized must not have a report.
	if report := chain.LastReorgReport(); report != nil {
		t.Fatalf("expected no reorg report on a fresh chain, got %v",
			report)
	}

	// Build the main chain with 5 blocks on top of the genesis block.
	//
	// gen -> b1 -> b2 -> b3 -> b4 -> b5
	mainHashes, spendableOuts, err := addBlocks(5, chain, tip, nil)
	if err != nil {
		t.Fatalf("unable to build main chain: %v", err)
	}

	// Extending the same (main) chain must not publish a report.
	if report := chain.LastReorgReport(); report != nil {
		t.Fatalf("extending the main chain must not publish a reorg "+
			"report, got %v", report)
	}

	// Build a fork off the block at height 2 with 4 blocks so the fork tip
	// (height 6) has more cumulative work than the main chain tip (height
	// 5) and causes a reorganization.  The fork spends the outputs created
	// by the block at height 2 to ensure the fork blocks are unique.
	//
	//                   gen -> b1 -> b2 -> b3 -> b4 -> b5
	//                                \
	//                                 f3 -> f4 -> f5 -> f6
	forkBase, err := chain.BlockByHeight(2)
	if err != nil {
		t.Fatalf("unable to fetch fork base block: %v", err)
	}
	forkHashes, _, err := addBlocks(4, chain, forkBase, spendableOuts[1])
	if err != nil {
		t.Fatalf("unable to build fork chain: %v", err)
	}

	// The reorganization must have succeeded and published a report that
	// lists the common ancestor (the block at height 2) along with the 3
	// rolled back blocks (b3..b5) and the 4 attached blocks (f3..f6).
	report := chain.LastReorgReport()
	if report == nil {
		t.Fatal("expected a reorg report after a successful reorg")
	}
	if report.ForkHeight != 2 {
		t.Fatalf("unexpected fork height -- got %d, want 2",
			report.ForkHeight)
	}
	if report.ForkHash != *mainHashes[1] {
		t.Fatalf("unexpected fork hash -- got %v, want %v",
			report.ForkHash, mainHashes[1])
	}
	if report.DetachBlocks != 3 {
		t.Fatalf("unexpected detach count -- got %d, want 3",
			report.DetachBlocks)
	}
	if report.AttachBlocks != 4 {
		t.Fatalf("unexpected attach count -- got %d, want 4",
			report.AttachBlocks)
	}
	if report.Depth() != 7 {
		t.Fatalf("unexpected reorg depth -- got %d, want 7",
			report.Depth())
	}
	if report.HeightDelta() != 1 {
		t.Fatalf("unexpected height delta -- got %d, want 1",
			report.HeightDelta())
	}

	// The best chain must now be the fork chain.
	best := chain.BestSnapshot()
	if best.Height != 6 {
		t.Fatalf("unexpected best height -- got %d, want 6", best.Height)
	}
	if best.Hash != *forkHashes[3] {
		t.Fatalf("unexpected best hash -- got %v, want %v", best.Hash,
			forkHashes[3])
	}

	// The report handed out to callers is read-only: mutating the returned
	// copy must not affect the report kept by the chain.
	report.DetachBlocks = 999
	report.AttachBlocks = 999
	again := chain.LastReorgReport()
	if again.DetachBlocks != 3 || again.AttachBlocks != 4 {
		t.Fatalf("reorg report is not read-only -- got %v", again)
	}

	// Extending the new main chain (the same chain) must not overwrite the
	// report of the last reorganization.
	newTip, err := chain.BlockByHash(&best.Hash)
	if err != nil {
		t.Fatalf("unable to fetch new tip block: %v", err)
	}
	if _, _, err := addBlocks(1, chain, newTip, nil); err != nil {
		t.Fatalf("unable to extend the new main chain: %v", err)
	}
	again = chain.LastReorgReport()
	if again == nil || again.ForkHeight != 2 || again.DetachBlocks != 3 ||
		again.AttachBlocks != 4 {

		t.Fatalf("extending the same chain must not publish a new "+
			"report -- got %v", again)
	}
}

// TestReorgReportInvalidFork ensures that an invalid fork never publishes a
// successful reorganization report and that a reorganization decision with
// zero depth (nothing to detach or attach) never triggers a rollback report.
func TestReorgReportInvalidFork(t *testing.T) {
	// Create an in-memory short chain on the regression network with a
	// coinbase maturity of 1 block.
	chain, params, tearDown := utxoCacheTestChain("TestReorgReportInvalidFork")
	defer tearDown()

	tip := btcutil.NewBlock(params.GenesisBlock)
	tip.SetHeight(0)

	// Build the main chain with 5 blocks on top of the genesis block.
	_, spendableOuts, err := addBlocks(5, chain, tip, nil)
	if err != nil {
		t.Fatalf("unable to build main chain: %v", err)
	}

	// Build an invalid fork block off the block at height 2.  The block
	// spends an output that is only created by the main chain block at
	// height 4 and therefore does not exist from the viewpoint of the
	// fork.  It is accepted as a side chain block since it does not have
	// enough cumulative work to cause a reorganization yet.
	forkBase, err := chain.BlockByHeight(2)
	if err != nil {
		t.Fatalf("unable to fetch fork base block: %v", err)
	}
	badForkBlock, _, err := addBlock(chain, forkBase, spendableOuts[3])
	if err != nil {
		t.Fatalf("unable to add side chain block: %v", err)
	}

	// Extend the invalid fork with valid blocks so the fork tip (height 6)
	// has more cumulative work than the main chain tip (height 5).  The
	// reorganization must fail because the fork is invalid.  The block
	// that triggers the reorganization is processed directly so it is
	// still available to the test even though processing it fails.
	forkBlock := badForkBlock
	for i := 0; i < 2; i++ {
		forkBlock, _, err = addBlock(chain, forkBlock, nil)
		if err != nil {
			t.Fatalf("unable to extend fork chain: %v", err)
		}
	}
	forkTip, _, err := newBlock(chain, forkBlock, nil)
	if err != nil {
		t.Fatalf("unable to create fork tip block: %v", err)
	}
	if _, _, err := chain.ProcessBlock(forkTip, BFNone); err == nil {
		t.Fatal("expected an error when the invalid fork causes a " +
			"reorganization")
	}

	// The failed reorganization must not publish a success report and the
	// best chain must be untouched.
	if report := chain.LastReorgReport(); report != nil {
		t.Fatalf("failed reorg must not publish a success report, "+
			"got %v", report)
	}
	if best := chain.BestSnapshot(); best.Height != 5 {
		t.Fatalf("unexpected best height after failed reorg -- got "+
			"%d, want 5", best.Height)
	}

	// The failed reorganization marked the invalid fork block and its
	// descendants as invalid.  Extending the invalid fork once more is
	// rejected because the parent is known to be invalid, so the
	// reorganization decision has zero depth (there is nothing valid to
	// detach or attach) and must not trigger a rollback report either.
	if _, _, err := addBlock(chain, forkTip, nil); err == nil {
		t.Fatal("expected an error when extending a known invalid fork")
	}
	if report := chain.LastReorgReport(); report != nil {
		t.Fatalf("zero depth reorg must not trigger a rollback "+
			"report, got %v", report)
	}
	if best := chain.BestSnapshot(); best.Height != 5 {
		t.Fatalf("unexpected best height after zero depth reorg -- "+
			"got %d, want 5", best.Height)
	}
}
