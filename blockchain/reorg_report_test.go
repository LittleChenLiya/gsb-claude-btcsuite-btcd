// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"testing"

	"github.com/btcsuite/btcd/blockchain/internal/testhelper"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
)

// reorgReportSink collects reorganization notifications published by the
// chain.  Notifications are delivered synchronously, so no locking is
// required.
type reorgReportSink struct {
	reports []*ReorganizationReport
}

func (s *reorgReportSink) callback(n *Notification) {
	if n.Type == NTReorganization {
		s.reports = append(s.reports, n.Data.(*ReorganizationReport))
	}
}

// disconnectedSink counts the number of blocks that are disconnected from the
// main chain.  It is used to verify the rollback depth during a reorg.
type disconnectedSink struct {
	count int
}

func (s *disconnectedSink) callback(n *Notification) {
	if n.Type == NTBlockDisconnected {
		s.count++
	}
}

// reorgTestChain creates a fresh in-memory chain using the regression test
// parameters with a coinbase maturity of one block and registers the provided
// notification sinks.  The returned teardown function must be called when the
// test is finished.
func reorgTestChain(t *testing.T, name string, sinks ...NotificationCallback) (
	*BlockChain, *chaincfg.Params, func()) {

	t.Helper()

	params := chaincfg.RegressionNetParams
	chain, tearDown, err := chainSetup(name, &params)
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	chain.TstSetCoinbaseMaturity(1)

	for _, sink := range sinks {
		chain.Subscribe(sink)
	}

	return chain, &params, tearDown
}

// TestReorganizationReportSuccessfulReorg verifies that a successful chain
// reorganization publishes a read-only height difference report listing the
// common ancestor and the number of blocks rolled back and connected.
//
// The test builds a short main chain and a longer fork chain in memory:
//
//	main:   genesis -> 1 -> 2 -> 3 -> 4
//	                      \-> 2a -> 3a -> 4a -> 5a
//
// When the fourth side block (5a) is processed, the side chain has more
// cumulative work than the main chain, so a reorganization occurs.  The report
// must show the fork at height 1, three blocks rolled back (2, 3, 4) and four
// blocks connected (2a, 3a, 4a, 5a).
func TestReorganizationReportSuccessfulReorg(t *testing.T) {
	reportSink := &reorgReportSink{}
	disconnectSink := &disconnectedSink{}
	chain, params, tearDown := reorgTestChain(t,
		"TestReorganizationReportSuccessfulReorg",
		reportSink.callback, disconnectSink.callback)
	defer tearDown()

	tip := btcutil.NewBlock(params.GenesisBlock)
	tip.SetHeight(0)

	// Build the main chain: heights 1 through 4.
	_, mainOuts, err := addBlocks(4, chain, tip, nil)
	if err != nil {
		t.Fatalf("failed to build main chain: %v", err)
	}

	// Capture the expected fork and old-best hashes before the reorg.
	forkBlock, err := chain.BlockByHeight(1)
	if err != nil {
		t.Fatalf("failed to fetch fork block: %v", err)
	}
	oldBestBlock, err := chain.BlockByHeight(4)
	if err != nil {
		t.Fatalf("failed to fetch old best block: %v", err)
	}

	// Build the fork chain from block 1: heights 2a through 5a (four blocks).
	// The fourth side block gives the fork chain more cumulative work than
	// the main chain, triggering the reorganization.
	b1, err := chain.BlockByHeight(1)
	if err != nil {
		t.Fatalf("failed to fetch block 1: %v", err)
	}
	sideHashes, _, err := addBlocks(4, chain, b1, mainOuts[0])
	if err != nil {
		t.Fatalf("failed to build fork chain: %v", err)
	}

	// Exactly one reorganization report must have been published.
	if len(reportSink.reports) != 1 {
		t.Fatalf("expected 1 reorganization report, got %d",
			len(reportSink.reports))
	}
	report := reportSink.reports[0]

	// Verify the common ancestor.
	if report.ForkHeight != 1 {
		t.Errorf("fork height: got %d, want 1", report.ForkHeight)
	}
	if !report.ForkHash.IsEqual(forkBlock.Hash()) {
		t.Errorf("fork hash: got %v, want %v", report.ForkHash,
			forkBlock.Hash())
	}

	// Verify the old best chain tip.
	if report.OldBestHeight != 4 {
		t.Errorf("old best height: got %d, want 4", report.OldBestHeight)
	}
	if !report.OldBestHash.IsEqual(oldBestBlock.Hash()) {
		t.Errorf("old best hash: got %v, want %v", report.OldBestHash,
			oldBestBlock.Hash())
	}

	// Verify the new best chain tip.  It must be the last block connected
	// to the new chain (side block 5a).
	newBest := chain.BestSnapshot()
	if report.NewBestHeight != newBest.Height {
		t.Errorf("new best height: got %d, want %d", report.NewBestHeight,
			newBest.Height)
	}
	if !report.NewBestHash.IsEqual(&newBest.Hash) {
		t.Errorf("new best hash: got %v, want %v", report.NewBestHash,
			newBest.Hash)
	}
	if !report.NewBestHash.IsEqual(sideHashes[3]) {
		t.Errorf("new best hash: got %v, want side block 5a %v",
			report.NewBestHash, sideHashes[3])
	}

	// Verify the rollback and connect counts.
	if report.DetachCount != 3 {
		t.Errorf("detach count: got %d, want 3", report.DetachCount)
	}
	if report.AttachCount != 4 {
		t.Errorf("attach count: got %d, want 4", report.AttachCount)
	}

	// The number of blocks actually disconnected from the main chain must
	// match the reported rollback depth.
	if disconnectSink.count != int(report.DetachCount) {
		t.Errorf("disconnected blocks: got %d, want %d",
			disconnectSink.count, report.DetachCount)
	}

	// The main chain must now be the fork chain at height 5.
	if newBest.Height != 5 {
		t.Errorf("best chain height: got %d, want 5", newBest.Height)
	}
}

// TestReorganizationReportIdenticalChain verifies that processing a chain
// that is identical to the current best chain does not trigger a
// reorganization and therefore publishes no report.  A reorg depth of zero
// means no blocks are rolled back.
func TestReorganizationReportIdenticalChain(t *testing.T) {
	reportSink := &reorgReportSink{}
	disconnectSink := &disconnectedSink{}
	chain, params, tearDown := reorgTestChain(t,
		"TestReorganizationReportIdenticalChain",
		reportSink.callback, disconnectSink.callback)
	defer tearDown()

	tip := btcutil.NewBlock(params.GenesisBlock)
	tip.SetHeight(0)

	// Build the main chain: heights 1 through 3.
	_, _, err := addBlocks(3, chain, tip, nil)
	if err != nil {
		t.Fatalf("failed to build main chain: %v", err)
	}

	// Processing the same blocks again must not trigger a reorganization.
	// The blocks already exist in the chain, so ProcessBlock returns a
	// duplicate block error.
	for height := int32(1); height <= 3; height++ {
		block, err := chain.BlockByHeight(height)
		if err != nil {
			t.Fatalf("failed to fetch block at height %d: %v", height, err)
		}
		_, _, err = chain.ProcessBlock(block, BFNone)
		if err == nil {
			t.Errorf("expected duplicate block error at height %d", height)
		}
	}

	// No reorganization report must have been published.
	if len(reportSink.reports) != 0 {
		t.Errorf("expected no reorganization reports, got %d",
			len(reportSink.reports))
	}

	// No blocks must have been disconnected (zero depth, no rollback).
	if disconnectSink.count != 0 {
		t.Errorf("expected no disconnected blocks, got %d",
			disconnectSink.count)
	}

	// The main chain must be unchanged at height 3.
	newBest := chain.BestSnapshot()
	if newBest.Height != 3 {
		t.Errorf("best chain height: got %d, want 3", newBest.Height)
	}
}

// TestReorganizationReportInvalidFork verifies that a reorganization that
// fails because the fork chain contains an invalid block does not publish a
// success report and leaves the main chain unchanged.
//
// The test builds a short main chain and a fork chain with an invalid block
// in memory:
//
//	main:   genesis -> 1 -> 2 -> 3
//	                      \-> 2a -> 3a(invalid) -> 4a
//
// When 4a is processed, the fork chain has more cumulative work, so a
// reorganization is attempted.  The reorg validation fails because block 3a
// is invalid (its coinbase overspends the allowed subsidy plus fees).  No
// success report is published and the main chain remains at height 3.
func TestReorganizationReportInvalidFork(t *testing.T) {
	reportSink := &reorgReportSink{}
	chain, params, tearDown := reorgTestChain(t,
		"TestReorganizationReportInvalidFork",
		reportSink.callback)
	defer tearDown()

	tip := btcutil.NewBlock(params.GenesisBlock)
	tip.SetHeight(0)

	// Build the main chain: heights 1 through 3.
	_, mainOuts, err := addBlocks(3, chain, tip, nil)
	if err != nil {
		t.Fatalf("failed to build main chain: %v", err)
	}

	b1, err := chain.BlockByHeight(1)
	if err != nil {
		t.Fatalf("failed to fetch block 1: %v", err)
	}

	// Build the first side block (2a), which is valid and spends block 1's
	// coinbase output.
	_, side2aOuts, err := addBlock(chain, b1, mainOuts[0])
	if err != nil {
		t.Fatalf("failed to build side block 2a: %v", err)
	}

	// Build the second side block (3a) with an inflated spend amount so that
	// its coinbase overspends the allowed subsidy plus fees.  The block is
	// added to the index as a side chain block but is not validated until a
	// reorganization is attempted.
	inflatedOuts := side2aOuts
	inflatedOuts[0].Amount += testhelper.LowFee
	side3a, _, err := addBlock(chain, b1, inflatedOuts)
	if err != nil {
		t.Fatalf("failed to build side block 3a: %v", err)
	}

	// Build the third side block (4a) on top of the invalid block 3a.  This
	// gives the fork chain more cumulative work than the main chain, so a
	// reorganization is attempted and fails during validation.
	_, _, err = addBlock(chain, side3a, nil)
	if err != nil {
		t.Fatalf("failed to build side block 4a: %v", err)
	}

	// No success report must have been published for the failed
	// reorganization.
	if len(reportSink.reports) != 0 {
		t.Errorf("expected no reorganization reports for invalid fork, got %d",
			len(reportSink.reports))
	}

	// The main chain must remain unchanged at height 3.
	newBest := chain.BestSnapshot()
	if newBest.Height != 3 {
		t.Errorf("best chain height: got %d, want 3", newBest.Height)
	}
}
