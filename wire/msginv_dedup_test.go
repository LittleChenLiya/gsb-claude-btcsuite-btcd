// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
)

// hashFromStrForTest panics on error to keep the table below readable.
func hashFromStrForTest(s string) chainhash.Hash {
	h, err := chainhash.NewHashFromStr(s)
	if err != nil {
		panic(err)
	}
	return *h
}

// TestNewMsgInvFromInvVectsDedup verifies the optional duplicate compression
// constructor keeps the first-occurrence order and only treats vectors with
// both matching type and hash as duplicates.
func TestNewMsgInvFromInvVectsDedup(t *testing.T) {
	blockHash := hashFromStrForTest(
		"3264bc2ac36a60840790ba1d475d01367e7c723da941069e9dc")
	txHash := hashFromStrForTest(
		"d28a3dc7392bf00a9855ee93dd9a81eff82a2c4fe57fbd42cfe71b487accfaf0")

	ivBlock := NewInvVect(InvTypeBlock, &blockHash)
	ivTx := NewInvVect(InvTypeTx, &txHash)
	// Same hash as ivBlock, but a different type: not a duplicate.
	ivFiltered := NewInvVect(InvTypeFilteredBlock, &blockHash)

	input := []*InvVect{ivBlock, ivBlock, ivTx, ivFiltered, ivBlock, ivTx}

	msg, err := NewMsgInvFromInvVects(input, true)
	if err != nil {
		t.Fatalf("NewMsgInvFromInvVects: unexpected error: %v", err)
	}

	want := []*InvVect{ivBlock, ivTx, ivFiltered}
	if len(msg.InvList) != len(want) {
		t.Fatalf("unexpected compressed length - got %d, want %d",
			len(msg.InvList), len(want))
	}
	for i, iv := range want {
		if *msg.InvList[i] != *iv {
			t.Errorf("position %d: got %+v, want %+v",
				i, *msg.InvList[i], *iv)
		}
	}
	t.Logf("dedup: %d input vectors -> %d (first-occurrence order kept)",
		len(input), len(msg.InvList))
}

// TestNewMsgInvFromInvVectsNoDedup ensures the default (dedup=false) path
// preserves every input vector, so default serialization is untouched.
func TestNewMsgInvFromInvVectsNoDedup(t *testing.T) {
	h := chainhash.Hash{}
	iv := NewInvVect(InvTypeBlock, &h)
	input := []*InvVect{iv, iv, iv}

	msg, err := NewMsgInvFromInvVects(input, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msg.InvList) != len(input) {
		t.Fatalf("dedup=false changed length - got %d, want %d",
			len(msg.InvList), len(input))
	}

	// A message built the classic way must serialize identically.
	classic := NewMsgInv()
	for _, iv := range input {
		if err := classic.AddInvVect(iv); err != nil {
			t.Fatalf("AddInvVect: %v", err)
		}
	}

	var a, b bytes.Buffer
	if err := msg.BtcEncode(&a, ProtocolVersion, BaseEncoding); err != nil {
		t.Fatalf("encode constructor msg: %v", err)
	}
	if err := classic.BtcEncode(&b, ProtocolVersion, BaseEncoding); err != nil {
		t.Fatalf("encode classic msg: %v", err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatalf("dedup=false encoding differs from classic:\n got %x\nwant %x",
			a.Bytes(), b.Bytes())
	}
}

// TestNewMsgInvFromInvVectsWire checks the compressed output against the exact
// expected bitcoin protocol bytes and confirms it round-trips.
func TestNewMsgInvFromInvVectsWire(t *testing.T) {
	blockHash := hashFromStrForTest(
		"3264bc2ac36a60840790ba1d475d01367e7c723da941069e9dc")
	txHash := hashFromStrForTest(
		"d28a3dc7392bf00a9855ee93dd9a81eff82a2c4fe57fbd42cfe71b487accfaf0")
	ivBlock := NewInvVect(InvTypeBlock, &blockHash)
	ivTx := NewInvVect(InvTypeTx, &txHash)

	// Two duplicates plus the same hash under a second type.
	input := []*InvVect{ivBlock, ivBlock, ivTx,
		NewInvVect(InvTypeFilteredBlock, &blockHash), ivBlock}

	msg, err := NewMsgInvFromInvVects(input, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantBytes := []byte{
		0x03,                   // Varint for number of inv vectors
		0x02, 0x00, 0x00, 0x00, // InvTypeBlock
		0xdc, 0xe9, 0x69, 0x10, 0x94, 0xda, 0x23, 0xc7,
		0xe7, 0x67, 0x13, 0xd0, 0x75, 0xd4, 0xa1, 0x0b,
		0x79, 0x40, 0x08, 0xa6, 0x36, 0xac, 0xc2, 0x4b,
		0x26, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Block hash
		0x01, 0x00, 0x00, 0x00, // InvTypeTx
		0xf0, 0xfa, 0xcc, 0x7a, 0x48, 0x1b, 0xe7, 0xcf,
		0x42, 0xbd, 0x7f, 0xe5, 0x4f, 0x2c, 0x2a, 0xf8,
		0xef, 0x81, 0x9a, 0xdd, 0x93, 0xee, 0x55, 0x98,
		0x0a, 0xf0, 0x2b, 0x39, 0xc7, 0x3d, 0x8a, 0xd2, // Tx hash
		0x03, 0x00, 0x00, 0x00, // InvTypeFilteredBlock
		0xdc, 0xe9, 0x69, 0x10, 0x94, 0xda, 0x23, 0xc7,
		0xe7, 0x67, 0x13, 0xd0, 0x75, 0xd4, 0xa1, 0x0b,
		0x79, 0x40, 0x08, 0xa6, 0x36, 0xac, 0xc2, 0x4b,
		0x26, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Same block hash
	}

	var buf bytes.Buffer
	if err := msg.BtcEncode(&buf, ProtocolVersion, BaseEncoding); err != nil {
		t.Fatalf("BtcEncode: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), wantBytes) {
		t.Fatalf("compressed encoding mismatch:\n got %x\nwant %x",
			buf.Bytes(), wantBytes)
	}

	// Round-trip the compressed wire encoding.
	var decoded MsgInv
	if err := decoded.BtcDecode(bytes.NewReader(wantBytes),
		ProtocolVersion, BaseEncoding); err != nil {
		t.Fatalf("BtcDecode: %v", err)
	}
	if len(decoded.InvList) != 3 {
		t.Fatalf("decoded length - got %d, want 3",
			len(decoded.InvList))
	}
}

// TestNewMsgInvFromInvVectsLimits verifies capacity is checked before
// de-duplication: exactly MaxInvPerMsg vectors are accepted (even all
// duplicate), while MaxInvPerMsg+1 is rejected even though compression would
// shrink it to one.
func TestNewMsgInvFromInvVectsLimits(t *testing.T) {
	h := chainhash.Hash{}
	iv := NewInvVect(InvTypeBlock, &h)

	atMax := make([]*InvVect, MaxInvPerMsg)
	for i := range atMax {
		atMax[i] = iv
	}
	msg, err := NewMsgInvFromInvVects(atMax, true)
	if err != nil {
		t.Fatalf("exactly %d duplicates should be accepted: %v",
			MaxInvPerMsg, err)
	}
	if len(msg.InvList) != 1 {
		t.Fatalf("expected all %d duplicates compressed to 1, got %d",
			MaxInvPerMsg, len(msg.InvList))
	}

	overMax := make([]*InvVect, MaxInvPerMsg+1)
	for i := range overMax {
		overMax[i] = iv
	}
	if _, err := NewMsgInvFromInvVects(overMax, true); err == nil {
		t.Fatalf("expected error for %d inputs, got nil", len(overMax))
	} else {
		t.Logf("over-limit input (%d duplicates) rejected before "+
			"dedup: %v", len(overMax), err)
	}
	if _, err := NewMsgInvFromInvVects(overMax, false); err == nil {
		t.Fatalf("expected error for %d inputs (no dedup), got nil",
			len(overMax))
	}
}
