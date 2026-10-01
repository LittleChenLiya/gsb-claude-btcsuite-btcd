// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"io"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/davecgh/go-spew/spew"
)

// TestInv tests the MsgInv API.
func TestInv(t *testing.T) {
	pver := ProtocolVersion

	// Ensure the command is expected value.
	wantCmd := "inv"
	msg := NewMsgInv()
	if cmd := msg.Command(); cmd != wantCmd {
		t.Errorf("NewMsgInv: wrong command - got %v want %v",
			cmd, wantCmd)
	}

	// Ensure max payload is expected value for latest protocol version.
	// Num inventory vectors (varInt) + max allowed inventory vectors.
	wantPayload := uint32(1800009)
	maxPayload := msg.MaxPayloadLength(pver)
	if maxPayload != wantPayload {
		t.Errorf("MaxPayloadLength: wrong max payload length for "+
			"protocol version %d - got %v, want %v", pver,
			maxPayload, wantPayload)
	}

	// Ensure inventory vectors are added properly.
	hash := chainhash.Hash{}
	iv := NewInvVect(InvTypeBlock, &hash)
	err := msg.AddInvVect(iv)
	if err != nil {
		t.Errorf("AddInvVect: %v", err)
	}
	if msg.InvList[0] != iv {
		t.Errorf("AddInvVect: wrong invvect added - got %v, want %v",
			spew.Sprint(msg.InvList[0]), spew.Sprint(iv))
	}

	// Ensure adding more than the max allowed inventory vectors per
	// message returns an error.
	for i := 0; i < MaxInvPerMsg; i++ {
		err = msg.AddInvVect(iv)
	}
	if err == nil {
		t.Errorf("AddInvVect: expected error on too many inventory " +
			"vectors not received")
	}

	// Ensure creating the message with a size hint larger than the max
	// works as expected.
	msg = NewMsgInvSizeHint(MaxInvPerMsg + 1)
	wantCap := MaxInvPerMsg
	if cap(msg.InvList) != wantCap {
		t.Errorf("NewMsgInvSizeHint: wrong cap for size hint - "+
			"got %v, want %v", cap(msg.InvList), wantCap)
	}
}

// TestInvDedup tests the optional duplicate-compressing inv message
// constructor.
func TestInvDedup(t *testing.T) {
	// A handful of distinct hashes used to build inventory vectors.
	hashes := make([]*chainhash.Hash, 4)
	for i := range hashes {
		h := chainhash.Hash{byte(i + 1)}
		hashes[i] = &h
	}

	tests := []struct {
		name string
		add  func(*MsgInv) []*InvVect // vectors to add, in order
		want []*InvVect               // vectors expected after compression
	}{
		{
			name: "duplicate hashes are compressed to first occurrence",
			add: func(msg *MsgInv) []*InvVect {
				v0 := NewInvVect(InvTypeBlock, hashes[0])
				msg.AddInvVect(v0)
				msg.AddInvVect(v0)
				msg.AddInvVect(v0)
				return []*InvVect{v0}
			},
		},
		{
			name: "order of first occurrence is preserved",
			add: func(msg *MsgInv) []*InvVect {
				v0 := NewInvVect(InvTypeBlock, hashes[0])
				v1 := NewInvVect(InvTypeTx, hashes[1])
				v2 := NewInvVect(InvTypeBlock, hashes[2])
				msg.AddInvVect(v0)
				msg.AddInvVect(v1)
				msg.AddInvVect(v0) // duplicate of v0
				msg.AddInvVect(v2)
				msg.AddInvVect(v1) // duplicate of v1
				return []*InvVect{v0, v1, v2}
			},
		},
		{
			name: "same hash under different types is kept",
			add: func(msg *MsgInv) []*InvVect {
				blockVect := NewInvVect(InvTypeBlock, hashes[3])
				txVect := NewInvVect(InvTypeTx, hashes[3])
				msg.AddInvVect(blockVect)
				msg.AddInvVect(txVect)
				msg.AddInvVect(blockVect) // duplicate of the block vector
				return []*InvVect{blockVect, txVect}
			},
		},
	}

	for _, test := range tests {
		msg := NewMsgInvDedup()
		want := test.add(msg)
		if len(msg.InvList) != len(want) {
			t.Errorf("%s: wrong length - got %v, want %v",
				test.name, len(msg.InvList), len(want))
			continue
		}
		for i := range want {
			if msg.InvList[i] != want[i] {
				t.Errorf("%s: wrong vector at index %d - got %v, want %v",
					test.name, i, spew.Sdump(msg.InvList[i]),
					spew.Sdump(want[i]))
			}
		}
	}

	// The default constructors must keep duplicates, i.e. default
	// serialization is unchanged.
	defaultMsg := NewMsgInv()
	v := NewInvVect(InvTypeBlock, hashes[0])
	for i := 0; i < 3; i++ {
		if err := defaultMsg.AddInvVect(v); err != nil {
			t.Fatalf("AddInvVect: unexpected error: %v", err)
		}
	}
	if len(defaultMsg.InvList) != 3 {
		t.Errorf("default MsgInv should keep duplicates - got %v, want 3",
			len(defaultMsg.InvList))
	}
}

// TestInvDedupCapacity ensures the capacity limit is enforced before any
// deduplication takes place.
func TestInvDedupCapacity(t *testing.T) {
	// Fill a dedup message to the max with distinct vectors.
	msg := NewMsgInvDedup()
	ivs := make([]*InvVect, MaxInvPerMsg)
	for i := 0; i < MaxInvPerMsg; i++ {
		h := chainhash.Hash{byte(i), byte(i >> 8), byte(i >> 16)}
		ivs[i] = NewInvVect(InvTypeTx, &h)
		if err := msg.AddInvVect(ivs[i]); err != nil {
			t.Fatalf("AddInvVect #%d: unexpected error: %v", i, err)
		}
	}
	if len(msg.InvList) != MaxInvPerMsg {
		t.Fatalf("wrong length after filling - got %v, want %v",
			len(msg.InvList), MaxInvPerMsg)
	}

	// Adding one more distinct vector must fail with the capacity error.
	extra := NewInvVect(InvTypeBlock, &chainhash.Hash{0xff, 0xff})
	if err := msg.AddInvVect(extra); err == nil {
		t.Errorf("AddInvVect: expected capacity error for %d vectors",
			MaxInvPerMsg+1)
	}

	// Adding a duplicate once the message is full must also fail: the
	// capacity check runs before deduplication.
	if err := msg.AddInvVect(ivs[0]); err == nil {
		t.Errorf("AddInvVect: expected capacity error for duplicate " +
			"vector once at max capacity")
	}
	if len(msg.InvList) != MaxInvPerMsg {
		t.Errorf("length changed after rejected adds - got %v, want %v",
			len(msg.InvList), MaxInvPerMsg)
	}

	// By contrast, a duplicate added while there is still room is silently
	// compressed out.
	roomy := NewMsgInvDedup()
	if err := roomy.AddInvVect(ivs[0]); err != nil {
		t.Fatalf("AddInvVect: unexpected error: %v", err)
	}
	if err := roomy.AddInvVect(ivs[0]); err != nil {
		t.Fatalf("AddInvVect duplicate: unexpected error: %v", err)
	}
	if len(roomy.InvList) != 1 {
		t.Errorf("duplicate with room: wrong length - got %v, want 1",
			len(roomy.InvList))
	}
}

// TestInvDedupWire ensures the wire encoding of a dedup message is byte for
// byte identical to the original protocol encoding produced by a normal
// message, and that decoding a stream with duplicates into a dedup message
// compresses them while decoding into a normal message keeps them.
func TestInvDedupWire(t *testing.T) {
	hash0 := chainhash.Hash{0x01}
	hash1 := chainhash.Hash{0x02}
	hash2 := chainhash.Hash{0x03}
	blockVect := NewInvVect(InvTypeBlock, &hash0)
	txVect := NewInvVect(InvTypeTx, &hash1)
	blockVect2 := NewInvVect(InvTypeBlock, &hash2)

	// Dedup message with duplicates added out of order.
	dedupMsg := NewMsgInvDedup()
	dedupMsg.AddInvVect(blockVect)
	dedupMsg.AddInvVect(txVect)
	dedupMsg.AddInvVect(blockVect) // duplicate of blockVect
	dedupMsg.AddInvVect(blockVect2)
	dedupMsg.AddInvVect(txVect) // duplicate of txVect

	// Normal message carrying only the unique vectors, in first-occurrence
	// order.
	normalMsg := NewMsgInv()
	normalMsg.AddInvVect(blockVect)
	normalMsg.AddInvVect(txVect)
	normalMsg.AddInvVect(blockVect2)

	if len(dedupMsg.InvList) != 3 {
		t.Fatalf("dedup message: wrong length - got %v, want 3",
			len(dedupMsg.InvList))
	}

	var dedupBuf, normalBuf bytes.Buffer
	if err := dedupMsg.BtcEncode(&dedupBuf, ProtocolVersion, BaseEncoding); err != nil {
		t.Fatalf("BtcEncode dedup: %v", err)
	}
	if err := normalMsg.BtcEncode(&normalBuf, ProtocolVersion, BaseEncoding); err != nil {
		t.Fatalf("BtcEncode normal: %v", err)
	}
	if !bytes.Equal(dedupBuf.Bytes(), normalBuf.Bytes()) {
		t.Errorf("dedup encoding differs from original protocol encoding\n"+
			"got: %s\nwant: %s", spew.Sdump(dedupBuf.Bytes()),
			spew.Sdump(normalBuf.Bytes()))
	}

	// Build a wire stream that carries 5 vectors with duplicates.
	ladenMsg := NewMsgInv()
	ladenMsg.AddInvVect(blockVect)
	ladenMsg.AddInvVect(txVect)
	ladenMsg.AddInvVect(blockVect) // duplicate of blockVect
	ladenMsg.AddInvVect(blockVect2)
	ladenMsg.AddInvVect(txVect) // duplicate of txVect
	var ladenBuf bytes.Buffer
	if err := ladenMsg.BtcEncode(&ladenBuf, ProtocolVersion, BaseEncoding); err != nil {
		t.Fatalf("BtcEncode laden: %v", err)
	}

	// Decoding the duplicate-laden stream into a dedup message compresses
	// the duplicates while preserving first-occurrence order.
	decodedDedup := NewMsgInvDedup()
	if err := decodedDedup.BtcDecode(bytes.NewReader(ladenBuf.Bytes()),
		ProtocolVersion, BaseEncoding); err != nil {
		t.Fatalf("BtcDecode dedup: %v", err)
	}
	if len(decodedDedup.InvList) != 3 {
		t.Errorf("decode into dedup: wrong length - got %v, want 3",
			len(decodedDedup.InvList))
	}
	wantDecoded := []*InvVect{blockVect, txVect, blockVect2}
	for i, want := range wantDecoded {
		got := decodedDedup.InvList[i]
		if got.Type != want.Type || got.Hash != want.Hash {
			t.Errorf("decode into dedup: wrong vector at index %d - "+
				"got %v, want %v", i, spew.Sdump(got),
				spew.Sdump(want))
		}
	}

	// Decoding the same stream into a normal message keeps every vector,
	// confirming default behavior is unchanged.
	var decodedNormal MsgInv
	if err := decodedNormal.BtcDecode(bytes.NewReader(ladenBuf.Bytes()),
		ProtocolVersion, BaseEncoding); err != nil {
		t.Fatalf("BtcDecode normal: %v", err)
	}
	if len(decodedNormal.InvList) != 5 {
		t.Errorf("decode into normal: wrong length - got %v, want 5",
			len(decodedNormal.InvList))
	}

	// A wire stream claiming more than the max count is rejected at decode
	// time before any deduplication, even though the duplicates it carries
	// would compress it below the limit.  Build such a stream by hand:
	// varint count 50001 followed by 50001 copies of one vector.
	var oneBuf bytes.Buffer
	oneMsg := NewMsgInv()
	oneMsg.AddInvVect(blockVect)
	if err := oneMsg.BtcEncode(&oneBuf, ProtocolVersion, BaseEncoding); err != nil {
		t.Fatalf("BtcEncode one vector: %v", err)
	}
	vectBytes := oneBuf.Bytes()[1:] // strip the count varint
	overStream := append([]byte{0xfd, 0x51, 0xc3},
		bytes.Repeat(vectBytes, MaxInvPerMsg+1)...)

	var overMsg MsgInv
	overMsg.dedup = true
	err := overMsg.BtcDecode(bytes.NewReader(overStream), ProtocolVersion,
		BaseEncoding)
	if err == nil {
		t.Errorf("BtcDecode: expected error for count %d", MaxInvPerMsg+1)
	} else if _, ok := err.(*MessageError); !ok {
		t.Errorf("BtcDecode: expected MessageError, got %T: %v", err, err)
	}
}

// of inventory vectors and protocol versions.
func TestInvWire(t *testing.T) {
	// Block 203707 hash.
	hashStr := "3264bc2ac36a60840790ba1d475d01367e7c723da941069e9dc"
	blockHash, err := chainhash.NewHashFromStr(hashStr)
	if err != nil {
		t.Errorf("NewHashFromStr: %v", err)
	}

	// Transaction 1 of Block 203707 hash.
	hashStr = "d28a3dc7392bf00a9855ee93dd9a81eff82a2c4fe57fbd42cfe71b487accfaf0"
	txHash, err := chainhash.NewHashFromStr(hashStr)
	if err != nil {
		t.Errorf("NewHashFromStr: %v", err)
	}

	iv := NewInvVect(InvTypeBlock, blockHash)
	iv2 := NewInvVect(InvTypeTx, txHash)

	// Empty inv message.
	NoInv := NewMsgInv()
	NoInvEncoded := []byte{
		0x00, // Varint for number of inventory vectors
	}

	// Inv message with multiple inventory vectors.
	MultiInv := NewMsgInv()
	MultiInv.AddInvVect(iv)
	MultiInv.AddInvVect(iv2)
	MultiInvEncoded := []byte{
		0x02,                   // Varint for number of inv vectors
		0x02, 0x00, 0x00, 0x00, // InvTypeBlock
		0xdc, 0xe9, 0x69, 0x10, 0x94, 0xda, 0x23, 0xc7,
		0xe7, 0x67, 0x13, 0xd0, 0x75, 0xd4, 0xa1, 0x0b,
		0x79, 0x40, 0x08, 0xa6, 0x36, 0xac, 0xc2, 0x4b,
		0x26, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Block 203707 hash
		0x01, 0x00, 0x00, 0x00, // InvTypeTx
		0xf0, 0xfa, 0xcc, 0x7a, 0x48, 0x1b, 0xe7, 0xcf,
		0x42, 0xbd, 0x7f, 0xe5, 0x4f, 0x2c, 0x2a, 0xf8,
		0xef, 0x81, 0x9a, 0xdd, 0x93, 0xee, 0x55, 0x98,
		0x0a, 0xf0, 0x2b, 0x39, 0xc7, 0x3d, 0x8a, 0xd2, // Tx 1 of block 203707 hash
	}

	tests := []struct {
		in   *MsgInv         // Message to encode
		out  *MsgInv         // Expected decoded message
		buf  []byte          // Wire encoding pver uint32
		pver uint32          // Protocol version for wire encoding
		enc  MessageEncoding // Message encodinf format
	}{
		// Latest protocol version with no inv vectors.
		{
			NoInv,
			NoInv,
			NoInvEncoded,
			ProtocolVersion,
			BaseEncoding,
		},

		// Latest protocol version with multiple inv vectors.
		{
			MultiInv,
			MultiInv,
			MultiInvEncoded,
			ProtocolVersion,
			BaseEncoding,
		},

		// Protocol version BIP0035Version no inv vectors.
		{
			NoInv,
			NoInv,
			NoInvEncoded,
			BIP0035Version,
			BaseEncoding,
		},

		// Protocol version BIP0035Version with multiple inv vectors.
		{
			MultiInv,
			MultiInv,
			MultiInvEncoded,
			BIP0035Version,
			BaseEncoding,
		},

		// Protocol version BIP0031Version no inv vectors.
		{
			NoInv,
			NoInv,
			NoInvEncoded,
			BIP0031Version,
			BaseEncoding,
		},

		// Protocol version BIP0031Version with multiple inv vectors.
		{
			MultiInv,
			MultiInv,
			MultiInvEncoded,
			BIP0031Version,
			BaseEncoding,
		},

		// Protocol version NetAddressTimeVersion no inv vectors.
		{
			NoInv,
			NoInv,
			NoInvEncoded,
			NetAddressTimeVersion,
			BaseEncoding,
		},

		// Protocol version NetAddressTimeVersion with multiple inv vectors.
		{
			MultiInv,
			MultiInv,
			MultiInvEncoded,
			NetAddressTimeVersion,
			BaseEncoding,
		},

		// Protocol version MultipleAddressVersion no inv vectors.
		{
			NoInv,
			NoInv,
			NoInvEncoded,
			MultipleAddressVersion,
			BaseEncoding,
		},

		// Protocol version MultipleAddressVersion with multiple inv vectors.
		{
			MultiInv,
			MultiInv,
			MultiInvEncoded,
			MultipleAddressVersion,
			BaseEncoding,
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode the message to wire format.
		var buf bytes.Buffer
		err := test.in.BtcEncode(&buf, test.pver, test.enc)
		if err != nil {
			t.Errorf("BtcEncode #%d error %v", i, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("BtcEncode #%d\n got: %s want: %s", i,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.buf))
			continue
		}

		// Decode the message from wire format.
		var msg MsgInv
		rbuf := bytes.NewReader(test.buf)
		err = msg.BtcDecode(rbuf, test.pver, test.enc)
		if err != nil {
			t.Errorf("BtcDecode #%d error %v", i, err)
			continue
		}
		if !reflect.DeepEqual(&msg, test.out) {
			t.Errorf("BtcDecode #%d\n got: %s want: %s", i,
				spew.Sdump(msg), spew.Sdump(test.out))
			continue
		}
	}
}

// TestInvWireErrors performs negative tests against wire encode and decode
// of MsgInv to confirm error paths work correctly.
func TestInvWireErrors(t *testing.T) {
	pver := ProtocolVersion
	wireErr := &MessageError{}

	// Block 203707 hash.
	hashStr := "3264bc2ac36a60840790ba1d475d01367e7c723da941069e9dc"
	blockHash, err := chainhash.NewHashFromStr(hashStr)
	if err != nil {
		t.Errorf("NewHashFromStr: %v", err)
	}

	iv := NewInvVect(InvTypeBlock, blockHash)

	// Base inv message used to induce errors.
	baseInv := NewMsgInv()
	baseInv.AddInvVect(iv)
	baseInvEncoded := []byte{
		0x02,                   // Varint for number of inv vectors
		0x02, 0x00, 0x00, 0x00, // InvTypeBlock
		0xdc, 0xe9, 0x69, 0x10, 0x94, 0xda, 0x23, 0xc7,
		0xe7, 0x67, 0x13, 0xd0, 0x75, 0xd4, 0xa1, 0x0b,
		0x79, 0x40, 0x08, 0xa6, 0x36, 0xac, 0xc2, 0x4b,
		0x26, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Block 203707 hash
	}

	// Inv message that forces an error by having more than the max allowed
	// inv vectors.
	maxInv := NewMsgInv()
	for i := 0; i < MaxInvPerMsg; i++ {
		maxInv.AddInvVect(iv)
	}
	maxInv.InvList = append(maxInv.InvList, iv)
	maxInvEncoded := []byte{
		0xfd, 0x51, 0xc3, // Varint for number of inv vectors (50001)
	}

	tests := []struct {
		in       *MsgInv         // Value to encode
		buf      []byte          // Wire encoding
		pver     uint32          // Protocol version for wire encoding
		enc      MessageEncoding // Message encoding format
		max      int             // Max size of fixed buffer to induce errors
		writeErr error           // Expected write error
		readErr  error           // Expected read error
	}{
		// Latest protocol version with intentional read/write errors.
		// Force error in inventory vector count
		{baseInv, baseInvEncoded, pver, BaseEncoding, 0, io.ErrShortWrite, io.EOF},
		// Force error in inventory list.
		{baseInv, baseInvEncoded, pver, BaseEncoding, 1, io.ErrShortWrite, io.EOF},
		// Force error with greater than max inventory vectors.
		{maxInv, maxInvEncoded, pver, BaseEncoding, 3, wireErr, wireErr},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode to wire format.
		w := newFixedWriter(test.max)
		err := test.in.BtcEncode(w, test.pver, test.enc)
		if reflect.TypeOf(err) != reflect.TypeOf(test.writeErr) {
			t.Errorf("BtcEncode #%d wrong error got: %v, want: %v",
				i, err, test.writeErr)
			continue
		}

		// For errors which are not of type MessageError, check them for
		// equality.
		if _, ok := err.(*MessageError); !ok {
			if err != test.writeErr {
				t.Errorf("BtcEncode #%d wrong error got: %v, "+
					"want: %v", i, err, test.writeErr)
				continue
			}
		}

		// Decode from wire format.
		var msg MsgInv
		r := newFixedReader(test.max, test.buf)
		err = msg.BtcDecode(r, test.pver, test.enc)
		if reflect.TypeOf(err) != reflect.TypeOf(test.readErr) {
			t.Errorf("BtcDecode #%d wrong error got: %v, want: %v",
				i, err, test.readErr)
			continue
		}

		// For errors which are not of type MessageError, check them for
		// equality.
		if _, ok := err.(*MessageError); !ok {
			if err != test.readErr {
				t.Errorf("BtcDecode #%d wrong error got: %v, "+
					"want: %v", i, err, test.readErr)
				continue
			}
		}

	}
}
