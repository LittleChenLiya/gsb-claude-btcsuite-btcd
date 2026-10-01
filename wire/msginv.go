// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"
)

// defaultInvListAlloc is the default size used for the backing array for an
// inventory list.  The array will dynamically grow as needed, but this
// figure is intended to provide enough space for the max number of inventory
// vectors in a *typical* inventory message without needing to grow the backing
// array multiple times.  Technically, the list can grow to MaxInvPerMsg, but
// rather than using that large figure, this figure more accurately reflects the
// typical case.
const defaultInvListAlloc = 1000

// MsgInv implements the Message interface and represents a bitcoin inv message.
// It is used to advertise a peer's known data such as blocks and transactions
// through inventory vectors.  It may be sent unsolicited to inform other peers
// of the data or in response to a getblocks message (MsgGetBlocks).  Each
// message is limited to a maximum number of inventory vectors, which is
// currently 50,000.
//
// Use the AddInvVect function to build up the list of inventory vectors when
// sending an inv message to another peer.
type MsgInv struct {
	InvList []*InvVect

	// dedup indicates whether duplicate inventory vectors are compressed
	// when they are added.  It is only enabled via the NewMsgInvDedup
	// constructor and is false for the default constructors, which preserves
	// the original behavior of keeping every added vector.
	dedup bool

	// seen tracks the inventory vectors that have already been added while
	// dedup is enabled so duplicates can be detected in constant time.  A
	// vector is only considered a duplicate when both its type and hash
	// match, so the same hash advertised under different inventory types is
	// kept as two distinct entries.
	seen map[InvVect]struct{}
}

// AddInvVect adds an inventory vector to the message.  When the message was
// created with the NewMsgInvDedup constructor, an inventory vector that
// duplicates one already in the message is silently ignored while preserving
// the order of first occurrence.  The capacity limit is always enforced first
// though, so once the message holds the maximum number of vectors, every
// subsequent add - duplicates included - is rejected.
func (msg *MsgInv) AddInvVect(iv *InvVect) error {
	if len(msg.InvList)+1 > MaxInvPerMsg {
		str := fmt.Sprintf("too many invvect in message [max %v]",
			MaxInvPerMsg)
		return messageError("MsgInv.AddInvVect", str)
	}

	if msg.dedup {
		if msg.seen == nil {
			msg.seen = make(map[InvVect]struct{})
		}

		key := *iv
		if _, exists := msg.seen[key]; exists {
			return nil
		}
		msg.seen[key] = struct{}{}
	}

	msg.InvList = append(msg.InvList, iv)
	return nil
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgInv) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	buf := binarySerializer.Borrow()
	defer binarySerializer.Return(buf)

	count, err := ReadVarIntBuf(r, pver, buf)
	if err != nil {
		return err
	}

	// Limit to max inventory vectors per message.
	if count > MaxInvPerMsg {
		str := fmt.Sprintf("too many invvect in message [%v]", count)
		return messageError("MsgInv.BtcDecode", str)
	}

	// Create a contiguous slice of inventory vectors to deserialize into in
	// order to reduce the number of allocations.
	invList := make([]InvVect, count)
	msg.InvList = make([]*InvVect, 0, count)
	if msg.dedup {
		msg.seen = make(map[InvVect]struct{})
	}
	for i := uint64(0); i < count; i++ {
		iv := &invList[i]
		err := readInvVectBuf(r, pver, iv, buf)
		if err != nil {
			return err
		}
		msg.AddInvVect(iv)
	}

	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgInv) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	// Limit to max inventory vectors per message.
	count := len(msg.InvList)
	if count > MaxInvPerMsg {
		str := fmt.Sprintf("too many invvect in message [%v]", count)
		return messageError("MsgInv.BtcEncode", str)
	}

	buf := binarySerializer.Borrow()
	defer binarySerializer.Return(buf)

	err := WriteVarIntBuf(w, pver, uint64(count), buf)
	if err != nil {
		return err
	}

	for _, iv := range msg.InvList {
		err := writeInvVectBuf(w, pver, iv, buf)
		if err != nil {
			return err
		}
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgInv) Command() string {
	return CmdInv
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgInv) MaxPayloadLength(pver uint32) uint32 {
	// Num inventory vectors (varInt) + max allowed inventory vectors.
	return MaxVarIntPayload + (MaxInvPerMsg * maxInvVectPayload)
}

// NewMsgInv returns a new bitcoin inv message that conforms to the Message
// interface.  See MsgInv for details.
func NewMsgInv() *MsgInv {
	return &MsgInv{
		InvList: make([]*InvVect, 0, defaultInvListAlloc),
	}
}

// NewMsgInvSizeHint returns a new bitcoin inv message that conforms to the
// Message interface.  See MsgInv for details.  This function differs from
// NewMsgInv in that it allows a default allocation size for the backing array
// which houses the inventory vector list.  This allows callers who know in
// advance how large the inventory list will grow to avoid the overhead of
// growing the internal backing array several times when appending large amounts
// of inventory vectors with AddInvVect.  Note that the specified hint is just
// that - a hint that is used for the default allocation size.  Adding more
// (or less) inventory vectors will still work properly.  The size hint is
// limited to MaxInvPerMsg.
func NewMsgInvSizeHint(sizeHint uint) *MsgInv {
	// Limit the specified hint to the maximum allow per message.
	if sizeHint > MaxInvPerMsg {
		sizeHint = MaxInvPerMsg
	}

	return &MsgInv{
		InvList: make([]*InvVect, 0, sizeHint),
	}
}

// NewMsgInvDedup returns a new bitcoin inv message that conforms to the
// Message interface.  It differs from NewMsgInv in that inventory vectors
// added through AddInvVect which duplicate a vector already in the message
// are compressed out: only the first occurrence of a given type/hash pair is
// kept, and the order of first occurrence is preserved.  Two vectors are
// considered duplicates only when both their type and hash are equal, so the
// same hash advertised under different inventory types (e.g. InvTypeTx and
// InvTypeBlock) is retained as two distinct entries.
//
// The wire encoding produced by this message is byte for byte identical to
// that of a normal inv message carrying the same unique vectors, so peers that
// do not support compression are unaffected.  The max capacity is enforced
// before any deduplication takes place: once MaxInvPerMsg vectors have been
// added, every further add, duplicates included, is rejected.
func NewMsgInvDedup() *MsgInv {
	return &MsgInv{
		InvList: make([]*InvVect, 0, defaultInvListAlloc),
		dedup:   true,
		seen:    make(map[InvVect]struct{}),
	}
}
