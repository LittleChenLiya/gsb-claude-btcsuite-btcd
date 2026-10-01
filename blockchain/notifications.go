// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"fmt"

	"github.com/btcsuite/btcd/chainhash/v2"
)

// NotificationType represents the type of a notification message.
type NotificationType int

// NotificationCallback is used for a caller to provide a callback for
// notifications about various chain events.
type NotificationCallback func(*Notification)

// Constants for the type of a notification message.
const (
	// NTBlockAccepted indicates the associated block was accepted into
	// the block chain.  Note that this does not necessarily mean it was
	// added to the main chain.  For that, use NTBlockConnected.
	NTBlockAccepted NotificationType = iota

	// NTBlockConnected indicates the associated block was connected to the
	// main chain.
	NTBlockConnected

	// NTBlockDisconnected indicates the associated block was disconnected
	// from the main chain.
	NTBlockDisconnected

	// NTReorganization indicates the chain underwent a reorganization.  The
	// associated data is a *ReorganizationReport describing the common
	// ancestor (fork point) and the number of blocks that were rolled back
	// (detached from the old chain) and connected (attached to the new
	// chain).  This notification is only published after a reorganization
	// completes successfully; a failed reorganization never produces one.
	NTReorganization
)

// notificationTypeStrings is a map of notification types back to their constant
// names for pretty printing.
var notificationTypeStrings = map[NotificationType]string{
	NTBlockAccepted:     "NTBlockAccepted",
	NTBlockConnected:    "NTBlockConnected",
	NTBlockDisconnected: "NTBlockDisconnected",
	NTReorganization:    "NTReorganization",
}

// String returns the NotificationType in human-readable form.
func (n NotificationType) String() string {
	if s, ok := notificationTypeStrings[n]; ok {
		return s
	}
	return fmt.Sprintf("Unknown Notification Type (%d)", int(n))
}

// Notification defines notification that is sent to the caller via the callback
// function provided during the call to New and consists of a notification type
// as well as associated data that depends on the type as follows:
//   - NTBlockAccepted:     *btcutil.Block
//   - NTBlockConnected:    *btcutil.Block
//   - NTBlockDisconnected: *btcutil.Block
//   - NTReorganization:    *ReorganizationReport
type Notification struct {
	Type NotificationType
	Data interface{}
}

// ReorganizationReport is a read-only snapshot of a chain reorganization
// decision.  It records the common ancestor (fork point) of the old and new
// best chains along with the number of blocks that were rolled back
// (detached from the old main chain) and connected (attached to the new main
// chain).
//
// The report is generated at the point the reorganization is decided, before
// the chain is modified, and is only published to subscribers after the
// reorganization completes successfully.  A failed reorganization never
// produces a report.
type ReorganizationReport struct {
	// ForkHash is the hash of the common ancestor of the old and new best
	// chains (the point at which the chain forked).
	ForkHash chainhash.Hash

	// ForkHeight is the height of the common ancestor.
	ForkHeight int32

	// OldBestHash is the hash of the best chain tip before the
	// reorganization.
	OldBestHash chainhash.Hash

	// OldBestHeight is the height of the best chain tip before the
	// reorganization.
	OldBestHeight int32

	// NewBestHash is the hash of the best chain tip after the
	// reorganization.
	NewBestHash chainhash.Hash

	// NewBestHeight is the height of the best chain tip after the
	// reorganization.
	NewBestHeight int32

	// DetachCount is the number of blocks that were rolled back
	// (disconnected) from the old main chain.  A value of zero means no
	// blocks were rolled back.
	DetachCount int32

	// AttachCount is the number of blocks that were connected to the new
	// main chain.
	AttachCount int32
}

// Subscribe to block chain notifications. Registers a callback to be executed
// when various events take place. See the documentation on Notification and
// NotificationType for details on the types and contents of notifications.
func (b *BlockChain) Subscribe(callback NotificationCallback) {
	b.notificationsLock.Lock()
	b.notifications = append(b.notifications, callback)
	b.notificationsLock.Unlock()
}

// sendNotification sends a notification with the passed type and data if the
// caller requested notifications by providing a callback function in the call
// to New.
func (b *BlockChain) sendNotification(typ NotificationType, data interface{}) {
	// Generate and send the notification.
	n := Notification{Type: typ, Data: data}
	b.notificationsLock.RLock()
	for _, callback := range b.notifications {
		callback(&n)
	}
	b.notificationsLock.RUnlock()
}
