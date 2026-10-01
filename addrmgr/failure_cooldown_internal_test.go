// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package addrmgr

import (
	"net"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire/v2"
)

// fakeClock is a controllable clock used to make the failure cooldown behavior
// fully deterministic.
type fakeClock struct {
	t time.Time
}

func newFakeClock() *fakeClock {
	// Start in the past relative to the real wall clock: addresses created
	// by the manager carry real "now" timestamps, so this keeps chance()
	// from deprioritising every fixture address.
	// Start far enough in the past (more than ten minutes) relative to the
	// real wall clock so that attempt timestamps recorded through this
	// clock do not get deprioritised by chance()'s real-time weighting.
	return &fakeClock{t: time.Now().Add(-61 * time.Minute)}
}

func (c *fakeClock) now() time.Time { return c.t }
func (c *fakeClock) advance(d time.Duration) {
	c.t = c.t.Add(d)
}

// cooldownFixture builds an address manager with a failure cooldown window, a
// controllable clock and exactly three known routable addresses which have all
// been promoted into the tried bucket.  It returns the manager, its clock and
// the three fixture addresses.
func cooldownFixture(t *testing.T, cooldown time.Duration,
	clock *fakeClock) (*AddrManager, []*wire.NetAddressV2) {

	t.Helper()

	a := New(t.TempDir(), nil,
		WithFailureCooldown(cooldown),
		withNowFunc(clock.now),
	)
	src := wire.NetAddressV2FromBytes(
		time.Now(), wire.SFNodeNetwork, net.IPv4(173, 144, 173, 111),
		8333,
	)
	ips := []net.IP{
		net.IPv4(1, 2, 3, 4),
		net.IPv4(5, 6, 7, 8),
		net.IPv4(9, 10, 11, 12),
	}
	addrs := make([]*wire.NetAddressV2, len(ips))
	for i, ip := range ips {
		addrs[i] = wire.NetAddressV2FromBytes(
			time.Now(), wire.SFNodeNetwork, ip, 8333,
		)
		a.AddAddress(addrs[i], src)
		// Promote the address into the tried bucket so selection does
		// not depend on new/tried bucket hashing.
		a.Good(addrs[i])
	}
	if a.NumAddresses() != len(addrs) {
		t.Fatalf("expected %d addresses, got %d", len(addrs),
			a.NumAddresses())
	}
	return a, addrs
}

// selectionPossible reports whether a call to GetAddress can return the given
// address.  It samples a number of draws to account for the manager's random,
// chance-weighted selection.
func selectionPossible(t *testing.T, a *AddrManager,
	want *wire.NetAddressV2, draws int) bool {

	t.Helper()
	for i := 0; i < draws; i++ {
		ka := a.GetAddress()
		if ka == nil {
			continue
		}
		if NetAddressKey(ka.NetAddress()) == NetAddressKey(want) {
			return true
		}
	}
	return false
}

// reportFailure mirrors the real connection flow: an attempt followed by a
// failure report.
func reportFailure(a *AddrManager, addr *wire.NetAddressV2) {
	a.Attempt(addr)
	a.Failed(addr)
}

// assertOnlySelectable verifies GetAddress deterministically returns only the
// expected address, which is possible when it is the single non-cooling
// candidate.
func assertOnlySelectable(t *testing.T, a *AddrManager,
	want *wire.NetAddressV2) {

	t.Helper()
	for i := 0; i < 10; i++ {
		ka := a.GetAddress()
		if ka == nil {
			t.Fatalf("expected only %s to be selectable, got nil",
				NetAddressKey(want))
		}
		if NetAddressKey(ka.NetAddress()) != NetAddressKey(want) {
			t.Fatalf("expected %s to be the only selectable "+
				"address, got %s", NetAddressKey(want),
				NetAddressKey(ka.NetAddress()))
		}
	}
}

// assertEmpty asserts the explicit empty result: every candidate is cooling
// down so GetAddress must repeatedly return nil.
func assertEmpty(t *testing.T, a *AddrManager) {
	t.Helper()
	for i := 0; i < 10; i++ {
		if ka := a.GetAddress(); ka != nil {
			t.Fatalf("expected nil while every candidate is cooling "+
				"down, got %s", NetAddressKey(ka.NetAddress()))
		}
	}
}

// TestFailureCooldownWindow verifies the optional failure cooldown window with
// a controllable clock and a three-address fixture: failed addresses are
// skipped during the window, all candidates cooling down yields an explicit
// empty result, addresses recover once the window elapses (or immediately after
// a success), and the default strategy without the option is left unchanged.
func TestFailureCooldownWindow(t *testing.T) {
	const cooldown = 60 * time.Second

	clock := newFakeClock()
	a, addrs := cooldownFixture(t, cooldown, clock)
	addr1, addr2, addr3 := addrs[0], addrs[1], addrs[2]

	// Sanity check: with no failures every address is selectable.
	for _, addr := range addrs {
		if !selectionPossible(t, a, addr, 50) {
			t.Fatalf("address %s should be selectable before any "+
				"failure", NetAddressKey(addr))
		}
	}

	// t0: fail addr1.  It is skipped while the other two stay selectable.
	reportFailure(a, addr1)
	{
		ka := a.find(addr1)
		got := ka.LastFailed()
		if !got.Equal(clock.now()) {
			t.Fatalf("expected LastFailed %v, got %v", clock.now(),
				got)
		}
		if !a.find(addr2).LastFailed().IsZero() {
			t.Fatal("expected LastFailed to be zero for an address " +
				"that has never failed")
		}
	}
	if selectionPossible(t, a, addr1, 50) {
		t.Fatalf("failed address %s should be skipped during the "+
			"cooldown window", NetAddressKey(addr1))
	}
	if !selectionPossible(t, a, addr2, 50) {
		t.Fatalf("address %s should remain selectable while another "+
			"address is cooling down", NetAddressKey(addr2))
	}
	if !selectionPossible(t, a, addr3, 50) {
		t.Fatalf("address %s should remain selectable while another "+
			"address is cooling down", NetAddressKey(addr3))
	}

	// t0+20s: fail addr2.  addr1 is still cooling (until t0+60s) so addr3
	// is the sole selectable candidate.
	clock.advance(20 * time.Second)
	reportFailure(a, addr2)
	assertOnlySelectable(t, a, addr3)

	// t0+40s: fail addr3 as well.  All three candidates are now cooling
	// (addr1 until t0+60s, addr2 until t0+80s, addr3 until t0+100s), so
	// the manager must return an explicit empty result.
	clock.advance(20 * time.Second)
	reportFailure(a, addr3)
	assertEmpty(t, a)

	// Inside the window boundaries the empty result must persist.
	clock.advance(19 * time.Second) // t0+59s
	assertEmpty(t, a)

	// At t0+60s addr1's window elapses: it recovers and is the only
	// selectable address, so GetAddress deterministically returns it.
	clock.advance(time.Second)
	assertOnlySelectable(t, a, addr1)

	// At t0+80s addr2 recovers as well; addr3 remains cooling.
	clock.advance(20 * time.Second)
	if !selectionPossible(t, a, addr1, 50) {
		t.Fatalf("address %s should have recovered", NetAddressKey(addr1))
	}
	if !selectionPossible(t, a, addr2, 50) {
		t.Fatalf("address %s should have recovered", NetAddressKey(addr2))
	}
	if selectionPossible(t, a, addr3, 50) {
		t.Fatalf("address %s should still be cooling down",
			NetAddressKey(addr3))
	}

	// At t0+100s all three candidates have recovered.
	clock.advance(20 * time.Second)
	for _, addr := range addrs {
		if !selectionPossible(t, a, addr, 50) {
			t.Fatalf("address %s should have recovered once its "+
				"cooldown elapsed", NetAddressKey(addr))
		}
	}

	// A success clears a failure immediately, independent of the clock.
	reportFailure(a, addr1)
	if selectionPossible(t, a, addr1, 50) {
		t.Fatalf("re-failed address %s should be skipped",
			NetAddressKey(addr1))
	}
	a.Good(addr1)
	if !a.find(addr1).LastFailed().IsZero() {
		t.Fatal("expected a success to clear the last failure time")
	}
	if !selectionPossible(t, a, addr1, 50) {
		t.Fatalf("address %s should be selectable again after a "+
			"success clears the failure", NetAddressKey(addr1))
	}

	// Reporting a failure for an unknown address is a no-op.
	unknown := wire.NetAddressV2FromBytes(
		time.Now(), wire.SFNodeNetwork, net.IPv4(66, 66, 66, 66),
		8333,
	)
	a.Failed(unknown)
}

// TestFailureCooldownEmptyManager ensures the explicit empty result also holds
// when there are no known addresses at all.
func TestFailureCooldownEmptyManager(t *testing.T) {
	clock := newFakeClock()
	a := New(t.TempDir(), nil,
		WithFailureCooldown(time.Minute),
		withNowFunc(clock.now),
	)
	if ka := a.GetAddress(); ka != nil {
		t.Fatalf("expected nil from an empty manager, got %s",
			NetAddressKey(ka.NetAddress()))
	}
}

// TestDefaultStrategyIgnoresFailures verifies that without the
// WithFailureCooldown option the historical selection strategy is unchanged:
// even a just-failed address can still be returned.
func TestDefaultStrategyIgnoresFailures(t *testing.T) {
	clock := newFakeClock()
	a := New(t.TempDir(), nil, withNowFunc(clock.now))
	src := wire.NetAddressV2FromBytes(
		time.Now(), wire.SFNodeNetwork, net.IPv4(173, 144, 173, 111),
		8333,
	)
	addr := wire.NetAddressV2FromBytes(
		time.Now(), wire.SFNodeNetwork, net.IPv4(8, 8, 8, 8), 8333,
	)
	a.AddAddress(addr, src)

	a.Failed(addr)
	if got := a.GetAddress(); got == nil {
		t.Fatal("default strategy should still return the failed " +
			"address, got nil")
	} else if NetAddressKey(got.NetAddress()) != NetAddressKey(addr) {
		t.Fatalf("default strategy returned %s, want %s",
			NetAddressKey(got.NetAddress()), NetAddressKey(addr))
	}
}
