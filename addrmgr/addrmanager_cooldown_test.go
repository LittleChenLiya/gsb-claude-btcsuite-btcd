// Copyright (c) 2024 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package addrmgr

import (
	"net"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire/v2"
)

// cooldownFixture returns three distinct, routable network addresses used to
// exercise the failure cooldown window. The addresses are given the supplied
// timestamp so the fixture is fully deterministic.
func cooldownFixture(ts time.Time) []*wire.NetAddressV2 {
	ips := []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"}
	addrs := make([]*wire.NetAddressV2, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, wire.NetAddressV2FromBytes(
			ts, wire.SFNodeNetwork, net.ParseIP(ip), 8333,
		))
	}
	return addrs
}

// sampleKeys calls GetAddress n times and returns the set of address keys that
// were selected. It is used to observe which addresses are eligible during the
// various phases of the cooldown window.
func sampleKeys(t *testing.T, am *AddrManager, n int) map[string]struct{} {
	t.Helper()

	seen := make(map[string]struct{})
	for i := 0; i < n; i++ {
		ka := am.GetAddress()
		if ka == nil {
			continue
		}
		seen[NetAddressKey(ka.na)] = struct{}{}
	}
	return seen
}

// assertNeverSelected fails the test if any of the supplied keys appear in the
// sampled set.
func assertNeverSelected(t *testing.T, seen map[string]struct{},
	keys ...string) {

	t.Helper()
	for _, key := range keys {
		if _, ok := seen[key]; ok {
			t.Errorf("address %s should have been skipped during "+
				"cooldown but was selected", key)
		}
	}
}

// assertAllSelected fails the test if any of the supplied keys are missing
// from the sampled set.
func assertAllSelected(t *testing.T, seen map[string]struct{},
	keys ...string) {

	t.Helper()
	for _, key := range keys {
		if _, ok := seen[key]; !ok {
			t.Errorf("address %s should have been selectable but "+
				"was never returned", key)
		}
	}
}

// TestFailureCooldown drives a three-address fixture through failure,
// cooldown, recovery and the all-cooling empty-result boundary using a
// controllable clock.
func TestFailureCooldown(t *testing.T) {
	t.Parallel()

	const cooldown = 10 * time.Minute

	// Controllable clock: the whole test runs at a fixed base time and we
	// advance it explicitly to cross the cooldown boundary.
	base := time.Unix(1_600_000_000, 0)
	now := base

	am := New(t.TempDir(), nil, WithFailureCooldown(cooldown))
	am.now = func() time.Time { return now }

	addrs := cooldownFixture(base)
	for _, na := range addrs {
		am.AddAddress(na, na)
	}

	keys := make([]string, len(addrs))
	for i, na := range addrs {
		keys[i] = NetAddressKey(na)
	}
	keyA, keyB, keyC := keys[0], keys[1], keys[2]

	// Before any failure all three addresses are selectable.
	if ka := am.GetAddress(); ka == nil {
		t.Fatalf("expected an address from a full pool, got nil")
	}
	seen := sampleKeys(t, am, 5000)
	assertAllSelected(t, seen, keyA, keyB, keyC)

	// Fail address A at the base time.
	now = base
	am.Failed(addrs[0])
	if got := am.find(addrs[0]).LastFailure(); !got.Equal(base) {
		t.Fatalf("expected lastfailure %v, got %v", base, got)
	}

	// While inside the cooldown window A must be skipped, but B and C
	// remain eligible.
	now = base.Add(cooldown / 2)
	if !am.coolingDown(am.find(addrs[0])) {
		t.Fatalf("address A should be cooling down at base+%v",
			cooldown/2)
	}
	seen = sampleKeys(t, am, 5000)
	assertNeverSelected(t, seen, keyA)
	assertAllSelected(t, seen, keyB, keyC)

	// Failing B and C as well puts every candidate into cooldown. The
	// selection must then return a clear empty result instead of spinning.
	now = base
	am.Failed(addrs[1])
	am.Failed(addrs[2])
	now = base.Add(cooldown / 2)
	if ka := am.GetAddress(); ka != nil {
		t.Fatalf("expected nil when all candidates are cooling, got %v",
			NetAddressKey(ka.na))
	}
	if am.hasSelectableAddress() {
		t.Fatalf("expected no selectable addresses while all are cooling")
	}

	// Once the clock moves past the cooldown boundary all addresses recover
	// and selection returns non-nil again, with A back in the rotation.
	now = base.Add(cooldown + time.Second)
	if am.coolingDown(am.find(addrs[0])) {
		t.Fatalf("address A should have recovered after cooldown")
	}
	if ka := am.GetAddress(); ka == nil {
		t.Fatalf("expected an address after recovery, got nil")
	}
	seen = sampleKeys(t, am, 5000)
	assertAllSelected(t, seen, keyA, keyB, keyC)
}

// TestFailureCooldownDisabled ensures that when no cooldown window is
// configured (the default), the original selection policy is preserved:
// failed addresses are never skipped and the pool never returns an empty
// result due to cooldown.
func TestFailureCooldownDisabled(t *testing.T) {
	t.Parallel()

	base := time.Unix(1_600_000_000, 0)
	now := base

	// No WithFailureCooldown option: cooldownDuration stays zero.
	am := New(t.TempDir(), nil)
	am.now = func() time.Time { return now }

	addrs := cooldownFixture(base)
	for _, na := range addrs {
		am.AddAddress(na, na)
	}

	// Fail every address; with the cooldown disabled this must have no
	// effect on selection.
	now = base
	for _, na := range addrs {
		am.Failed(na)
	}
	if !am.hasSelectableAddress() {
		t.Fatalf("hasSelectableAddress should report true when cooldown is disabled")
	}
	for _, na := range addrs {
		if am.coolingDown(am.find(na)) {
			t.Fatalf("address %s should never be cooling when cooldown is disabled",
				NetAddressKey(na))
		}
	}

	// Repeated selection must always return a candidate, never nil.
	for i := 0; i < 100; i++ {
		if ka := am.GetAddress(); ka == nil {
			t.Fatalf("GetAddress returned nil with cooldown disabled")
		}
	}
}

// TestFailureCooldownClearedOnGood verifies that a successful connection
// clears a prior failure record so the address is immediately eligible.
func TestFailureCooldownClearedOnGood(t *testing.T) {
	t.Parallel()

	const cooldown = 10 * time.Minute
	base := time.Unix(1_600_000_000, 0)
	now := base

	am := New(t.TempDir(), nil, WithFailureCooldown(cooldown))
	am.now = func() time.Time { return now }

	addrs := cooldownFixture(base)
	for _, na := range addrs {
		am.AddAddress(na, na)
	}

	// Fail address A, then mark it good. The failure record must be cleared.
	now = base
	am.Failed(addrs[0])
	now = base.Add(time.Minute)
	am.Good(addrs[0])

	if got := am.find(addrs[0]).LastFailure(); !got.IsZero() {
		t.Fatalf("expected lastfailure to be cleared after Good, got %v",
			got)
	}
	if am.coolingDown(am.find(addrs[0])) {
		t.Fatalf("address A should not be cooling after a successful Good")
	}
}
