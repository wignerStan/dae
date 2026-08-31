/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import "testing"

func TestShouldWaitForNetwork(t *testing.T) {
	tests := []struct {
		name              string
		disabled          bool
		prepareOnly       bool
		subscriptionCount int
		externalPolicy    bool
		want              bool
	}{
		{name: "initial startup", want: true},
		{name: "ordinary staged reload", prepareOnly: true, want: true},
		{name: "external staged reload with dae subscriptions", prepareOnly: true, subscriptionCount: 1, externalPolicy: true, want: true},
		{name: "external staged reload without dae subscriptions", prepareOnly: true, externalPolicy: true, want: false},
		{name: "explicitly disabled", disabled: true, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := shouldWaitForNetwork(test.disabled, test.prepareOnly, test.subscriptionCount, test.externalPolicy)
			if got != test.want {
				t.Fatalf("shouldWaitForNetwork() = %t, want %t", got, test.want)
			}
		})
	}
}
