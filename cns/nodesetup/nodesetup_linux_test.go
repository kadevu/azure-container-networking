// Copyright Microsoft. All rights reserved.
// MIT License

package nodesetup

import (
	"net"
	"os"
	"testing"

	"github.com/Azure/azure-container-networking/cns/logger"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	//nolint:staticcheck // SA1019: suppress deprecated logger.InitLogger usage. Todo: legacy logger usage is consistent in cns repo. Migrates when all logger usage is migrated
	logger.InitLogger("testlogs", 0, 0, "./")
	os.Exit(m.Run())
}

func TestWireserverIPRules(t *testing.T) {
	rules, err := wireserverIPRules("168.63.129.16")
	require.NoError(t, err)
	require.Len(t, rules, 1)

	rule := rules[0]
	assert.Equal(t, "168.63.129.16/32", rule.Dst.String())
	assert.Equal(t, unix.RT_TABLE_MAIN, rule.Table)
	assert.Equal(t, wireserverRulePriority, rule.Priority)
}

var (
	errMockRuleList = errors.New("mock rule list error")
	errMockRuleAdd  = errors.New("mock rule add error")
)

func TestRun(t *testing.T) {
	wireserverCIDR := "168.63.129.16/32"
	_, wireserverNet, _ := net.ParseCIDR(wireserverCIDR)

	tests := []struct {
		name          string
		expectedErr   string
		expectedAdded int
		listFn        func() ([]ipRule, error)
		addFn         func(ipRule) error
	}{
		{
			name:          "adds wireserver rule when rule does not exist",
			expectedAdded: 1,
			listFn:        func() ([]ipRule, error) { return nil, nil },
		},
		{
			name:          "skips wireserver rule when it already exists (idempotency)",
			expectedAdded: 0,
			listFn: func() ([]ipRule, error) {
				return []ipRule{
					{Dst: wireserverNet, Table: unix.RT_TABLE_MAIN, Priority: wireserverRulePriority},
				}, nil
			},
		},
		{
			name:        "returns error when list fails",
			expectedErr: "failed to list existing ip rules",
			listFn:      func() ([]ipRule, error) { return nil, errMockRuleList },
		},
		{
			name:        "returns error when add fails",
			expectedErr: "failed to add ip rule",
			listFn:      func() ([]ipRule, error) { return nil, nil },
			addFn:       func(_ ipRule) error { return errMockRuleAdd },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var addedRules []ipRule

			origList := listIPRules
			origAdd := addIPRuleFn
			defer func() {
				listIPRules = origList
				addIPRuleFn = origAdd
			}()

			listIPRules = tt.listFn
			if tt.addFn != nil {
				addIPRuleFn = tt.addFn
			} else {
				addIPRuleFn = func(rule ipRule) error {
					addedRules = append(addedRules, rule)
					return nil
				}
			}

			err := Run("168.63.129.16")

			if tt.expectedErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			} else {
				require.NoError(t, err)
			}

			assert.Len(t, addedRules, tt.expectedAdded)
			if tt.expectedAdded > 0 {
				assert.Equal(t, wireserverCIDR, addedRules[0].Dst.String())
				assert.Equal(t, unix.RT_TABLE_MAIN, addedRules[0].Table)
				assert.Equal(t, wireserverRulePriority, addedRules[0].Priority)
			}
		})
	}
}
