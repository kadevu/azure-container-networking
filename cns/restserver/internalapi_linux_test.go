// Copyright 2020 Microsoft. All rights reserved.
// MIT License

package restserver

import (
	"net"
	"strconv"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/cns/fakes"
	"github.com/Azure/azure-container-networking/cns/types"
	"github.com/Azure/azure-container-networking/common"
	"github.com/Azure/azure-container-networking/iptables"
	"github.com/Azure/azure-container-networking/network/networkutils"
)

type FakeIPTablesProvider struct {
	iptables       *fakes.IPTablesMock
	iptablesLegacy *fakes.IPTablesLegacyMock
}

func (c *FakeIPTablesProvider) GetIPTables() (iptablesClient, error) {
	// persist iptables in testing
	if c.iptables == nil {
		c.iptables = fakes.NewIPTablesMock()
	}
	return c.iptables, nil
}

func (c *FakeIPTablesProvider) GetIPTablesLegacy() (iptablesLegacyClient, error) {
	if c.iptablesLegacy == nil {
		c.iptablesLegacy = &fakes.IPTablesLegacyMock{}
	}
	return c.iptablesLegacy, nil
}

func TestAddSNATRules(t *testing.T) {
	type chainExpectation struct {
		table    string
		chain    string
		expected []string
	}

	type preExistingRule struct {
		table string
		chain string
		rule  []string
	}

	tests := []struct {
		name                    string
		input                   *cns.CreateNetworkContainerRequest
		preExistingRules        []preExistingRule
		expectedChains          []chainExpectation
		expectedClearChainCalls int
	}{
		{
			// in pod subnet, the primary nic ip is in the same address space as the pod subnet
			name: "podsubnet",
			input: &cns.CreateNetworkContainerRequest{
				NetworkContainerid: ncID,
				IPConfiguration: cns.IPConfiguration{
					IPSubnet: cns.IPSubnet{
						IPAddress:    "240.1.2.1",
						PrefixLength: 24,
					},
				},
				SecondaryIPConfigs: map[string]cns.SecondaryIPConfig{
					"abc": {
						IPAddress: "240.1.2.7",
					},
				},
				HostPrimaryIP: "10.0.0.4",
			},
			expectedChains: []chainExpectation{
				{
					table: iptables.Nat,
					chain: SWIFTPOSTROUTING,
					expected: []string{
						"-N SWIFT-POSTROUTING",
						"-A SWIFT-POSTROUTING -m addrtype ! --dst-type local -s 240.1.2.0/24 -d " + networkutils.AzureDNS + " -p udp --dport " + strconv.Itoa(iptables.DNSPort) + " -j SNAT --to 10.0.0.4",
						"-A SWIFT-POSTROUTING -m addrtype ! --dst-type local -s 240.1.2.0/24 -d " + networkutils.AzureDNS + " -p tcp --dport " + strconv.Itoa(iptables.DNSPort) + " -j SNAT --to 10.0.0.4",
						"-A SWIFT-POSTROUTING -m addrtype ! --dst-type local -s 240.1.2.0/24 -d " + networkutils.AzureIMDS + " -p tcp --dport " + strconv.Itoa(iptables.HTTPPort) + " -j SNAT --to 10.0.0.4",
					},
				},
				{
					table: iptables.Nat,
					chain: iptables.Postrouting,
					expected: []string{
						"-P POSTROUTING ACCEPT",
						"-A POSTROUTING -j SWIFT-POSTROUTING",
					},
				},
			},
			expectedClearChainCalls: 1,
		},
		{
			// test with pre-existing SWIFT rule that should be migrated
			name: "migration from old SWIFT",
			input: &cns.CreateNetworkContainerRequest{
				NetworkContainerid: ncID,
				IPConfiguration: cns.IPConfiguration{
					IPSubnet: cns.IPSubnet{
						IPAddress:    "240.1.2.1",
						PrefixLength: 24,
					},
				},
				SecondaryIPConfigs: map[string]cns.SecondaryIPConfig{
					"abc": {
						IPAddress: "240.1.2.7",
					},
				},
				HostPrimaryIP: "10.0.0.4",
			},
			preExistingRules: []preExistingRule{
				{
					table: iptables.Nat,
					chain: iptables.Postrouting,
					rule:  []string{"-j", "SWIFT"},
				},
				{
					// stale rule at lower priority should be cleaned up
					table: iptables.Nat,
					chain: iptables.Postrouting,
					rule:  []string{"-j", "SWIFT-POSTROUTING"},
				},
				{
					// should be cleaned up
					table: iptables.Nat,
					chain: SWIFTPOSTROUTING,
					rule: []string{
						"-m", "addrtype", "!", "--dst-type", "local", "-s", "240.1.2.0/24", "-d", networkutils.AzureDNS,
						"-p", "udp", "--dport", strconv.Itoa(iptables.DNSPort), "-j", "SNAT", "--to", "99.1.2.1",
					},
				},
				{
					table: iptables.Nat,
					chain: "SWIFT",
					rule: []string{
						"-m", "addrtype", "!", "--dst-type", "local", "-s", "240.1.2.0/24", "-d", networkutils.AzureDNS,
						"-p", "udp", "--dport", strconv.Itoa(iptables.DNSPort), "-j", "SNAT", "--to", "192.1.2.1",
					},
				},
			},
			expectedChains: []chainExpectation{
				{
					table: iptables.Nat,
					chain: SWIFTPOSTROUTING,
					expected: []string{
						"-N SWIFT-POSTROUTING",
						"-A SWIFT-POSTROUTING -m addrtype ! --dst-type local -s 240.1.2.0/24 -d " + networkutils.AzureDNS + " -p udp --dport " + strconv.Itoa(iptables.DNSPort) + " -j SNAT --to 10.0.0.4",
						"-A SWIFT-POSTROUTING -m addrtype ! --dst-type local -s 240.1.2.0/24 -d " + networkutils.AzureDNS + " -p tcp --dport " + strconv.Itoa(iptables.DNSPort) + " -j SNAT --to 10.0.0.4",
						"-A SWIFT-POSTROUTING -m addrtype ! --dst-type local -s 240.1.2.0/24 -d " + networkutils.AzureIMDS + " -p tcp --dport " + strconv.Itoa(iptables.HTTPPort) + " -j SNAT --to 10.0.0.4",
					},
				},
				{
					table: iptables.Nat,
					chain: iptables.Postrouting,
					expected: []string{
						"-P POSTROUTING ACCEPT",
						"-A POSTROUTING -j SWIFT-POSTROUTING",
						"-A POSTROUTING -j SWIFT",
					},
				},
				{
					// stale old rule can remain
					table: iptables.Nat,
					chain: "SWIFT",
					expected: []string{
						"-N SWIFT",
						"-A SWIFT -m addrtype ! --dst-type local -s 240.1.2.0/24 -d " + networkutils.AzureDNS + " -p udp --dport " + strconv.Itoa(iptables.DNSPort) + " -j SNAT --to 192.1.2.1",
					},
				},
			},
			expectedClearChainCalls: 1,
		},
		{
			// test after migration has already completed
			name: "after migration from old SWIFT",
			input: &cns.CreateNetworkContainerRequest{
				NetworkContainerid: ncID,
				IPConfiguration: cns.IPConfiguration{
					IPSubnet: cns.IPSubnet{
						IPAddress:    "240.1.2.1",
						PrefixLength: 24,
					},
				},
				SecondaryIPConfigs: map[string]cns.SecondaryIPConfig{
					"abc": {
						IPAddress: "240.1.2.7",
					},
				},
				HostPrimaryIP: "10.0.0.4",
			},
			preExistingRules: []preExistingRule{
				{
					// rule at higher priority means nothing happens
					table: iptables.Nat,
					chain: iptables.Postrouting,
					rule:  []string{"-j", "SWIFT-POSTROUTING"},
				},
				{
					table: iptables.Nat,
					chain: iptables.Postrouting,
					rule:  []string{"-j", "SWIFT"},
				},
				{
					table: iptables.Nat,
					chain: SWIFTPOSTROUTING,
					rule: []string{
						"-m", "addrtype", "!", "--dst-type", "local", "-s", "240.1.2.0/24", "-d", networkutils.AzureDNS,
						"-p", "udp", "--dport", strconv.Itoa(iptables.DNSPort), "-j", "SNAT", "--to", "10.0.0.4",
					},
				},
				{
					table: iptables.Nat,
					chain: SWIFTPOSTROUTING,
					rule: []string{
						"-m", "addrtype", "!", "--dst-type", "local", "-s", "240.1.2.0/24", "-d", networkutils.AzureDNS,
						"-p", "tcp", "--dport", strconv.Itoa(iptables.DNSPort), "-j", "SNAT", "--to", "10.0.0.4",
					},
				},
				{
					table: iptables.Nat,
					chain: SWIFTPOSTROUTING,
					rule: []string{
						"-m", "addrtype", "!", "--dst-type", "local", "-s", "240.1.2.0/24", "-d", networkutils.AzureIMDS,
						"-p", "tcp", "--dport", strconv.Itoa(iptables.HTTPPort), "-j", "SNAT", "--to", "10.0.0.4",
					},
				},
				{
					table: iptables.Nat,
					chain: "SWIFT",
					rule: []string{
						"-m", "addrtype", "!", "--dst-type", "local", "-s", "240.1.2.0/24", "-d", networkutils.AzureDNS,
						"-p", "udp", "--dport", strconv.Itoa(iptables.DNSPort), "-j", "SNAT", "--to", "192.1.2.1",
					},
				},
			},
			expectedChains: []chainExpectation{
				{
					table: iptables.Nat,
					chain: SWIFTPOSTROUTING,
					expected: []string{
						"-N SWIFT-POSTROUTING",
						"-A SWIFT-POSTROUTING -m addrtype ! --dst-type local -s 240.1.2.0/24 -d " + networkutils.AzureDNS + " -p udp --dport " + strconv.Itoa(iptables.DNSPort) + " -j SNAT --to 10.0.0.4",
						"-A SWIFT-POSTROUTING -m addrtype ! --dst-type local -s 240.1.2.0/24 -d " + networkutils.AzureDNS + " -p tcp --dport " + strconv.Itoa(iptables.DNSPort) + " -j SNAT --to 10.0.0.4",
						"-A SWIFT-POSTROUTING -m addrtype ! --dst-type local -s 240.1.2.0/24 -d " + networkutils.AzureIMDS + " -p tcp --dport " + strconv.Itoa(iptables.HTTPPort) + " -j SNAT --to 10.0.0.4",
					},
				},
				{
					table: iptables.Nat,
					chain: iptables.Postrouting,
					expected: []string{
						"-P POSTROUTING ACCEPT",
						"-A POSTROUTING -j SWIFT-POSTROUTING",
						"-A POSTROUTING -j SWIFT",
					},
				},
				{
					// stale old rule can remain
					table: iptables.Nat,
					chain: "SWIFT",
					expected: []string{
						"-N SWIFT",
						"-A SWIFT -m addrtype ! --dst-type local -s 240.1.2.0/24 -d " + networkutils.AzureDNS + " -p udp --dport " + strconv.Itoa(iptables.DNSPort) + " -j SNAT --to 192.1.2.1",
					},
				},
			},
			expectedClearChainCalls: 0,
		},
		{
			// in vnet scale, the primary nic ip becomes the node ip (diff address space from pod subnet)
			name: "vnet scale",
			input: &cns.CreateNetworkContainerRequest{
				NetworkContainerid: ncID,
				IPConfiguration: cns.IPConfiguration{
					IPSubnet: cns.IPSubnet{
						IPAddress:    "10.0.0.4",
						PrefixLength: 28,
					},
				},
				SecondaryIPConfigs: map[string]cns.SecondaryIPConfig{
					"abc": {
						IPAddress: "240.1.2.15",
					},
				},
				HostPrimaryIP: "10.0.0.4",
			},
			expectedChains: []chainExpectation{
				{
					table: iptables.Nat,
					chain: SWIFTPOSTROUTING,
					expected: []string{
						"-N SWIFT-POSTROUTING",
						"-A SWIFT-POSTROUTING -m addrtype ! --dst-type local -s 240.1.2.0/28 -d " + networkutils.AzureDNS + " -p udp --dport " + strconv.Itoa(iptables.DNSPort) + " -j SNAT --to 10.0.0.4",
						"-A SWIFT-POSTROUTING -m addrtype ! --dst-type local -s 240.1.2.0/28 -d " + networkutils.AzureDNS + " -p tcp --dport " + strconv.Itoa(iptables.DNSPort) + " -j SNAT --to 10.0.0.4",
						"-A SWIFT-POSTROUTING -m addrtype ! --dst-type local -s 240.1.2.0/28 -d " + networkutils.AzureIMDS + " -p tcp --dport " + strconv.Itoa(iptables.HTTPPort) + " -j SNAT --to 10.0.0.4",
					},
				},
				{
					table: iptables.Nat,
					chain: iptables.Postrouting,
					expected: []string{
						"-P POSTROUTING ACCEPT",
						"-A POSTROUTING -j SWIFT-POSTROUTING",
					},
				},
			},
			expectedClearChainCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := getTestService(cns.KubernetesCRD)
			ipt := fakes.NewIPTablesMock()
			iptl := &fakes.IPTablesLegacyMock{}
			service.iptables = &FakeIPTablesProvider{
				iptables:       ipt,
				iptablesLegacy: iptl,
			}

			// setup pre-existing rules
			if len(tt.preExistingRules) > 0 {
				for _, preRule := range tt.preExistingRules {
					chainExists, _ := ipt.ChainExists(preRule.table, preRule.chain)

					if !chainExists {
						err := ipt.NewChain(preRule.table, preRule.chain)
						if err != nil {
							t.Fatal("failed to setup pre-existing rule chain:", err)
						}
					}

					err := ipt.Append(preRule.table, preRule.chain, preRule.rule...)
					if err != nil {
						t.Fatal("failed to setup pre-existing rule:", err)
					}
				}
			}

			resp, msg := service.programSNATRules(tt.input)
			if resp != types.Success {
				t.Fatal("failed to program snat rules", msg)
			}

			// verify chain contents using List
			for _, chainExp := range tt.expectedChains {
				actualRules, err := ipt.List(chainExp.table, chainExp.chain)
				if err != nil {
					t.Fatal("failed to list rules for chain", chainExp.chain, ":", err)
				}

				if len(actualRules) != len(chainExp.expected) {
					t.Fatalf("chain %s rule count mismatch: got %d, expected %d\nActual: %v\nExpected: %v",
						chainExp.chain, len(actualRules), len(chainExp.expected), actualRules, chainExp.expected)
				}

				for i, expectedRule := range chainExp.expected {
					if actualRules[i] != expectedRule {
						t.Fatalf("chain %s rule %d mismatch:\nActual:   %s\nExpected: %s",
							chainExp.chain, i, actualRules[i], expectedRule)
					}
				}
			}

			// verify ClearChain was called the expected number of times
			actualClearChainCalls := ipt.ClearChainCallCount()
			if actualClearChainCalls != tt.expectedClearChainCalls {
				t.Fatalf("ClearChain call count mismatch: got %d, expected %d", actualClearChainCalls, tt.expectedClearChainCalls)
			}

			// verify we delete legacy swift postrouting jump
			actualLegacyDeleteCalls := iptl.DeleteCallCount()
			if actualLegacyDeleteCalls != 1 {
				t.Fatalf("Delete call count mismatch: got %d, expected 1", actualLegacyDeleteCalls)
			}
		})
	}
}

// ipRuleClientMock is a test mock for IPRuleClient.
type ipRuleClientMock struct {
	rules       []IPRule
	ruleListErr error
	ruleAddErr  error
	addedRules  []IPRule
}

func (m *ipRuleClientMock) RuleList(_ int) ([]IPRule, error) {
	if m.ruleListErr != nil {
		return nil, m.ruleListErr
	}
	return m.rules, nil
}

func (m *ipRuleClientMock) RuleAdd(rule *IPRule) error {
	if m.ruleAddErr != nil {
		return m.ruleAddErr
	}
	m.addedRules = append(m.addedRules, *rule)
	return nil
}

func TestWireserverIPRules(t *testing.T) {
	rules, err := wireserverIPRules()
	require.NoError(t, err)
	require.Len(t, rules, 1)

	rule := rules[0]
	assert.Equal(t, WireserverIP+"/32", rule.Dst.String())
	assert.Equal(t, unix.RT_TABLE_MAIN, rule.Table)
	assert.Equal(t, WireserverRulePriority, rule.Priority)
}

var (
	errMockRuleList = errors.New("mock rule list error")
	errMockRuleAdd  = errors.New("mock rule add error")
)

func TestAddRules(t *testing.T) {
	wireserverCIDR := WireserverIP + "/32"
	_, wireserverNet, _ := net.ParseCIDR(wireserverCIDR)

	tests := []struct {
		name          string
		ipruleclient  IPRuleClient
		optEnabled    bool
		expectedErr   string
		expectedAdded int
		setupMock     func(*ipRuleClientMock)
	}{
		{
			name:          "no-op when ipruleclient is nil",
			ipruleclient:  nil,
			optEnabled:    true,
			expectedAdded: 0,
		},
		{
			name:          "no-op when option is disabled",
			optEnabled:    false,
			expectedAdded: 0,
			setupMock:     func(_ *ipRuleClientMock) {},
		},
		{
			name:          "adds wireserver rule when option enabled and rule does not exist",
			optEnabled:    true,
			expectedAdded: 1,
			setupMock:     func(_ *ipRuleClientMock) {},
		},
		{
			name:          "skips wireserver rule when it already exists (idempotency)",
			optEnabled:    true,
			expectedAdded: 0,
			setupMock: func(m *ipRuleClientMock) {
				m.rules = []IPRule{
					{Dst: wireserverNet, Table: unix.RT_TABLE_MAIN, Priority: WireserverRulePriority},
				}
			},
		},
		{
			name:        "returns error when RuleList fails",
			optEnabled:  true,
			expectedErr: "failed to list existing ip rules",
			setupMock: func(m *ipRuleClientMock) {
				m.ruleListErr = errMockRuleList
			},
		},
		{
			name:        "returns error when RuleAdd fails",
			optEnabled:  true,
			expectedErr: "failed to add ip rule",
			setupMock: func(m *ipRuleClientMock) {
				m.ruleAddErr = errMockRuleAdd
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testSvc := getTestService(cns.KubernetesCRD)

			if tt.ipruleclient != nil || tt.setupMock != nil {
				mock := &ipRuleClientMock{}
				if tt.setupMock != nil {
					tt.setupMock(mock)
				}
				testSvc.ipruleclient = mock

				if tt.optEnabled {
					testSvc.SetOption(common.OptVnetBlockDualStackSwiftV2, true)
				}

				err := testSvc.AddRules()

				if tt.expectedErr != "" {
					require.Error(t, err)
					assert.Contains(t, err.Error(), tt.expectedErr)
				} else {
					require.NoError(t, err)
				}

				assert.Len(t, mock.addedRules, tt.expectedAdded)
				if tt.expectedAdded > 0 {
					assert.Equal(t, wireserverCIDR, mock.addedRules[0].Dst.String())
					assert.Equal(t, unix.RT_TABLE_MAIN, mock.addedRules[0].Table)
					assert.Equal(t, WireserverRulePriority, mock.addedRules[0].Priority)
				}
			} else {
				// nil ipruleclient case
				testSvc.ipruleclient = nil
				if tt.optEnabled {
					testSvc.SetOption(common.OptVnetBlockDualStackSwiftV2, true)
				}
				err := testSvc.AddRules()
				require.NoError(t, err)
			}
		})
	}
}
