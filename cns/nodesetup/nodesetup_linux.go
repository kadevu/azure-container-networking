// Copyright Microsoft. All rights reserved.
// MIT License

package nodesetup

import (
	"net"

	"github.com/Azure/azure-container-networking/cns/logger"
	"github.com/pkg/errors"
	vishnetlink "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// wireserverRulePriority is the priority for the ip rule that routes wireserver traffic.
	// This ensures wireserver traffic goes through eth0 (infra NIC) even when other rules are added.
	wireserverRulePriority = 0
)

// ipRule is a simple representation of an IP routing rule,
// decoupled from the underlying netlink implementation.
type ipRule struct {
	Dst      *net.IPNet
	Table    int
	Priority int
}

// listIPRules and addIPRule encapsulate the netlink dependency.
// They are package-level variables to allow test injection.
var (
	listIPRules = defaultListIPRules
	addIPRuleFn = defaultAddIPRule
)

func defaultListIPRules() ([]ipRule, error) {
	rules, err := vishnetlink.RuleList(vishnetlink.FAMILY_V4)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list ip rules")
	}
	result := make([]ipRule, len(rules))
	for i := range rules {
		result[i] = ipRule{
			Dst:      rules[i].Dst,
			Table:    rules[i].Table,
			Priority: rules[i].Priority,
		}
	}
	return result, nil
}

func defaultAddIPRule(rule ipRule) error {
	nlRule := vishnetlink.NewRule()
	nlRule.Dst = rule.Dst
	nlRule.Table = rule.Table
	nlRule.Priority = rule.Priority
	return errors.Wrap(vishnetlink.RuleAdd(nlRule), "failed to add ip rule")
}

// Run performs one-time node-level setup.
// On Linux it programs ip rules to route wireserver traffic through the infra NIC.
// It is idempotent: rules that already exist are skipped.
func Run(wireserverIP string) error {
	rules, err := wireserverIPRules(wireserverIP)
	if err != nil {
		return err
	}

	if len(rules) == 0 {
		return nil
	}

	existing, err := listIPRules()
	if err != nil {
		return errors.Wrap(err, "failed to list existing ip rules")
	}

	for i := range rules {
		if err := ensureIPRule(rules[i], existing); err != nil {
			return err
		}
	}
	return nil
}

// wireserverIPRules returns ip rules to route wireserver traffic through the main routing table.
// For scenarios like Prefix on NIC v6 with Cilium CNI, pod traffic may be routed
// through eth1 (delegated NIC). These rules ensure critical traffic (e.g. wireserver)
// is routed through eth0 (infra NIC) via the main routing table.
func wireserverIPRules(wireserverIP string) ([]ipRule, error) {
	_, wireserverNet, err := net.ParseCIDR(wireserverIP + "/32")
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse wireserver IP %s", wireserverIP)
	}
	return []ipRule{
		{Dst: wireserverNet, Table: unix.RT_TABLE_MAIN, Priority: wireserverRulePriority},
	}, nil
}

// ensureIPRule programs a single ip rule if it does not already exist in the provided set.
func ensureIPRule(rule ipRule, existing []ipRule) error {
	for _, r := range existing {
		if r.Dst != nil && rule.Dst != nil && r.Dst.String() == rule.Dst.String() &&
			r.Table == rule.Table && r.Priority == rule.Priority {
			//nolint:staticcheck // SA1019: suppress deprecated logger.Printf usage. Todo: legacy logger usage is consistent in cns repo. Migrates when all logger usage is migrated
			logger.Printf("[Azure CNS] ip rule already exists: to %s table %d priority %d", rule.Dst, rule.Table, rule.Priority)
			return nil
		}
	}

	if err := addIPRuleFn(rule); err != nil {
		return errors.Wrapf(err, "failed to add ip rule to %s table %d priority %d", rule.Dst, rule.Table, rule.Priority)
	}

	//nolint:staticcheck // SA1019: suppress deprecated logger.Printf usage. Todo: legacy logger usage is consistent in cns repo. Migrates when all logger usage is migrated
	logger.Printf("[Azure CNS] Added ip rule: to %s table %d priority %d", rule.Dst, rule.Table, rule.Priority)
	return nil
}
