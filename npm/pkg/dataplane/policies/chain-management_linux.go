package policies

// This file contains code for booting up and reconciling iptables

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Azure/azure-container-networking/npm/metrics"
	"github.com/Azure/azure-container-networking/npm/util"
	npmerrors "github.com/Azure/azure-container-networking/npm/util/errors"
	"github.com/Azure/azure-container-networking/npm/util/ioutil"
	"k8s.io/klog"
	utilexec "k8s.io/utils/exec"
)

const (
	doesNotExistErrorCode      int = 1 // stderr possibility: Bad rule (does a matching rule exist in that chain?)
	couldntLoadTargetErrorCode int = 2 // Couldn't load target `AZURE-NPM-EGRESS':No such file or directory

	// transferred from iptm.go and not sure why this length is important
	minLineNumberStringLength int = 3
)

var (
	// Must loop through a slice because we need a deterministic order for fexec commands for UTs.
	iptablesAzureChains = []string{
		util.IptablesAzureChain,
		util.IptablesAzureIngressChain,
		util.IptablesAzureIngressAllowMarkChain,
		util.IptablesAzureEgressChain,
		util.IptablesAzureAcceptChain,
	}
	// Should not be used directly. Initialized from iptablesAzureChains on first use of isAzureChain().
	iptablesAzureChainsMap map[string]struct{}

	jumpToAzureChainArgs = []string{
		util.IptablesJumpFlag,
		util.IptablesAzureChain,
		util.IptablesModuleFlag,
		util.IptablesCtstateModuleFlag,
		util.IptablesCtstateFlag,
		util.IptablesNewState,
	}
	jumpFromForwardToAzureChainArgs = append([]string{util.IptablesForwardChain}, jumpToAzureChainArgs...)

	removeDeprecatedJumpIgnoredErrors = []*exitErrorInfo{
		{
			// doesNotExistErrorCode happens when AZURE-NPM chain exists, but this jump rule doesn't exist
			exitCode:     doesNotExistErrorCode,
			stdErr:       "No chain/target/match by that name",
			messageToLog: "didn't delete deprecated jump rule from FORWARD chain to AZURE-NPM chain likely because NPM v1 was not used prior",
		},
		{
			// couldntLoadTargetErrorCode happens when AZURE-NPM chain doesn't exist (and hence the jump rule doesn't exist too)
			exitCode:     couldntLoadTargetErrorCode,
			stdErr:       "Couldn't load target `AZURE-NPM':No such file or directory",
			messageToLog: "didn't delete deprecated jump rule from FORWARD chain to AZURE-NPM chain likely because AZURE-NPM chain doesn't exist",
		},
		{
			// nft version
			// couldntLoadTargetErrorCode happens when AZURE-NPM chain doesn't exist (and hence the jump rule doesn't exist too)
			exitCode:     couldntLoadTargetErrorCode,
			stdErr:       "Chain 'AZURE-NPM' does not exist",
			messageToLog: "in nft tables, didn't delete deprecated jump rule from FORWARD chain to AZURE-NPM chain likely because AZURE-NPM chain doesn't exist",
		},
		{
			exitCode:     doesNotExistErrorCode,
			stdErr:       "Bad rule (does a matching rule exist in that chain?)",
			messageToLog: "probably tried to delete a jump rule that didn't exist in nft tables",
		},
	}

	listForwardEntriesArgs = []string{
		util.IptablesWaitFlag, util.IptablesDefaultWaitTime, util.IptablesTableFlag, util.IptablesFilterTable,
		util.IptablesNumericFlag, util.IptablesListFlag, util.IptablesForwardChain, util.IptablesLineNumbersFlag,
	}
	spaceByte                                 = []byte(" ")
	errNoLineNumber                           = errors.New("no line number found")
	errUnexpectedLineNumberString             = errors.New("unexpected line number string")
	deprecatedJumpFromForwardToAzureChainArgs = []string{
		util.IptablesForwardChain,
		util.IptablesJumpFlag,
		util.IptablesAzureChain,
	}

	listHintChainArgs   = []string{"KUBE-IPTABLES-HINT", util.IptablesTableFlag, util.IptablesMangleTable, util.IptablesNumericFlag}
	listCanaryChainArgs = []string{"KUBE-KUBELET-CANARY", util.IptablesTableFlag, util.IptablesMangleTable, util.IptablesNumericFlag}

	errDetectingIptablesVersion = errors.New("unable to locate which iptables version kube proxy is using")
)

type exitErrorInfo struct {
	exitCode     int
	stdErr       string
	messageToLog string
}

type staleChains struct {
	chainsToCleanup map[string]struct{}
}

func newStaleChains() *staleChains {
	return &staleChains{
		chainsToCleanup: make(map[string]struct{}),
	}
}

// forceLock stops reconciling if it is running, and then locks the reconcileManager
func (rm *reconcileManager) forceLock() {
	rm.releaseLockSignal <- struct{}{}
	rm.Lock()
}

// forceUnlock makes sure that the releaseLockSignal channel is empty (in case reconciling
// wasn't running when forceLock was called), and then unlocks the reconcileManager.
func (rm *reconcileManager) forceUnlock() {
	select {
	case <-rm.releaseLockSignal:
	default:
	}
	rm.Unlock()
}

// Adds the chain if it isn't one of the iptablesAzureChains.
// This protects against trying to delete any core NPM chain.
func (s *staleChains) add(chain string) {
	if !isBaseChain(chain) {
		s.chainsToCleanup[chain] = struct{}{}
	}
}

func (s *staleChains) remove(chain string) {
	delete(s.chainsToCleanup, chain)
}

func (s *staleChains) emptyAndGetAll() []string {
	result := make([]string, len(s.chainsToCleanup))
	k := 0
	for chain := range s.chainsToCleanup {
		result[k] = chain
		s.remove(chain)
		k++
	}
	return result
}

func (s *staleChains) empty() {
	s.chainsToCleanup = make(map[string]struct{})
}

func isBaseChain(chain string) bool {
	if iptablesAzureChainsMap == nil {
		iptablesAzureChainsMap = make(map[string]struct{})
		for _, chain := range iptablesAzureChains {
			iptablesAzureChainsMap[chain] = struct{}{}
		}
	}
	_, exist := iptablesAzureChainsMap[chain]
	return exist
}

/*
Called once at startup.
Like the rest of PolicyManager, minimizes the number of OS calls by consolidating all possible actions into one iptables-restore call.

0.1. Detect iptables version.
0.2. Clean up legacy tables if using nft and vice versa.
1. Delete the deprecated jump from FORWARD to AZURE-NPM chain (if it exists).
2. Cleanup old NPM chains, and configure base chains and their rules.
 1. Do the following via iptables-restore --noflush:
    - flush all deprecated chains
    - flush old v2 policy chains
    - create/flush the base chains
    - add rules for the base chains, except for AZURE-NPM (so that PolicyManager will be deactivated)
 2. In the background:
    - delete all deprecated chains
    - delete old v2 policy chains

3. Add/reposition the jump from FORWARD chain to AZURE-NPM chain.

TODO: could use one grep call instead of separate calls for getting jump line nums and for getting deprecated chains and old v2 policy chains
  - would use a grep pattern like so: <line num...AZURE-NPM>|<Chain AZURE-NPM>
*/
func (pMgr *PolicyManager) bootup(_ []string) error {
	klog.Infof("booting up iptables Azure chains")

	// 0.1. Detect iptables version
	if err := pMgr.detectIptablesVersion(); err != nil {
		return npmerrors.SimpleErrorWrapper("failed to detect iptables version", err)
	}

	// Stop reconciling so we don't contend for iptables, and so we don't update the staleChains at the same time as reconcile()
	// Reconciling would only be happening if this function were called to reset iptables well into the azure-npm pod lifecycle.
	pMgr.reconcileManager.forceLock()
	defer pMgr.reconcileManager.forceUnlock()

	// 0.2. cleanup
	if err := pMgr.cleanupOtherIptables(); err != nil {
		return npmerrors.SimpleErrorWrapper("failed to cleanup other iptables chains", err)
	}

	if err := pMgr.bootupAfterDetectAndCleanup(); err != nil {
		return err
	}

	return nil
}

func (pMgr *PolicyManager) bootupAfterDetectAndCleanup() error {
	// 1. delete the deprecated jump to AZURE-NPM
	deprecatedErrCode, deprecatedErr := pMgr.ignoreErrorsAndRunIPTablesCommand(removeDeprecatedJumpIgnoredErrors, util.IptablesDeletionFlag, deprecatedJumpFromForwardToAzureChainArgs...)
	if deprecatedErrCode == 0 {
		klog.Infof("deleted deprecated jump rule from FORWARD chain to AZURE-NPM chain")
	} else if deprecatedErr != nil {
		metrics.SendErrorLogAndMetric(util.IptmID,
			"failed to delete deprecated jump rule from FORWARD chain to AZURE-NPM chain for unexpected reason with exit code %d and error: %s",
			deprecatedErrCode, deprecatedErr.Error())
	}

	currentChains, err := ioutil.AllCurrentAzureChains(pMgr.ioShim.Exec, util.IptablesDefaultWaitTime)
	if err != nil {
		return npmerrors.SimpleErrorWrapper("failed to get current chains for bootup", err)
	}

	klog.Infof("found %d current chains in the default iptables", len(currentChains))

	// 2. cleanup old NPM chains, and configure base chains and their rules.
	creator := pMgr.creatorForBootup(currentChains)
	if err := restore(creator); err != nil {
		return npmerrors.SimpleErrorWrapper("failed to run iptables-restore for bootup", err)
	}

	// 3. add/reposition the jump to AZURE-NPM
	if err := pMgr.positionAzureChainJumpRule(); err != nil {
		baseErrString := "failed to add/reposition jump from FORWARD chain to AZURE-NPM chain"
		metrics.SendErrorLogAndMetric(util.IptmID, "error: %s with error: %s", baseErrString, err.Error())
		return npmerrors.SimpleErrorWrapper(baseErrString, err) // we used to ignore this error in v1
	}
	return nil
}

// detectIptablesVersion sets the global iptables variable to nft if detected or legacy if detected.
// NPM will crash if it fails to detect either.
// This global variable is referenced in all iptables related functions.
// NPM should use the same iptables version as kube-proxy.
// kube-proxy creates an iptables chain as a hint for which version it uses.
// For more details, see: https://kubernetes.io/blog/2022/09/07/iptables-chains-not-api/#use-case-iptables-mode
func (pMgr *PolicyManager) detectIptablesVersion() error {
	klog.Info("first attempt detecting iptables version. looking for hint/canary chain in iptables-nft")
	if pMgr.hintOrCanaryChainExist(util.IptablesNft) {
		util.SetIptablesToNft()
		return nil
	}

	klog.Info("second attempt detecting iptables version. looking for hint/canary chain in iptables-legacy")
	if pMgr.hintOrCanaryChainExist(util.IptablesLegacy) {
		util.SetIptablesToLegacy()
		return nil
	}

	return errDetectingIptablesVersion
}

func (pMgr *PolicyManager) hintOrCanaryChainExist(iptablesCmd string) bool {
	// hint chain should exist since k8s 1.24 (see https://kubernetes.io/blog/2022/09/07/iptables-chains-not-api/#use-case-iptables-mode)
	prevIptables := util.Iptables
	util.Iptables = iptablesCmd
	defer func() {
		util.Iptables = prevIptables
	}()

	_, hintErr := pMgr.runIPTablesCommand(util.IptablesListFlag, listHintChainArgs...)
	if hintErr == nil {
		metrics.SendLog(util.IptmID, "found hint chain. will use iptables version: %s"+iptablesCmd, metrics.DonotPrint)
		return true
	}

	// check for canary chain
	_, canaryErr := pMgr.runIPTablesCommand(util.IptablesListFlag, listCanaryChainArgs...)
	if canaryErr != nil {
		return false
	}

	metrics.SendLog(util.IptmID, "found canary chain. will use iptables version: "+iptablesCmd, metrics.DonotPrint)
	return true
}

// clenaupOtherIptablesChains cleans up legacy tables if using nft and vice versa.
// It will only return an error if it fails to delete a jump rule and flush the AZURE-NPM chain (see comment about #3088 below).
// Cleanup logic:
// 1. delete jump rules to AZURE-NPM
// 2. flush all chains
// 3. delete all chains
func (pMgr *PolicyManager) cleanupOtherIptables() error {
	hadNFT := util.Iptables == util.IptablesNft
	if hadNFT {
		klog.Info("detected nft iptables. cleaning up legacy iptables")
		util.SetIptablesToLegacy()
	} else {
		klog.Info("detected legacy iptables. cleaning up nft iptables")
		util.SetIptablesToNft()
	}

	defer func() {
		if hadNFT {
			klog.Info("cleaned up legacy iptables")
			util.SetIptablesToNft()
		} else {
			klog.Info("cleaned up nft tables")
			util.SetIptablesToLegacy()
		}
	}()

	deletedJumpRule := false

	// 1.1. delete the deprecated jump to AZURE-NPM
	errCode, err := pMgr.ignoreErrorsAndRunIPTablesCommand(removeDeprecatedJumpIgnoredErrors, util.IptablesDeletionFlag, deprecatedJumpFromForwardToAzureChainArgs...)
	if errCode == 0 {
		klog.Infof("[cleanup] deleted deprecated jump rule from FORWARD chain to AZURE-NPM chain")
		deletedJumpRule = true
	} else if err != nil {
		metrics.SendErrorLogAndMetric(util.IptmID,
			"[cleanup] failed to delete deprecated jump rule from FORWARD chain to AZURE-NPM chain for unexpected reason with exit code %d and error: %s",
			errCode, err.Error())
	}

	// 1.2. delete the jump to AZURE-NPM
	errCode, err = pMgr.ignoreErrorsAndRunIPTablesCommand(removeDeprecatedJumpIgnoredErrors, util.IptablesDeletionFlag, jumpFromForwardToAzureChainArgs...)
	if errCode == 0 {
		deletedJumpRule = true
		klog.Infof("[cleanup] deleted jump rule from FORWARD chain to AZURE-NPM chain")
	} else if err != nil {
		metrics.SendErrorLogAndMetric(util.IptmID,
			"[cleanup] failed to delete jump rule from FORWARD chain to AZURE-NPM chain for unexpected reason with exit code %d and error: %s",
			errCode, err.Error())
	}

	// 2. get current chains
	currentChains, err := ioutil.AllCurrentAzureChains(pMgr.ioShim.Exec, util.IptablesDefaultWaitTime)
	if err != nil {
		return npmerrors.SimpleErrorWrapper("[cleanup] failed to get current chains for bootup", err)
	}

	if len(currentChains) == 0 {
		klog.Info("no chains to cleanup")
		return nil
	}

	klog.Infof("[cleanup] %d chains to clean up", len(currentChains))

	// 3.1. try to flush all chains at once
	chains := make([]string, 0, len(currentChains))
	_, hasAzureChain := currentChains[util.IptablesAzureChain]
	if hasAzureChain {
		// putting AZURE-NPM chain first is required for proper unit testing (for determinancy in destroying chains)
		chains = append(chains, util.IptablesAzureChain)
	}
	for chain := range currentChains {
		if chain == util.IptablesAzureChain {
			// putting AZURE-NPM chain first is required for proper unit testing (for determinancy in destroying chains)
			continue
		}
		chains = append(chains, chain)
	}

	creator := pMgr.creatorForCleanup(chains)
	if err := restore(creator); err != nil {
		msg := "[cleanup] failed to flush all chains with error: %s"
		klog.Infof(msg, err.Error())
		metrics.SendErrorLogAndMetric(util.IptmID, msg, err.Error())

		// 3.2. if we failed to flush all chains, then try to flush and delete them one by one
		var aggregateError error
		if _, ok := currentChains[util.IptablesAzureChain]; ok {
			_, err := pMgr.runIPTablesCommand(util.IptablesFlushFlag, util.IptablesAzureChain)
			aggregateError = err
			if err != nil && !deletedJumpRule {
				// fixes #3088
				// if we failed to delete a jump rule to AZURE-NPM and we failed to flush AZURE-NPM chain,
				// then there is risk that there is a jump rule to AZURE-NPM, which in turn has rules which could lead to allowing or dropping a packet.
				// We have failed to cleanup the other iptables rules, and there is no guarantee that packets will be processed correctly now.
				// So we must crash and retry.
				return npmerrors.SimpleErrorWrapper("[cleanup] must crash and retry. failed to delete jump rule and flush AZURE-NPM chain with error", err)
			}
		}

		for chain := range currentChains {
			if chain == util.IptablesAzureChain {
				// already flushed above
				continue
			}

			errCode, err := pMgr.runIPTablesCommand(util.IptablesFlushFlag, chain)
			if err != nil && errCode != doesNotExistErrorCode {
				// NOTE: if we fail to flush or delete the chain, then we will never clean it up in the future.
				// This is zero-day behavior since NPM supported nft (we used to mark the chain stale, but this would not have worked as expected).
				// NPM currently has no mechanism for retrying flush/delete for a chain from the other iptables version (other than the AZURE-NPM chain which is handled above).
				currentErrString := fmt.Sprintf("failed to flush chain %s with err [%v]", chain, err)
				if aggregateError == nil {
					aggregateError = npmerrors.SimpleError(currentErrString)
				} else {
					aggregateError = npmerrors.SimpleErrorWrapper(currentErrString+" and had previous error", aggregateError)
				}
			}
		}

		if aggregateError != nil {
			metrics.SendErrorLogAndMetric(util.IptmID,
				"[cleanup] benign failure to flush chains with error: %s",
				aggregateError.Error())
		}
	}

	// 4. delete all chains
	var aggregateError error
	for _, chain := range chains {
		errCode, err := pMgr.runIPTablesCommand(util.IptablesDestroyFlag, chain)
		if err != nil && errCode != doesNotExistErrorCode {
			// NOTE: if we fail to flush or delete the chain, then we will never clean it up in the future.
			// This is zero-day behavior since NPM supported nft (we used to mark the chain stale, but this would not have worked as expected).
			// NPM currently has no mechanism for retrying flush/delete for a chain from the other iptables version (other than the AZURE-NPM chain which is handled above).
			currentErrString := fmt.Sprintf("failed to delete chain %s with err [%v]", chain, err)
			if aggregateError == nil {
				aggregateError = npmerrors.SimpleError(currentErrString)
			} else {
				aggregateError = npmerrors.SimpleErrorWrapper(currentErrString+" and had previous error", aggregateError)
			}
		}
	}

	if aggregateError != nil {
		metrics.SendErrorLogAndMetric(util.IptmID,
			"[cleanup] benign failure to delete chains with error: %s",
			aggregateError.Error())
	}

	return nil
}

func (pMgr *PolicyManager) creatorForCleanup(chains []string) *ioutil.FileCreator {
	// pass nil because we don't need to add any lines like ":CHAIN-NAME - -" because that is for creating chains
	creator := pMgr.newCreatorWithChains(nil)
	for _, chain := range chains {
		creator.AddLine("", nil, "-F "+chain)
	}
	creator.AddLine("", nil, util.IptablesRestoreCommit)
	return creator
}

// reconcile does the following:
// - creates the jump rule from FORWARD chain to AZURE-NPM chain (if it does not exist) and makes sure it's after the jumps to KUBE-FORWARD & KUBE-SERVICES chains (if they exist).
// - cleans up stale policy chains. It can be forced to stop this process if reconcileManager.forceLock() is called.
func (pMgr *PolicyManager) reconcile() {
	if err := pMgr.positionAzureChainJumpRule(); err != nil {
		msg := fmt.Sprintf("failed to reconcile jump rule to Azure-NPM due to %s", err.Error())
		metrics.SendErrorLogAndMetric(util.IptmID, "error: %s", msg)
		klog.Error(msg)
	}

	pMgr.reconcileManager.Lock()
	defer pMgr.reconcileManager.Unlock()
	staleChains := pMgr.staleChains.emptyAndGetAll()

	if len(staleChains) == 0 {
		return
	}

	klog.Infof("cleaning up these stale chains: %+v", staleChains)
	if err := pMgr.cleanupChains(staleChains); err != nil {
		msg := fmt.Sprintf("failed to clean up old policy chains with the following error: %s", err.Error())
		metrics.SendErrorLogAndMetric(util.IptmID, "error: %s", msg)
		klog.Error(msg)
	}
}

// cleanupChains deletes all the chains in the given list.
// If a chain fails to delete and it isn't one of the iptablesAzureChains, then it is added to the staleChains.
// This is a separate function for with a slice argument so that UTs can have deterministic behavior for ioshim.
func (pMgr *PolicyManager) cleanupChains(chains []string) error {
	var aggregateError error
deleteLoop:
	for k, chain := range chains {
		select {
		case <-pMgr.reconcileManager.releaseLockSignal:
			// if reconcileManager.forceLock() was called, then stop deleting stale chains so that reconcileManager can be unlocked right away
			for j := k; j < len(chains); j++ {
				pMgr.staleChains.add(chains[j])
			}
			break deleteLoop
		default:
			errCode, err := pMgr.runIPTablesCommand(util.IptablesDestroyFlag, chain)
			if err != nil && errCode != doesNotExistErrorCode {
				// add to staleChains if it's not one of the iptablesAzureChains
				pMgr.staleChains.add(chain)
				currentErrString := fmt.Sprintf("failed to clean up chain %s with err [%v]", chain, err)
				if aggregateError == nil {
					aggregateError = npmerrors.SimpleError(currentErrString)
				} else {
					aggregateError = npmerrors.SimpleErrorWrapper(fmt.Sprintf("%s and had previous error", currentErrString), aggregateError)
				}
			}
		}
	}
	if aggregateError != nil {
		return npmerrors.SimpleErrorWrapper("failed to clean up some chains", aggregateError)
	}
	return nil
}

// this function has a direct comparison in NPM v1 iptables manager (iptm.go)
func (pMgr *PolicyManager) runIPTablesCommand(operationFlag string, args ...string) (int, error) {
	return pMgr.ignoreErrorsAndRunIPTablesCommand(nil, operationFlag, args...)
}

func (pMgr *PolicyManager) ignoreErrorsAndRunIPTablesCommand(ignored []*exitErrorInfo, operationFlag string, args ...string) (int, error) {
	allArgs := []string{util.IptablesWaitFlag, util.IptablesDefaultWaitTime, operationFlag}
	allArgs = append(allArgs, args...)

	klog.Infof("executing iptables command [%s] with args %v", util.Iptables, allArgs)

	command := pMgr.ioShim.Exec.Command(util.Iptables, allArgs...)
	output, err := command.CombinedOutput()

	var exitError utilexec.ExitError
	if ok := errors.As(err, &exitError); ok {
		errCode := exitError.ExitStatus()
		allArgsString := strings.Join(allArgs, " ")
		outputString := strings.TrimSuffix(string(output), "\n")
		for _, info := range ignored {
			if errCode == info.exitCode && strings.Contains(outputString, info.stdErr) {
				klog.Infof("%s. not able to run iptables command [%s %s]. exit code: %d, output: %s", info.messageToLog, util.Iptables, allArgsString, errCode, outputString)
				return errCode, nil
			}
		}
		if errCode > 0 {
			metrics.SendErrorLogAndMetric(util.IptmID, "error: There was an error running command: [%s %s] Stderr: [%v, %s]", util.Iptables, allArgsString, exitError, outputString)
		}
		return errCode, fmt.Errorf("failed to run iptables command [%s %s] Stderr: [%s]. err: [%w]", util.Iptables, allArgsString, outputString, exitError)
	}
	return 0, nil
}

// Writes the restore file for bootup, and marks the following as stale: deprecated chains and old v2 policy chains.
// This is a separate function to help with UTs.
func (pMgr *PolicyManager) creatorForBootup(currentChains map[string]struct{}) *ioutil.FileCreator {
	chainsToCreate := make([]string, 0, len(iptablesAzureChains))
	for _, chain := range iptablesAzureChains {
		_, exists := currentChains[chain]
		if !exists {
			chainsToCreate = append(chainsToCreate, chain)
		}
	}

	// Step 2.1 in bootup() comment: cleanup old NPM chains, and configure base chains and their rules
	// To leave NPM deactivated, don't specify any rules for AZURE-NPM chain.
	creator := pMgr.newCreatorWithChains(chainsToCreate)
	pMgr.staleChains.empty()
	for chain := range currentChains {
		creator.AddLine("", nil, fmt.Sprintf("-F %s", chain))
		// Step 2.2 in bootup() comment: delete deprecated chains and old v2 policy chains in the background
		pMgr.staleChains.add(chain) // won't add base chains
	}

	// add AZURE-NPM-INGRESS chain rules
	ingressDropSpecs := []string{util.IptablesAppendFlag, util.IptablesAzureIngressChain, util.IptablesJumpFlag, util.IptablesDrop}
	ingressDropSpecs = append(ingressDropSpecs, onMarkSpecs(util.IptablesAzureIngressDropMarkHex)...)
	ingressDropSpecs = append(ingressDropSpecs, commentSpecs(fmt.Sprintf("DROP-ON-INGRESS-DROP-MARK-%s", util.IptablesAzureIngressDropMarkHex))...)
	creator.AddLine("", nil, ingressDropSpecs...)

	// add AZURE-NPM-INGRESS-ALLOW-MARK chain
	markIngressAllowSpecs := []string{util.IptablesAppendFlag, util.IptablesAzureIngressAllowMarkChain}
	markIngressAllowSpecs = append(markIngressAllowSpecs, setMarkSpecs(util.IptablesAzureIngressAllowMarkHex)...)
	markIngressAllowSpecs = append(markIngressAllowSpecs, commentSpecs(fmt.Sprintf("SET-INGRESS-ALLOW-MARK-%s", util.IptablesAzureIngressAllowMarkHex))...)
	creator.AddLine("", nil, markIngressAllowSpecs...)
	creator.AddLine("", nil, util.IptablesAppendFlag, util.IptablesAzureIngressAllowMarkChain, util.IptablesJumpFlag, util.IptablesAzureEgressChain)

	// add AZURE-NPM-EGRESS chain rules
	egressDropSpecs := []string{util.IptablesAppendFlag, util.IptablesAzureEgressChain, util.IptablesJumpFlag, util.IptablesDrop}
	egressDropSpecs = append(egressDropSpecs, onMarkSpecs(util.IptablesAzureEgressDropMarkHex)...)
	egressDropSpecs = append(egressDropSpecs, commentSpecs(fmt.Sprintf("DROP-ON-EGRESS-DROP-MARK-%s", util.IptablesAzureEgressDropMarkHex))...)
	creator.AddLine("", nil, egressDropSpecs...)

	jumpOnIngressMatchSpecs := []string{util.IptablesAppendFlag, util.IptablesAzureEgressChain, util.IptablesJumpFlag, util.IptablesAzureAcceptChain}
	jumpOnIngressMatchSpecs = append(jumpOnIngressMatchSpecs, onMarkSpecs(util.IptablesAzureIngressAllowMarkHex)...)
	jumpOnIngressMatchSpecs = append(jumpOnIngressMatchSpecs, commentSpecs(fmt.Sprintf("ACCEPT-ON-INGRESS-ALLOW-MARK-%s", util.IptablesAzureIngressAllowMarkHex))...)
	creator.AddLine("", nil, jumpOnIngressMatchSpecs...)

	// add AZURE-NPM-ACCEPT chain rules
	creator.AddLine("", nil, util.IptablesAppendFlag, util.IptablesAzureAcceptChain, util.IptablesJumpFlag, util.IptablesAccept)
	creator.AddLine("", nil, util.IptablesRestoreCommit)
	return creator
}

// add/reposition the jump from FORWARD chain to AZURE-NPM chain to be in the correct position based on config:
// option 1) jump to AZURE-NPM chain should be the first rule
// option 2) jump to AZURE-NPM chain should be after the jump to KUBE-SERVICES chain
func (pMgr *PolicyManager) positionAzureChainJumpRule() error {
	// get the line number for the azure jump
	azureChainLineNum, err := pMgr.chainLineNumber(util.IptablesAzureChain)
	if err != nil {
		baseErrString := "failed to get index of jump from FORWARD chain to AZURE-NPM chain"
		metrics.SendErrorLogAndMetric(util.IptmID, "error: %s: %s", baseErrString, err.Error())
		return npmerrors.SimpleErrorWrapper(baseErrString, err)
	}

	if pMgr.PlaceAzureChainFirst == util.PlaceAzureChainFirst && azureChainLineNum == 1 {
		// the azure jump is in the right position, so we're done
		return nil
	}

	// place the azure jump in the first position, unless we want option 2 above and the kube jump exists
	targetIndex := 1
	if pMgr.PlaceAzureChainFirst == util.PlaceAzureChainAfterKubeServices {
		kubeChainLineNum, err := pMgr.chainLineNumber(util.IptablesKubeServicesChain)
		if err != nil {
			baseErrString := "failed to get index of jump from FORWARD chain to KUBE-SERVICES chain"
			metrics.SendErrorLogAndMetric(util.IptmID, "error: %s: %s", baseErrString, err.Error())
			return npmerrors.SimpleErrorWrapper(baseErrString, err)
		}

		if kubeChainLineNum != 0 {
			// kube jump exists
			// the azure jump should be immediately after the kube jump
			targetIndex = kubeChainLineNum + 1
		}
	}

	if azureChainLineNum == targetIndex {
		// the azure jump is in the right position, so we're done
		return nil
	}

	// delete the azure jump if it exists and update the target index
	if azureChainLineNum != 0 {
		metrics.SendErrorLogAndMetric(util.IptmID, "Info: Reconciler deleting and re-adding jump from FORWARD chain to AZURE-NPM chain table.")
		if deleteErrCode, deleteErr := pMgr.runIPTablesCommand(util.IptablesDeletionFlag, jumpFromForwardToAzureChainArgs...); deleteErr != nil {
			baseErrString := "failed to delete jump from FORWARD chain to AZURE-NPM chain"
			metrics.SendErrorLogAndMetric(util.IptmID, "error: %s with error code %d and error %s", baseErrString, deleteErrCode, deleteErr.Error())
			return npmerrors.SimpleErrorWrapper(baseErrString, deleteErr)
		}

		if azureChainLineNum < targetIndex {
			// this means kube jump existed and was below the deleted azure jump, so decrement the target index
			// this can only occur if PlaceAzureChainFirst == PlaceAfterKube
			// this logic depends on targetIndex being 1 or kubeChainLineNum + 1
			targetIndex--
		}
	}

	// add (back) the azure jump
	klog.Infof("Inserting jump from FORWARD chain to AZURE-NPM chain")
	var args []string
	if targetIndex == 1 {
		// when no index is provided, index of 1 is implied
		args = jumpFromForwardToAzureChainArgs
	} else {
		args = []string{util.IptablesForwardChain, strconv.Itoa(targetIndex)}
		args = append(args, jumpToAzureChainArgs...)
	}
	if insertErrCode, err := pMgr.runIPTablesCommand(util.IptablesInsertionFlag, args...); err != nil {
		baseErrString := "failed to insert jump from FORWARD chain to AZURE-NPM chain"
		metrics.SendErrorLogAndMetric(util.IptmID, "error: %s with error code %d and error %s", baseErrString, insertErrCode, err.Error())
		return npmerrors.SimpleErrorWrapper(baseErrString, err)
	}
	return nil
}

// returns 0 if the chain does not exist
// this function has a direct comparison in NPM v1 iptables manager (iptm.go)
func (pMgr *PolicyManager) chainLineNumber(chain string) (int, error) {
	listForwardEntriesCommand := pMgr.ioShim.Exec.Command(util.Iptables, listForwardEntriesArgs...)
	grepCommand := pMgr.ioShim.Exec.Command(ioutil.Grep, chain)
	searchResults, gotMatches, err := ioutil.PipeCommandToGrep(listForwardEntriesCommand, grepCommand)
	if err != nil {
		return 0, npmerrors.SimpleErrorWrapper(fmt.Sprintf("failed to determine line number for jump from FORWARD chain to %s chain", chain), err)
	}
	if !gotMatches {
		return 0, nil
	}
	if len(searchResults) >= minLineNumberStringLength {
		firstSpaceIndex := bytes.Index(searchResults, spaceByte)
		if firstSpaceIndex > 0 && firstSpaceIndex < len(searchResults) {
			lineNumberString := string(searchResults[0:firstSpaceIndex])
			lineNum, err := strconv.Atoi(lineNumberString)
			if err != nil {
				return 0, npmerrors.SimpleErrorWrapper(fmt.Sprintf("unable to parse line number. lineNumberString: [%s]. searchResults: [%s]", lineNumberString, string(searchResults)), errNoLineNumber)
			}
			return lineNum, nil
		}
	}
	return 0, npmerrors.SimpleErrorWrapper(fmt.Sprintf("unable to parse line number. searchResults: [%s]", string(searchResults)), errUnexpectedLineNumberString)
}

func onMarkSpecs(mark string) []string {
	return []string{
		util.IptablesModuleFlag,
		util.IptablesMarkVerb,
		util.IptablesMarkFlag,
		mark,
	}
}
