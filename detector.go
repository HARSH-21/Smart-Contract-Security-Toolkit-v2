package audit

import (
	"bufio"
	"strings"
)

// DetectExploits runs all custom pattern-based detectors over the raw Solidity
// source and returns a slice of Findings.  Each detector is independent and
// runs in its own goroutine so the full detector suite is O(detectors) not
// O(detectors * lines).
func DetectExploits(source string) []Finding {
	detectors := []func(string, []string) []Finding{
		detectReentrancy,
		detectTxOrigin,
		detectUncheckedCall,
		detectIntegerOverflow,
		detectSelfDestruct,
		detectTimestampDependence,
		detectDelegatecallMisuse,
		detectUnprotectedETHWithdraw,
		detectAccessControlMissing,
		detectHardcodedAddress,
		detectPriceManipulation,
		detectFlashLoanVulnerability,
		detectBlockHashDependence,
		detectUnsafeERC20,
		detectFrontRunning,
	}

	lines := splitLines(source)

	type partial []Finding
	ch := make(chan partial, len(detectors))

	for _, d := range detectors {
		go func(det func(string, []string) []Finding) {
			ch <- det(source, lines)
		}(d)
	}

	var all []Finding
	for range detectors {
		all = append(all, <-ch...)
	}
	return all
}

// ── helpers ──────────────────────────────────────────────────────────────────

func splitLines(src string) []string {
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(src))
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines
}

func lineContains(lines []string, sub string) (int, string) {
	for i, l := range lines {
		if strings.Contains(l, sub) {
			return i + 1, strings.TrimSpace(l)
		}
	}
	return 0, ""
}

// ── detectors ────────────────────────────────────────────────────────────────

func detectReentrancy(src string, lines []string) []Finding {
	var findings []Finding
	// Classic: external call before state update
	if strings.Contains(src, "call{value:") && strings.Contains(src, "balances[msg.sender] = 0") {
		ln, snippet := lineContains(lines, "call{value:")
		findings = append(findings, Finding{
			Source:      "CustomDetector",
			Type:        "Reentrancy",
			Severity:    SeverityCritical,
			Description: "External call precedes state update (balances reset). Attacker can re-enter before balance is zeroed.",
			Line:        ln,
			Snippet:     snippet,
		})
	}
	// CEI pattern violation: .call( appears before any storage write pattern
	if strings.Contains(src, ".call(") && !strings.Contains(src, "ReentrancyGuard") {
		ln, snippet := lineContains(lines, ".call(")
		findings = append(findings, Finding{
			Source:      "CustomDetector",
			Type:        "Reentrancy (no guard)",
			Severity:    SeverityHigh,
			Description: "External .call() used without ReentrancyGuard. Verify CEI (Checks-Effects-Interactions) order.",
			Line:        ln,
			Snippet:     snippet,
		})
	}
	return findings
}

func detectTxOrigin(src string, lines []string) []Finding {
	if !strings.Contains(src, "tx.origin") {
		return nil
	}
	ln, snippet := lineContains(lines, "tx.origin")
	return []Finding{{
		Source:      "CustomDetector",
		Type:        "Phishing via tx.origin",
		Severity:    SeverityHigh,
		Description: "tx.origin used for authentication. A malicious contract can forward calls and bypass this check. Use msg.sender instead.",
		Line:        ln,
		Snippet:     snippet,
	}}
}

func detectUncheckedCall(src string, lines []string) []Finding {
	if !strings.Contains(src, ".call(") {
		return nil
	}
	// If .call( exists but its return value is not checked via (bool success,
	if !strings.Contains(src, "bool success") && !strings.Contains(src, "(bool") {
		ln, snippet := lineContains(lines, ".call(")
		return []Finding{{
			Source:      "CustomDetector",
			Type:        "Unchecked External Call",
			Severity:    SeverityHigh,
			Description: "Return value of .call() is not checked. Silently failing calls can leave the contract in an inconsistent state.",
			Line:        ln,
			Snippet:     snippet,
		}}
	}
	return nil
}

func detectIntegerOverflow(src string, lines []string) []Finding {
	// Overflow risk: arithmetic without SafeMath and pragma < 0.8
	hasSafeMath := strings.Contains(src, "SafeMath") || strings.Contains(src, "using SafeMath")
	hasSolidity8 := strings.Contains(src, "pragma solidity ^0.8") || strings.Contains(src, "pragma solidity 0.8")
	if hasSafeMath || hasSolidity8 {
		return nil
	}
	if strings.ContainsAny(src, "+-*/") {
		ln, snippet := lineContains(lines, "pragma solidity")
		return []Finding{{
			Source:      "CustomDetector",
			Type:        "Integer Overflow / Underflow",
			Severity:    SeverityHigh,
			Description: "Contract uses Solidity < 0.8 without SafeMath. Arithmetic operations may overflow or underflow silently.",
			Line:        ln,
			Snippet:     snippet,
		}}
	}
	return nil
}

func detectSelfDestruct(src string, lines []string) []Finding {
	if !strings.Contains(src, "selfdestruct") && !strings.Contains(src, "suicide(") {
		return nil
	}
	ln, snippet := lineContains(lines, "selfdestruct")
	if ln == 0 {
		ln, snippet = lineContains(lines, "suicide(")
	}
	return []Finding{{
		Source:      "CustomDetector",
		Type:        "Unprotected selfdestruct",
		Severity:    SeverityCritical,
		Description: "selfdestruct() call detected. Ensure it is protected by a strong access control check (e.g., onlyOwner).",
		Line:        ln,
		Snippet:     snippet,
	}}
}

func detectTimestampDependence(src string, lines []string) []Finding {
	if !strings.Contains(src, "block.timestamp") {
		return nil
	}
	// Only flag if used in a condition
	for i, l := range lines {
		if strings.Contains(l, "block.timestamp") &&
			(strings.Contains(l, "if (") || strings.Contains(l, "require(") || strings.Contains(l, "==") || strings.Contains(l, "<=") || strings.Contains(l, ">=")) {
			return []Finding{{
				Source:      "CustomDetector",
				Type:        "Timestamp Dependence",
				Severity:    SeverityMedium,
				Description: "block.timestamp used in conditional logic. Miners can manipulate this value by up to ~15 seconds.",
				Line:        i + 1,
				Snippet:     strings.TrimSpace(l),
			}}
		}
	}
	return nil
}

func detectDelegatecallMisuse(src string, lines []string) []Finding {
	if !strings.Contains(src, "delegatecall") {
		return nil
	}
	ln, snippet := lineContains(lines, "delegatecall")
	findings := []Finding{{
		Source:      "CustomDetector",
		Type:        "Delegatecall Misuse",
		Severity:    SeverityCritical,
		Description: "delegatecall executes code in the context of the calling contract. Storage layout must exactly match the target or state corruption occurs.",
		Line:        ln,
		Snippet:     snippet,
	}}
	if !strings.Contains(src, "onlyOwner") && !strings.Contains(src, "require(msg.sender") {
		findings[0].Description += " No access control visible around delegatecall — this is extremely dangerous."
	}
	return findings
}

func detectUnprotectedETHWithdraw(src string, lines []string) []Finding {
	hasWithdraw := strings.Contains(src, "transfer(") || strings.Contains(src, "send(") || strings.Contains(src, "call{value:")
	hasGuard := strings.Contains(src, "onlyOwner") || strings.Contains(src, "require(msg.sender ==")
	if hasWithdraw && !hasGuard {
		ln, snippet := lineContains(lines, "transfer(")
		if ln == 0 {
			ln, snippet = lineContains(lines, "call{value:")
		}
		return []Finding{{
			Source:      "CustomDetector",
			Type:        "Unprotected ETH Withdrawal",
			Severity:    SeverityCritical,
			Description: "ETH transfer found without visible access control. Any address may be able to drain the contract.",
			Line:        ln,
			Snippet:     snippet,
		}}
	}
	return nil
}

func detectAccessControlMissing(src string, lines []string) []Finding {
	// Admin-looking functions without modifiers
	adminKeywords := []string{"setOwner", "transferOwnership", "mint(", "pause(", "upgrade(", "initialize("}
	for _, kw := range adminKeywords {
		if strings.Contains(src, kw) {
			// Check for common guard patterns nearby
			if !strings.Contains(src, "onlyOwner") && !strings.Contains(src, "onlyAdmin") &&
				!strings.Contains(src, "require(msg.sender") && !strings.Contains(src, "AccessControl") {
				ln, snippet := lineContains(lines, kw)
				return []Finding{{
					Source:      "CustomDetector",
					Type:        "Missing Access Control",
					Severity:    SeverityHigh,
					Description: "Privileged function '" + kw + "' detected without obvious access control modifier. Verify authorization logic.",
					Line:        ln,
					Snippet:     snippet,
				}}
			}
		}
	}
	return nil
}

func detectHardcodedAddress(src string, lines []string) []Finding {
	for i, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.Contains(trimmed, "0x") && len(trimmed) >= 42 &&
			!strings.HasPrefix(trimmed, "//") && !strings.HasPrefix(trimmed, "*") {
			// crude heuristic: 40-hex-char sequence after 0x
			if containsHexAddress(trimmed) {
				return []Finding{{
					Source:      "CustomDetector",
					Type:        "Hardcoded Address",
					Severity:    SeverityMedium,
					Description: "Hardcoded Ethereum address detected. Consider using constructor parameters or upgradeable configuration.",
					Line:        i + 1,
					Snippet:     trimmed,
				}}
			}
		}
	}
	return nil
}

func containsHexAddress(s string) bool {
	idx := strings.Index(s, "0x")
	if idx < 0 || len(s)-idx < 42 {
		return false
	}
	candidate := s[idx+2 : idx+42]
	for _, c := range candidate {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func detectPriceManipulation(src string, lines []string) []Finding {
	oracleRisk := strings.Contains(src, "getReserves()") || strings.Contains(src, "token0.balanceOf") ||
		strings.Contains(src, "token1.balanceOf")
	noTWAP := !strings.Contains(src, "TWAP") && !strings.Contains(src, "consult(") &&
		!strings.Contains(src, "observe(")
	if oracleRisk && noTWAP {
		ln, snippet := lineContains(lines, "getReserves()")
		return []Finding{{
			Source:      "CustomDetector",
			Type:        "Price Oracle Manipulation",
			Severity:    SeverityCritical,
			Description: "Spot price read from AMM reserves without TWAP. Flash loans can manipulate this in a single transaction.",
			Line:        ln,
			Snippet:     snippet,
		}}
	}
	return nil
}

func detectFlashLoanVulnerability(src string, lines []string) []Finding {
	if !strings.Contains(src, "flashLoan") && !strings.Contains(src, "flashBorrow") {
		return nil
	}
	if !strings.Contains(src, "require") || (!strings.Contains(src, "balanceBefore") && !strings.Contains(src, "repaid")) {
		ln, snippet := lineContains(lines, "flashLoan")
		return []Finding{{
			Source:      "CustomDetector",
			Type:        "Flash Loan Attack Vector",
			Severity:    SeverityHigh,
			Description: "Flash loan callback found without apparent balance repayment check. Verify that loan repayment is strictly enforced.",
			Line:        ln,
			Snippet:     snippet,
		}}
	}
	return nil
}

func detectBlockHashDependence(src string, lines []string) []Finding {
	if !strings.Contains(src, "blockhash(") {
		return nil
	}
	ln, snippet := lineContains(lines, "blockhash(")
	return []Finding{{
		Source:      "CustomDetector",
		Type:        "Weak Randomness (blockhash)",
		Severity:    SeverityHigh,
		Description: "blockhash() used as a source of randomness. Miners can influence or withhold blocks. Use Chainlink VRF for on-chain randomness.",
		Line:        ln,
		Snippet:     snippet,
	}}
}

func detectUnsafeERC20(src string, lines []string) []Finding {
	hasSafeERC20 := strings.Contains(src, "SafeERC20") || strings.Contains(src, "safeTransfer")
	hasRawTransfer := strings.Contains(src, ".transfer(") || strings.Contains(src, ".transferFrom(")
	if hasRawTransfer && !hasSafeERC20 {
		ln, snippet := lineContains(lines, ".transfer(")
		return []Finding{{
			Source:      "CustomDetector",
			Type:        "Unsafe ERC20 Transfer",
			Severity:    SeverityMedium,
			Description: "Raw ERC20 transfer/transferFrom called without SafeERC20 wrapper. Non-standard tokens (e.g., USDT) return no bool — this will revert unexpectedly.",
			Line:        ln,
			Snippet:     snippet,
		}}
	}
	return nil
}

func detectFrontRunning(src string, lines []string) []Finding {
	if !strings.Contains(src, "commit") && !strings.Contains(src, "reveal") {
		// Simple swap or order-like patterns without slippage protection
		if (strings.Contains(src, "swap(") || strings.Contains(src, "buy(") || strings.Contains(src, "sell(")) &&
			!strings.Contains(src, "minAmountOut") && !strings.Contains(src, "slippage") && !strings.Contains(src, "deadline") {
			ln, snippet := lineContains(lines, "swap(")
			if ln == 0 {
				ln, snippet = lineContains(lines, "buy(")
			}
			return []Finding{{
				Source:      "CustomDetector",
				Type:        "Front-Running Risk",
				Severity:    SeverityMedium,
				Description: "Trade function without slippage/deadline protection detected. MEV bots can sandwich transactions for profit.",
				Line:        ln,
				Snippet:     snippet,
			}}
		}
	}
	return nil
}
