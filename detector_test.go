package audit

import (
	"testing"
)

func findingTypes(findings []Finding) []string {
	var types []string
	for _, f := range findings {
		types = append(types, f.Type)
	}
	return types
}

func containsFindingType(findings []Finding, t string) bool {
	for _, f := range findings {
		if f.Type == t {
			return true
		}
	}
	return false
}

func TestDetectReentrancy(t *testing.T) {
	src := `
pragma solidity ^0.8.0;
contract Vuln {
    mapping(address => uint) public balances;
    function withdraw() external {
        (bool ok,) = msg.sender.call{value: balances[msg.sender]}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
`
	findings := DetectExploits(src)
	if !containsFindingType(findings, "Reentrancy") {
		t.Errorf("expected Reentrancy finding, got: %v", findingTypes(findings))
	}
}

func TestDetectTxOrigin(t *testing.T) {
	src := `
pragma solidity ^0.8.0;
contract Auth {
    function adminOnly() public {
        require(tx.origin == owner);
    }
}
`
	findings := DetectExploits(src)
	if !containsFindingType(findings, "Phishing via tx.origin") {
		t.Errorf("expected tx.origin finding, got: %v", findingTypes(findings))
	}
}

func TestDetectUncheckedCall(t *testing.T) {
	src := `
pragma solidity ^0.6.0;
contract Pay {
    function send(address to, uint amt) external {
        to.call(abi.encodeWithSignature("deposit()"));
    }
}
`
	findings := DetectExploits(src)
	if !containsFindingType(findings, "Unchecked External Call") {
		t.Errorf("expected unchecked call finding, got: %v", findingTypes(findings))
	}
}

func TestDetectIntegerOverflow(t *testing.T) {
	src := `
pragma solidity ^0.6.0;
contract Counter {
    uint public count;
    function inc() external { count += 1; }
}
`
	findings := DetectExploits(src)
	if !containsFindingType(findings, "Integer Overflow / Underflow") {
		t.Errorf("expected overflow finding, got: %v", findingTypes(findings))
	}
}

func TestNoOverflowOnSolidity8(t *testing.T) {
	src := `
pragma solidity ^0.8.0;
contract Counter {
    uint public count;
    function inc() external { count += 1; }
}
`
	findings := DetectExploits(src)
	if containsFindingType(findings, "Integer Overflow / Underflow") {
		t.Error("should not flag overflow for Solidity >=0.8")
	}
}

func TestDetectSelfDestruct(t *testing.T) {
	src := `
pragma solidity ^0.8.0;
contract Bomb {
    function kill() external {
        selfdestruct(payable(msg.sender));
    }
}
`
	findings := DetectExploits(src)
	if !containsFindingType(findings, "Unprotected selfdestruct") {
		t.Errorf("expected selfdestruct finding, got: %v", findingTypes(findings))
	}
}

func TestDetectPriceManipulation(t *testing.T) {
	src := `
pragma solidity ^0.8.0;
interface IUniswap { function getReserves() external view returns (uint, uint, uint); }
contract Oracle {
    function getPrice(address pair) external view returns (uint) {
        (uint r0, uint r1,) = IUniswap(pair).getReserves();
        return r1 / r0;
    }
}
`
	findings := DetectExploits(src)
	if !containsFindingType(findings, "Price Oracle Manipulation") {
		t.Errorf("expected price manipulation finding, got: %v", findingTypes(findings))
	}
}

func TestCleanContract(t *testing.T) {
	src := `
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
contract Safe is ReentrancyGuard, Ownable {
    using SafeERC20 for IERC20;
    function deposit(IERC20 token, uint amount) external nonReentrant {
        token.safeTransferFrom(msg.sender, address(this), amount);
    }
}
`
	findings := DetectExploits(src)
	critOrHigh := 0
	for _, f := range findings {
		if f.Severity == SeverityCritical || f.Severity == SeverityHigh {
			critOrHigh++
		}
	}
	if critOrHigh > 0 {
		t.Errorf("clean contract should have 0 critical/high, got %d: %v", critOrHigh, findingTypes(findings))
	}
}

func TestBlockHashDependence(t *testing.T) {
	src := `
pragma solidity ^0.8.0;
contract Lottery {
    function pickWinner() external view returns (bytes32) {
        return blockhash(block.number - 1);
    }
}
`
	findings := DetectExploits(src)
	if !containsFindingType(findings, "Weak Randomness (blockhash)") {
		t.Errorf("expected blockhash finding, got: %v", findingTypes(findings))
	}
}

func TestSeverityOrdering(t *testing.T) {
	r := &Report{
		Findings: []Finding{
			{Severity: SeverityLow, Type: "A"},
			{Severity: SeverityCritical, Type: "B"},
			{Severity: SeverityMedium, Type: "C"},
			{Severity: SeverityHigh, Type: "D"},
		},
	}
	sorted := r.sortedFindings()
	order := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}
	for i, expected := range order {
		if sorted[i].Severity != expected {
			t.Errorf("position %d: want %s, got %s", i, expected, sorted[i].Severity)
		}
	}
}
