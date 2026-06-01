// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AgentEscrow} from "../../contracts/AgentEscrow.sol";

/**
 * @title MaliciousReceiver
 * @notice Reentrancy attack mock. When it receives ETH from AgentEscrow's
 *         `call{value:}` in confirmPayment / requestRefund, it tries to
 *         re-enter the escrow on the same requestId. Because the contract
 *         transitions state BEFORE the external call (checks-effects-interactions),
 *         the re-entry should hit the "Payment not in Locked state" require
 *         and revert — which in turn bubbles up and fails the original call.
 *
 *         Tests use this to assert that the contract is reentrancy-safe.
 */
contract MaliciousReceiver {
    AgentEscrow public escrow;
    string public targetRequestId;
    uint8 public mode; // 0 = no-op (benign receiver), 1 = re-enter confirm, 2 = re-enter refund, 3 = re-enter cancel
    bool public reentered;

    constructor(address _escrow) {
        escrow = AgentEscrow(_escrow);
    }

    function arm(string calldata _requestId, uint8 _mode) external {
        targetRequestId = _requestId;
        mode = _mode;
        reentered = false;
    }

    // Helper: call createPayment from this contract so msg.sender == this
    function createPaymentAsPayer(
        string calldata requestId,
        address payee,
        uint256 timeoutBlocks,
        uint256 challengePeriod
    ) external payable returns (bool) {
        return escrow.createPayment{value: msg.value}(requestId, payee, timeoutBlocks, challengePeriod);
    }

    function confirmAsPayer(string calldata requestId) external {
        escrow.confirmPayment(requestId);
    }

    function refundAsPayer(string calldata requestId) external {
        escrow.requestRefund(requestId);
    }

    function cancelAsPayer(string calldata requestId) external {
        escrow.cancelPayment(requestId);
    }

    receive() external payable {
        if (mode == 1) {
            reentered = true;
            // Should revert because state has already transitioned away from Locked
            escrow.confirmPayment(targetRequestId);
        } else if (mode == 2) {
            reentered = true;
            escrow.requestRefund(targetRequestId);
        } else if (mode == 3) {
            reentered = true;
            escrow.cancelPayment(targetRequestId);
        }
        // mode == 0: benign — accept ETH without re-entering
    }
}
