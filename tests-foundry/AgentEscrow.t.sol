// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {AgentEscrow} from "../contracts/AgentEscrow.sol";
import {MaliciousReceiver} from "./mocks/MaliciousReceiver.sol";

/**
 * @title AgentEscrowTest
 * @notice Foundry test suite for AgentEscrow.sol — covers:
 *   - happy path: createPayment → confirmPayment → funds released
 *   - timeout + challenge period: requestRefund flow
 *   - cancellation flow
 *   - access-control: only payer can confirm / refund / cancel
 *   - state-machine guards: cannot double-spend, cannot operate on wrong state
 *   - event emission for each state transition
 *   - reentrancy: malicious payee/payer cannot re-enter during call{value:}
 *   - view helpers: isExpired, isState, getPayment
 */
contract AgentEscrowTest is Test {
    AgentEscrow internal escrow;

    address internal payer  = makeAddr("payer");
    address internal payee  = makeAddr("payee");
    address internal stranger = makeAddr("stranger");

    uint256 internal constant CHAIN_ID = 1;
    uint256 internal constant TIMEOUT_BLOCKS = 100;
    uint256 internal constant CHALLENGE_PERIOD = 10;
    uint256 internal constant AMOUNT = 1 ether;

    // Re-declare events for vm.expectEmit (must match AgentEscrow exactly)
    event PaymentCreated(string indexed requestId, address indexed payer, address indexed payee, uint256 amount);
    event PaymentLocked(string indexed requestId);
    event PaymentConfirmed(string indexed requestId, address indexed payer);
    event PaymentReleased(string indexed requestId, address indexed payee, uint256 amount);
    event PaymentRefunded(string indexed requestId, address indexed payer, uint256 amount);
    event AgentRegistered(address indexed agent);

    function setUp() public {
        escrow = new AgentEscrow(CHAIN_ID);
        vm.deal(payer, 10 ether);
        vm.deal(stranger, 10 ether);
    }

    // -----------------------------------------------------------------
    // Constructor + immutables
    // -----------------------------------------------------------------

    function test_Constructor_SetsChainId() public {
        assertEq(escrow.chainId(), CHAIN_ID, "chainId not set");
        AgentEscrow another = new AgentEscrow(42);
        assertEq(another.chainId(), 42, "second instance chainId not set");
    }

    // -----------------------------------------------------------------
    // Agent registration
    // -----------------------------------------------------------------

    function test_RegisterAgent_EmitsEventAndUpdatesMapping() public {
        vm.expectEmit(true, false, false, true);
        emit AgentRegistered(payee);
        escrow.registerAgent(payee);
        assertTrue(escrow.registeredAgents(payee), "agent not registered");
    }

    // -----------------------------------------------------------------
    // createPayment — happy path + input validation
    // -----------------------------------------------------------------

    function test_CreatePayment_HappyPath() public {
        string memory rid = "req-001";

        // expect PaymentCreated then PaymentLocked
        vm.expectEmit(true, true, true, true);
        emit PaymentCreated(rid, payer, payee, AMOUNT);
        vm.expectEmit(true, false, false, false);
        emit PaymentLocked(rid);

        vm.prank(payer);
        bool ok = escrow.createPayment{value: AMOUNT}(rid, payee, TIMEOUT_BLOCKS, CHALLENGE_PERIOD);
        assertTrue(ok, "createPayment did not return true");

        assertEq(address(escrow).balance, AMOUNT, "escrow did not hold funds");
        assertTrue(escrow.isState(rid, AgentEscrow.State.Locked), "state != Locked");

        AgentEscrow.Payment memory p = escrow.getPayment(rid);
        assertEq(p.payer, payer);
        assertEq(p.payee, payee);
        assertEq(p.amount, AMOUNT);
        assertEq(p.timeoutBlocks, TIMEOUT_BLOCKS);
        assertEq(p.challengePeriod, CHALLENGE_PERIOD);
        assertEq(p.requestId, rid);
        assertEq(p.createdAt, block.number);
    }

    function test_CreatePayment_RevertsOnZeroValue() public {
        vm.prank(payer);
        vm.expectRevert(bytes("Must send ETH"));
        escrow.createPayment{value: 0}("rid", payee, TIMEOUT_BLOCKS, CHALLENGE_PERIOD);
    }

    function test_CreatePayment_RevertsOnEmptyRequestId() public {
        vm.prank(payer);
        vm.expectRevert(bytes("requestId cannot be empty"));
        escrow.createPayment{value: AMOUNT}("", payee, TIMEOUT_BLOCKS, CHALLENGE_PERIOD);
    }

    function test_CreatePayment_RevertsOnZeroPayee() public {
        vm.prank(payer);
        vm.expectRevert(bytes("payee cannot be zero address"));
        escrow.createPayment{value: AMOUNT}("rid", address(0), TIMEOUT_BLOCKS, CHALLENGE_PERIOD);
    }

    function test_CreatePayment_RevertsOnDuplicateRequestId() public {
        vm.startPrank(payer);
        escrow.createPayment{value: AMOUNT}("dup", payee, TIMEOUT_BLOCKS, CHALLENGE_PERIOD);
        vm.expectRevert(bytes("requestId already exists"));
        escrow.createPayment{value: AMOUNT}("dup", payee, TIMEOUT_BLOCKS, CHALLENGE_PERIOD);
        vm.stopPrank();
    }

    function test_CreatePayment_RevertsOnZeroTimeout() public {
        vm.prank(payer);
        vm.expectRevert(bytes("timeoutBlocks must be > 0"));
        escrow.createPayment{value: AMOUNT}("rid", payee, 0, CHALLENGE_PERIOD);
    }

    // -----------------------------------------------------------------
    // confirmPayment — happy path + guards
    // -----------------------------------------------------------------

    function test_ConfirmPayment_ReleasesFundsAndEmitsEvents() public {
        string memory rid = "req-confirm";
        _createPayment(rid, payer, payee, AMOUNT, TIMEOUT_BLOCKS, CHALLENGE_PERIOD);

        uint256 payeeBalanceBefore = payee.balance;

        vm.expectEmit(true, true, false, false);
        emit PaymentConfirmed(rid, payer);
        vm.expectEmit(true, true, false, true);
        emit PaymentReleased(rid, payee, AMOUNT);

        vm.prank(payer);
        bool ok = escrow.confirmPayment(rid);
        assertTrue(ok, "confirmPayment did not return true");

        assertEq(payee.balance - payeeBalanceBefore, AMOUNT, "payee did not receive funds");
        assertEq(address(escrow).balance, 0, "escrow still holds funds");
        assertTrue(escrow.isState(rid, AgentEscrow.State.Released), "state != Released");
    }

    function test_ConfirmPayment_RevertsIfNotPayer() public {
        string memory rid = "req-not-payer";
        _createPayment(rid, payer, payee, AMOUNT, TIMEOUT_BLOCKS, CHALLENGE_PERIOD);

        vm.prank(stranger);
        vm.expectRevert(bytes("Only payer can confirm"));
        escrow.confirmPayment(rid);
    }

    function test_ConfirmPayment_RevertsIfAlreadyReleased() public {
        string memory rid = "req-double-release";
        _createPayment(rid, payer, payee, AMOUNT, TIMEOUT_BLOCKS, CHALLENGE_PERIOD);

        vm.prank(payer);
        escrow.confirmPayment(rid);

        vm.prank(payer);
        vm.expectRevert(bytes("Payment not in Locked state"));
        escrow.confirmPayment(rid);
    }

    function test_ConfirmPayment_RevertsAfterExpiry() public {
        string memory rid = "req-expired";
        _createPayment(rid, payer, payee, AMOUNT, TIMEOUT_BLOCKS, CHALLENGE_PERIOD);

        // Roll forward past timeout
        vm.roll(block.number + TIMEOUT_BLOCKS + 1);

        vm.prank(payer);
        vm.expectRevert(bytes("Payment has expired"));
        escrow.confirmPayment(rid);
    }

    // -----------------------------------------------------------------
    // requestRefund — happy path + guards
    // -----------------------------------------------------------------

    function test_RequestRefund_AfterTimeoutAndChallenge() public {
        string memory rid = "req-refund";
        _createPayment(rid, payer, payee, AMOUNT, TIMEOUT_BLOCKS, CHALLENGE_PERIOD);

        uint256 payerBalanceBefore = payer.balance;

        // Roll past timeout + challenge
        vm.roll(block.number + TIMEOUT_BLOCKS + CHALLENGE_PERIOD);

        vm.expectEmit(true, true, false, true);
        emit PaymentRefunded(rid, payer, AMOUNT);

        vm.prank(payer);
        bool ok = escrow.requestRefund(rid);
        assertTrue(ok, "requestRefund did not return true");

        assertEq(payer.balance - payerBalanceBefore, AMOUNT, "payer did not get refund");
        assertEq(address(escrow).balance, 0, "escrow still holds funds");
        assertTrue(escrow.isState(rid, AgentEscrow.State.Refunded), "state != Refunded");
    }

    function test_RequestRefund_RevertsIfChallengeNotOver() public {
        string memory rid = "req-too-early";
        _createPayment(rid, payer, payee, AMOUNT, TIMEOUT_BLOCKS, CHALLENGE_PERIOD);

        // Past timeout but not past challenge
        vm.roll(block.number + TIMEOUT_BLOCKS);

        vm.prank(payer);
        vm.expectRevert(bytes("Challenge period not over"));
        escrow.requestRefund(rid);
    }

    function test_RequestRefund_RevertsIfNotPayer() public {
        string memory rid = "req-refund-not-payer";
        _createPayment(rid, payer, payee, AMOUNT, TIMEOUT_BLOCKS, CHALLENGE_PERIOD);

        vm.roll(block.number + TIMEOUT_BLOCKS + CHALLENGE_PERIOD);

        vm.prank(stranger);
        vm.expectRevert(bytes("Only payer can request refund"));
        escrow.requestRefund(rid);
    }

    function test_RequestRefund_RevertsIfAlreadyReleased() public {
        string memory rid = "req-released-then-refund";
        _createPayment(rid, payer, payee, AMOUNT, TIMEOUT_BLOCKS, CHALLENGE_PERIOD);

        vm.prank(payer);
        escrow.confirmPayment(rid);

        vm.roll(block.number + TIMEOUT_BLOCKS + CHALLENGE_PERIOD);

        vm.prank(payer);
        vm.expectRevert(bytes("Payment not in Locked state"));
        escrow.requestRefund(rid);
    }

    // -----------------------------------------------------------------
    // cancelPayment — happy path + guards
    // -----------------------------------------------------------------

    function test_CancelPayment_ReturnsFundsToPayer() public {
        string memory rid = "req-cancel";
        _createPayment(rid, payer, payee, AMOUNT, TIMEOUT_BLOCKS, CHALLENGE_PERIOD);

        uint256 payerBalanceBefore = payer.balance;

        vm.prank(payer);
        bool ok = escrow.cancelPayment(rid);
        assertTrue(ok, "cancelPayment did not return true");

        assertEq(payer.balance - payerBalanceBefore, AMOUNT, "payer did not get cancel refund");
        assertTrue(escrow.isState(rid, AgentEscrow.State.Cancelled), "state != Cancelled");

        AgentEscrow.Payment memory p = escrow.getPayment(rid);
        assertEq(p.amount, 0, "amount not zeroed");
    }

    function test_CancelPayment_RevertsIfNotPayer() public {
        string memory rid = "req-cancel-not-payer";
        _createPayment(rid, payer, payee, AMOUNT, TIMEOUT_BLOCKS, CHALLENGE_PERIOD);

        vm.prank(stranger);
        vm.expectRevert(bytes("Only payer can cancel"));
        escrow.cancelPayment(rid);
    }

    function test_CancelPayment_RevertsIfAlreadyConfirmed() public {
        string memory rid = "req-cancel-after-confirm";
        _createPayment(rid, payer, payee, AMOUNT, TIMEOUT_BLOCKS, CHALLENGE_PERIOD);

        vm.prank(payer);
        escrow.confirmPayment(rid);

        vm.prank(payer);
        vm.expectRevert(bytes("Payment not in Locked state"));
        escrow.cancelPayment(rid);
    }

    // -----------------------------------------------------------------
    // View helpers
    // -----------------------------------------------------------------

    function test_IsExpired_FalseForUnknownRequest() public view {
        assertFalse(escrow.isExpired("nonexistent"), "unknown rid should not be expired");
    }

    function test_IsExpired_FalseBeforeTimeout() public {
        string memory rid = "req-exp-1";
        _createPayment(rid, payer, payee, AMOUNT, TIMEOUT_BLOCKS, CHALLENGE_PERIOD);
        assertFalse(escrow.isExpired(rid), "should not be expired immediately");
    }

    function test_IsExpired_TrueAfterTimeout() public {
        string memory rid = "req-exp-2";
        _createPayment(rid, payer, payee, AMOUNT, TIMEOUT_BLOCKS, CHALLENGE_PERIOD);
        vm.roll(block.number + TIMEOUT_BLOCKS);
        assertTrue(escrow.isExpired(rid), "should be expired after timeout");
    }

    function test_IsExpired_FalseAfterRelease() public {
        string memory rid = "req-exp-3";
        _createPayment(rid, payer, payee, AMOUNT, TIMEOUT_BLOCKS, CHALLENGE_PERIOD);
        vm.prank(payer);
        escrow.confirmPayment(rid);
        vm.roll(block.number + TIMEOUT_BLOCKS + 10);
        // isExpired requires State.Locked, so released payments are not "expired"
        assertFalse(escrow.isExpired(rid), "released payment should not be expired");
    }

    // -----------------------------------------------------------------
    // Reentrancy
    // -----------------------------------------------------------------

    function test_Reentrancy_ConfirmPaymentCannotBeReentered() public {
        // Set malicious receiver as the payee. When escrow.call{value:}() lands,
        // the receiver will try to re-enter confirmPayment for the same rid.
        // The re-entry MUST revert because state is already Released —
        // and that bubbles up to fail the original confirmPayment call.
        MaliciousReceiver mal = new MaliciousReceiver(address(escrow));
        string memory rid = "req-reenter-confirm";

        vm.prank(payer);
        escrow.createPayment{value: AMOUNT}(rid, address(mal), TIMEOUT_BLOCKS, CHALLENGE_PERIOD);

        mal.arm(rid, 1); // mode 1 = re-enter confirm

        vm.prank(payer);
        vm.expectRevert(bytes("Transfer to payee failed"));
        escrow.confirmPayment(rid);

        // State should still be Locked (revert reverted the state change too)
        assertTrue(escrow.isState(rid, AgentEscrow.State.Locked), "state should still be Locked after revert");
        assertEq(address(escrow).balance, AMOUNT, "escrow should still hold funds");
    }

    function test_Reentrancy_RequestRefundCannotBeReentered() public {
        // Payer is the malicious receiver this time
        MaliciousReceiver mal = new MaliciousReceiver(address(escrow));
        vm.deal(address(mal), 10 ether);

        string memory rid = "req-reenter-refund";
        mal.createPaymentAsPayer{value: AMOUNT}(rid, payee, TIMEOUT_BLOCKS, CHALLENGE_PERIOD);

        // Past timeout + challenge
        vm.roll(block.number + TIMEOUT_BLOCKS + CHALLENGE_PERIOD);

        mal.arm(rid, 2); // mode 2 = re-enter requestRefund

        vm.expectRevert(bytes("Refund transfer failed"));
        mal.refundAsPayer(rid);

        assertTrue(escrow.isState(rid, AgentEscrow.State.Locked), "state should still be Locked after revert");
        assertEq(address(escrow).balance, AMOUNT, "escrow should still hold funds");
    }

    function test_Reentrancy_CancelPaymentCannotBeReentered() public {
        MaliciousReceiver mal = new MaliciousReceiver(address(escrow));
        vm.deal(address(mal), 10 ether);

        string memory rid = "req-reenter-cancel";
        mal.createPaymentAsPayer{value: AMOUNT}(rid, payee, TIMEOUT_BLOCKS, CHALLENGE_PERIOD);

        mal.arm(rid, 3); // mode 3 = re-enter cancel

        vm.expectRevert(bytes("Cancel refund failed"));
        mal.cancelAsPayer(rid);

        assertTrue(escrow.isState(rid, AgentEscrow.State.Locked), "state should still be Locked after revert");
        assertEq(address(escrow).balance, AMOUNT, "escrow should still hold funds");
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    function _createPayment(
        string memory rid,
        address _payer,
        address _payee,
        uint256 amount,
        uint256 timeoutBlocks,
        uint256 challengePeriod
    ) internal {
        vm.prank(_payer);
        escrow.createPayment{value: amount}(rid, _payee, timeoutBlocks, challengePeriod);
    }
}
