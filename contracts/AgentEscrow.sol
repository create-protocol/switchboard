// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IOracleAggregator} from "./IOracleAggregator.sol";

/**
 * @title AgentEscrow
 * @notice Escrow contract for agent-to-agent payments with timeout and refund.
 * @dev    Implements a two-party payment protocol where a payer locks funds on
 *         behalf of an agent (payee). Funds are released by one of three paths:
 *
 *         1. **Payer confirmation** — payer calls `confirmPayment` before timeout;
 *            always available regardless of whether a policy was set.
 *         2. **Oracle attestation** — any caller submits a quorum-signed attestation
 *            via `releaseByAttestation`; only valid when a non-zero `policyHash` was
 *            supplied at creation time and an `oracleAggregator` is configured.
 *         3. **Refund after timeout** — payer reclaims via `requestRefund` after
 *            `timeoutBlocks + challengePeriod` blocks have elapsed.
 *
 *         **Access-control note**: `registerAgent` is currently permissionless — any
 *         address may add itself to the `registeredAgents` whitelist. If the
 *         `onlyRegisteredAgent` modifier is used to guard future privileged operations,
 *         `registerAgent` MUST be restricted (e.g. to an owner or DAO). Deploy
 *         integrators should account for this until an owner model is added.
 *
 *         **Dead-code note**: `AgentDeregistered` is declared but never emitted
 *         because no `deregisterAgent` function exists. A companion PR should add
 *         `deregisterAgent(address)` (owner-only) or remove the orphaned event.
 *
 * Backward compatibility:
 *   - The original 4-arg `createPayment(string, address, uint256, uint256)` is
 *     preserved and equivalent to passing `policyHash = bytes32(0)`, which disables
 *     oracle release for that payment.
 *   - All existing functions (`confirmPayment`, `requestRefund`, `cancelPayment`,
 *     `getPayment`, `isState`, `isExpired`) are unchanged in signature and behaviour.
 */
contract AgentEscrow {
    /// @notice Lifecycle states a payment can occupy.
    /// @dev    Terminal states are `Confirmed`, `Released`, `Refunded`, and `Cancelled`.
    ///         A payment can only leave `Locked` state — it starts there on creation.
    ///         `Created` is reserved for future use; the current implementation sets
    ///         `Locked` immediately in `_createPayment`.
    enum State { Created, Locked, Confirmed, Released, Refunded, Cancelled }

    /// @notice All stored fields for a single escrow payment.
    /// @dev    `requestId` is an off-chain correlation key and is also used as the
    ///         primary mapping key. Callers must ensure uniqueness — duplicate
    ///         `requestId` values are rejected by `_createPayment`.
    struct Payment {
        /// @dev Address that deposited ETH and may confirm or cancel.
        address payer;
        /// @dev Address that will receive ETH on successful release.
        address payee;
        /// @dev ETH amount in wei locked in this escrow entry.
        uint256 amount;
        /// @dev Number of blocks after `createdAt` before the payment is considered
        ///      expired. Must be > 0.
        uint256 timeoutBlocks;
        /// @dev Additional blocks past `timeoutBlocks` that must elapse before payer
        ///      may reclaim via `requestRefund`. Provides a grace window for late
        ///      oracle attestations.
        uint256 challengePeriod;
        /// @dev Current lifecycle state.
        State state;
        /// @dev Off-chain payment request identifier. Duplicates the mapping key for
        ///      convenience when the struct is returned as a value.
        string requestId;
        /// @dev Block number at which this payment was created (set by `_createPayment`).
        uint256 createdAt;
        /// @dev keccak256 of the canonical policy JSON. `bytes32(0)` means oracle release
        ///      is disabled; any non-zero value enables `releaseByAttestation` for this
        ///      payment. See `kcolbchain/escrow-oracles` SPEC.md §3.
        bytes32 policyHash;
    }

    /// @notice Chain ID supplied at construction; used for cross-chain replay protection
    ///         in off-chain tooling.
    uint256 public immutable chainId;

    /// @notice Oracle aggregator consulted on `releaseByAttestation`.
    /// @dev    Set once at construction. `address(0)` disables oracle release even
    ///         for payments that declared a non-zero `policyHash`. In that case,
    ///         `createPaymentWithPolicy` reverts with "no aggregator configured" when
    ///         a non-zero hash is provided.
    IOracleAggregator public immutable oracleAggregator;

    /// @notice Maps a payment's `requestId` to its stored `Payment` struct.
    mapping(string => Payment) public payments;

    /// @notice True for addresses that have been registered as agents.
    /// @dev    See access-control note in the contract-level NatSpec — this mapping
    ///         is currently writable by anyone via the permissionless `registerAgent`.
    mapping(address => bool) public registeredAgents;

    // ─── Events ─────────────────────────────────────────────────────────────

    /// @notice Emitted when a new payment is created and ETH is locked.
    /// @param requestId Off-chain request identifier.
    /// @param payer     Address that sent ETH.
    /// @param payee     Address designated to receive ETH.
    /// @param amount    Wei value locked.
    event PaymentCreated(string indexed requestId, address indexed payer, address indexed payee, uint256 amount);

    /// @notice Emitted immediately after `PaymentCreated` to signal the payment
    ///         has entered `Locked` state.
    /// @param requestId Off-chain request identifier.
    event PaymentLocked(string indexed requestId);

    /// @notice Emitted when the payer explicitly confirms the payment.
    /// @param requestId Off-chain request identifier.
    /// @param payer     Address that called `confirmPayment`.
    event PaymentConfirmed(string indexed requestId, address indexed payer);

    /// @notice Emitted when ETH is transferred to the payee (any release path).
    /// @param requestId Off-chain request identifier.
    /// @param payee     Recipient of the released ETH.
    /// @param amount    Wei transferred.
    event PaymentReleased(string indexed requestId, address indexed payee, uint256 amount);

    /// @notice Emitted alongside `PaymentReleased` when the oracle aggregator
    ///         authorised the release via `releaseByAttestation`.
    /// @param requestId      Off-chain request identifier.
    /// @param policyHash     Hash of the policy that governed this release.
    /// @param attestationHash Hash of the attestation transcript accepted by the aggregator.
    event PaymentReleasedByOracle(string indexed requestId, bytes32 policyHash, bytes32 attestationHash);

    /// @notice Emitted when a payer reclaims ETH after timeout + challenge period.
    /// @param requestId Off-chain request identifier.
    /// @param payer     Address that received the refund.
    /// @param amount    Wei refunded.
    event PaymentRefunded(string indexed requestId, address indexed payer, uint256 amount);

    /// @notice Emitted when an address is added to the registered-agents whitelist.
    /// @param agent Address that was registered.
    event AgentRegistered(address indexed agent);

    /// @notice Emitted when an address is removed from the registered-agents whitelist.
    /// @dev    Currently unreachable — no `deregisterAgent` function has been
    ///         implemented. This event is reserved for a follow-up that adds
    ///         owner-gated deregistration. Do not rely on observing this event.
    event AgentDeregistered(address indexed agent);

    // ─── Constructor ────────────────────────────────────────────────────────

    /// @notice Deploy a new AgentEscrow instance.
    /// @param _chainId    Chain ID this contract is deployed on. Embedded in payment
    ///                    metadata for off-chain replay-protection purposes.
    /// @param _aggregator Optional oracle aggregator address. Pass `address(0)` to
    ///                    deploy without oracle-release support; any attempt to create
    ///                    a payment with a non-zero `policyHash` will revert.
    constructor(uint256 _chainId, IOracleAggregator _aggregator) {
        chainId = _chainId;
        oracleAggregator = _aggregator;
    }

    // ─── Modifiers ──────────────────────────────────────────────────────────

    /// @dev Reverts if the caller is not in `registeredAgents`.
    ///      Currently unused by the public API; reserved for privileged operations
    ///      that may be added in future upgrades.
    modifier onlyRegisteredAgent() {
        require(registeredAgents[msg.sender], "Caller is not a registered agent");
        _;
    }

    // ─── Agent registry ─────────────────────────────────────────────────────

    /// @notice Add `agent` to the registered-agents whitelist.
    /// @dev    **WARNING: permissionless.** Any address may register itself or
    ///         register others. Until an owner or access-control model is added,
    ///         `registeredAgents` should not be used as a trust anchor for
    ///         security-critical checks. See contract-level NatSpec for context.
    /// @param agent Address to register.
    function registerAgent(address agent) external {
        registeredAgents[agent] = true;
        emit AgentRegistered(agent);
    }

    // ─── Payment creation ───────────────────────────────────────────────────

    /// @notice Create a payment request and lock the sent ETH in escrow.
    /// @dev    Backward-compatible 4-arg form. Equivalent to calling
    ///         `createPaymentWithPolicy` with `policyHash = bytes32(0)`, which
    ///         disables oracle-mediated release for this payment. Payer-only
    ///         confirmation via `confirmPayment` is the only release path.
    /// @param requestId      Unique off-chain identifier for this payment. Must be
    ///                       non-empty and not already in use.
    /// @param payee          Address designated to receive the locked ETH.
    /// @param timeoutBlocks  Number of blocks from now after which the payment is
    ///                       considered expired. Must be greater than zero.
    /// @param challengePeriod Additional blocks after `timeoutBlocks` that must pass
    ///                       before the payer may call `requestRefund`.
    /// @return               Always `true` on success; reverts on any error.
    function createPayment(
        string calldata requestId,
        address payee,
        uint256 timeoutBlocks,
        uint256 challengePeriod
    ) external payable returns (bool) {
        return _createPayment(requestId, payee, timeoutBlocks, challengePeriod, bytes32(0));
    }

    /// @notice Create a payment and opt it in to oracle-mediated release.
    /// @dev    A non-zero `policyHash` enables `releaseByAttestation` for this
    ///         payment. The hash should be the keccak256 of the canonical policy JSON
    ///         defined in `kcolbchain/escrow-oracles` SPEC.md §3. Payer-only
    ///         confirmation via `confirmPayment` remains available as a fallback.
    ///
    ///         Reverts with "no aggregator configured" if `policyHash != bytes32(0)`
    ///         and the contract was deployed with `_aggregator = address(0)`.
    /// @param requestId      Unique off-chain identifier for this payment.
    /// @param payee          Address designated to receive the locked ETH.
    /// @param timeoutBlocks  Number of blocks from now after which the payment expires.
    /// @param challengePeriod Blocks after `timeoutBlocks` before the payer may refund.
    /// @param policyHash     keccak256 of the governing policy JSON, or `bytes32(0)` to
    ///                       behave identically to the 4-arg `createPayment`.
    /// @return               Always `true` on success; reverts on any error.
    function createPaymentWithPolicy(
        string calldata requestId,
        address payee,
        uint256 timeoutBlocks,
        uint256 challengePeriod,
        bytes32 policyHash
    ) external payable returns (bool) {
        if (policyHash != bytes32(0)) {
            require(address(oracleAggregator) != address(0), "no aggregator configured");
        }
        return _createPayment(requestId, payee, timeoutBlocks, challengePeriod, policyHash);
    }

    /// @dev Internal implementation shared by both `createPayment` variants.
    ///      Validates inputs, stores the `Payment` struct, and emits
    ///      `PaymentCreated` + `PaymentLocked`. The payment starts in `Locked` state.
    function _createPayment(
        string calldata requestId,
        address payee,
        uint256 timeoutBlocks,
        uint256 challengePeriod,
        bytes32 policyHash
    ) internal returns (bool) {
        require(msg.value > 0, "Must send ETH");
        require(bytes(requestId).length > 0, "requestId cannot be empty");
        require(payee != address(0), "payee cannot be zero address");
        require(payments[requestId].createdAt == 0, "requestId already exists");
        require(timeoutBlocks > 0, "timeoutBlocks must be > 0");

        payments[requestId] = Payment({
            payer: msg.sender,
            payee: payee,
            amount: msg.value,
            timeoutBlocks: timeoutBlocks,
            challengePeriod: challengePeriod,
            state: State.Locked,
            requestId: requestId,
            createdAt: block.number,
            policyHash: policyHash
        });

        emit PaymentCreated(requestId, msg.sender, payee, msg.value);
        emit PaymentLocked(requestId);
        return true;
    }

    // ─── Payment release ────────────────────────────────────────────────────

    /// @notice Payer confirms work is done and releases the escrowed ETH to the payee.
    /// @dev    Only the original payer may call this. Reverts if the payment has
    ///         already expired (`block.number >= createdAt + timeoutBlocks`). Works
    ///         regardless of whether a `policyHash` was set — payer-only confirmation
    ///         is always an available fallback.
    ///
    ///         Uses a low-level `.call` to transfer ETH. If the payee is a contract
    ///         that reverts on receive, this call will fail and the entire transaction
    ///         will revert, leaving funds locked. Integrators should ensure payees
    ///         can accept plain ETH transfers.
    /// @param requestId Off-chain identifier of the payment to confirm.
    /// @return          Always `true` on success; reverts on any error.
    function confirmPayment(string calldata requestId) external returns (bool) {
        Payment storage p = payments[requestId];
        require(p.payer == msg.sender, "Only payer can confirm");
        require(p.state == State.Locked, "Payment not in Locked state");
        require(block.number < p.createdAt + p.timeoutBlocks, "Payment has expired");

        p.state = State.Released;

        (bool success, ) = p.payee.call{value: p.amount}("");
        require(success, "Transfer to payee failed");

        emit PaymentConfirmed(requestId, msg.sender);
        emit PaymentReleased(requestId, p.payee, p.amount);
        return true;
    }

    /// @notice Oracle-mediated release. Any caller may submit a quorum attestation;
    ///         the configured `oracleAggregator` verifies it meets the threshold for
    ///         this payment's `policyHash`.
    /// @dev    Reverts if:
    ///         - the payment is not in `Locked` state,
    ///         - the payment has no `policyHash` (oracle release was not opted into),
    ///         - the timeout has elapsed (use `requestRefund` after the challenge
    ///           period instead),
    ///         - the `oracleAggregator` address is zero, or
    ///         - `oracleAggregator.verifyRelease` returns `false`.
    ///
    ///         This function is intentionally permissionless on the caller side — the
    ///         trust boundary is enforced by the aggregator, not by `msg.sender`.
    /// @param requestId       Off-chain identifier of the payment to release.
    /// @param attestationHash keccak256 of the canonical attestation transcript.
    /// @param signatures      Array of oracle signatures over `attestationHash`.
    /// @return                Always `true` on success; reverts on any error.
    function releaseByAttestation(
        string calldata requestId,
        bytes32 attestationHash,
        bytes[] calldata signatures
    ) external returns (bool) {
        Payment storage p = payments[requestId];
        require(p.state == State.Locked, "Payment not in Locked state");
        require(p.policyHash != bytes32(0), "No oracle policy on this payment");
        require(block.number < p.createdAt + p.timeoutBlocks, "Payment has expired");
        require(address(oracleAggregator) != address(0), "No aggregator");
        require(
            oracleAggregator.verifyRelease(p.policyHash, attestationHash, signatures),
            "Oracle attestation rejected"
        );

        p.state = State.Released;

        (bool success, ) = p.payee.call{value: p.amount}("");
        require(success, "Transfer to payee failed");

        emit PaymentReleasedByOracle(requestId, p.policyHash, attestationHash);
        emit PaymentReleased(requestId, p.payee, p.amount);
        return true;
    }

    // ─── Refund & cancellation ──────────────────────────────────────────────

    /// @notice Payer reclaims escrowed ETH after the timeout and challenge period.
    /// @dev    The payer must wait at least `timeoutBlocks + challengePeriod` blocks
    ///         from `createdAt` before calling this. The challenge period gives a
    ///         grace window for the payee or oracles to trigger release. Only
    ///         callable by the original payer.
    /// @param requestId Off-chain identifier of the payment to refund.
    /// @return          Always `true` on success; reverts on any error.
    function requestRefund(string calldata requestId) external returns (bool) {
        Payment storage p = payments[requestId];
        require(p.payer == msg.sender, "Only payer can request refund");
        require(p.state == State.Locked, "Payment not in Locked state");
        require(
            block.number >= p.createdAt + p.timeoutBlocks + p.challengePeriod,
            "Challenge period not over"
        );

        p.state = State.Refunded;

        (bool success, ) = p.payer.call{value: p.amount}("");
        require(success, "Refund transfer failed");

        emit PaymentRefunded(requestId, p.payer, p.amount);
        return true;
    }

    /// @notice Cancel a payment before timeout and return ETH to the payer.
    /// @dev    Only the original payer may cancel, and only while the payment is
    ///         in `Locked` state (before timeout and before any release). This is
    ///         an early-exit path for cases where the payer and agent mutually agree
    ///         the work will not proceed.
    ///
    ///         `p.amount` is zeroed before the ETH transfer to guard against
    ///         reentrancy. The state is also set to `Cancelled` prior to the call.
    /// @param requestId Off-chain identifier of the payment to cancel.
    /// @return          Always `true` on success; reverts on any error.
    function cancelPayment(string calldata requestId) external returns (bool) {
        Payment storage p = payments[requestId];
        require(p.payer == msg.sender, "Only payer can cancel");
        require(p.state == State.Locked, "Payment not in Locked state");

        uint256 amount = p.amount;
        p.state = State.Cancelled;
        p.amount = 0;

        (bool success, ) = p.payer.call{value: amount}("");
        require(success, "Cancel refund failed");

        return true;
    }

    // ─── View helpers ───────────────────────────────────────────────────────

    /// @notice Retrieve the full `Payment` struct for a given request ID.
    /// @dev    Returns a zero-initialised struct (with `createdAt == 0`) for
    ///         request IDs that do not exist. Callers should check `createdAt != 0`
    ///         to distinguish a real payment from a missing entry.
    /// @param requestId Off-chain identifier to look up.
    /// @return          The stored `Payment` value, or a zeroed struct if not found.
    function getPayment(string calldata requestId) external view returns (Payment memory) {
        return payments[requestId];
    }

    /// @notice Check whether a payment is in a specific lifecycle state.
    /// @param requestId Off-chain identifier to check.
    /// @param expected  The state to compare against.
    /// @return          `true` iff `payments[requestId].state == expected`.
    function isState(string calldata requestId, State expected) external view returns (bool) {
        return payments[requestId].state == expected;
    }

    /// @notice Check whether a payment has passed its timeout and is still Locked.
    /// @dev    Returns `false` for unknown request IDs (detected via `createdAt == 0`).
    ///         Note that "expired" and "refundable" are distinct: an expired payment
    ///         may still be within its `challengePeriod` and therefore not yet
    ///         eligible for `requestRefund`.
    /// @param requestId Off-chain identifier to check.
    /// @return          `true` iff the payment exists, is `Locked`, and
    ///                  `block.number >= createdAt + timeoutBlocks`.
    function isExpired(string calldata requestId) external view returns (bool) {
        Payment storage p = payments[requestId];
        if (p.createdAt == 0) return false;
        return block.number >= p.createdAt + p.timeoutBlocks && p.state == State.Locked;
    }
}
