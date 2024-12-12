// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import { OAppRead } from "@layerzerolabs/oapp-evm/contracts/oapp/OAppRead.sol";
import {ILayerZeroEndpointV2, MessagingFee, MessagingReceipt, Origin} from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import {ReadCodecV1, EVMCallComputeV1, EVMCallRequestV1} from "@layerzerolabs/oapp-evm/contracts/oapp/libs/ReadCodecV1.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import {OptionsBuilder} from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OptionsBuilder.sol";
import { AddressCast } from "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/AddressCast.sol";

contract LzReadDemo is OAppRead {
    using OptionsBuilder for bytes;

    /*«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-*/
    /*                           EVENTS                           */
    /*-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»*/

    event LogBytes(bytes data);

    event LogUint256(uint256 x);

    /*«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-*/
    /*                       CUSTOM ERRORS                        */
    /*-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»*/

    /// @dev The claim nonce has already been used.
    error ClaimNonceUsed();

    /// @dev Cannot be performed when the contract is paused.
    error Paused();

    /// @dev The vesting config must have one of `nft` and `collector` as a non-zero address.
    error InvalidVestingConfig();

    /// @dev The `uuid` in the config must match the existing `uuid` for the `(nft, tokenId)` pair.
    error InvalidUuid();

    /// @dev The current chain ID is not supported.
    error UnsupportedChainId();

    /// @dev The lengths of the input arrays are not the same.
    error ArrayLengthsMismatch();

    /// @dev The Merkle proof provided is invalid.
    error InvalidProof();

    /// @dev The ECDSA signature provided is invalid.
    error InvalidSignature();

    /// @dev For safety guardrails.
    error ExceedDailyTotalWithdrawnLimit();

    /// @dev Not authorized to call the function.
    error Unauthorized();

    /// @dev Cannot send tokens to the zero address.
    error ToIsZeroAddress();

    /// @dev Contract is not ready for claim.
    error NotReadyForClaim();

    /// @dev The sender or recipient is on the sanctions list.
    error Sanctioned();

    /*«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-*/
    /*                         CONSTANTS                          */
    /*-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»*/

    /// @dev Read message type
    uint8 internal constant _LZ_READ_TYPE = 1;

    /// @dev Same for Ethereum and Arbitrum.
    address internal constant _LZ_ENDPOINT = 0x1a44076050125825900e736c501f859c50fE728c;

    /// @dev Same for Sepolia and Arbitrum Sepolia.
    address internal constant _LZ_TESTNET_ENDPOINT = 0x6EDCE65403992e310A62460808c4b910D972f10f;

    /// @dev `lzRead` responses are sent from arbitrary channels with Endpoint IDs 
    /// in the range of `eid > 4294965694` (which is `type(uint32).max - 1600`).
    uint32 internal constant _READ_CHANNEL_EID_THRESHOLD = 4294965694;

    /// @dev See: https://chainlist.org/chain/1
    uint256 internal constant _CHAIN_ID_ETHEREUM = 1;

    /// @dev See: https://chainlist.org/chain/11155111
    uint256 internal constant _CHAIN_ID_SEPOLIA = 11155111;

    /// @dev See: https://chainlist.org/chain/42161
    uint256 internal constant _CHAIN_ID_ARBITRUM = 42161;

    /// @dev See: https://chainlist.org/chain/421614
    uint256 internal constant _CHAIN_ID_ARBITRUM_SEPOLIA = 421614;

    /// @dev See: https://docs.layerzero.network/v2/developers/evm/technical-reference/deployed-contracts
    uint32 internal constant _LZ_EID_ETHEREUM = 30101;

    /// @dev See: https://docs.layerzero.network/v2/developers/evm/technical-reference/deployed-contracts
    uint32 internal constant _LZ_EID_SEPOLIA = 40161;

    /// @dev See: https://docs.layerzero.network/v2/developers/evm/technical-reference/deployed-contracts
    uint32 internal constant _LZ_EID_ARBITRUM = 30110;

    /// @dev See: https://docs.layerzero.network/v2/developers/evm/technical-reference/deployed-contracts
    uint32 internal constant _LZ_EID_ARBITRUM_SEPOLIA = 40231;

    /*«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-*/
    /*                        CONSTRUCTOR                         */
    /*-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»*/

    constructor() OAppRead(_lzEndpoint(), msg.sender) Ownable(msg.sender) {
        _setPeer(_lzReadChannel(), AddressCast.toBytes32(address(this)));
    }

    function quote(bytes memory options) public view returns (uint256) {
        return _quote(_lzReadChannel(), _readCmd(), options, false).nativeFee;
    }

    function readMapping(bytes memory options) external payable returns (MessagingReceipt memory receipt) {
        return
            _lzSend(
                _lzReadChannel(),
                _readCmd(),
                options,
                MessagingFee(msg.value, 0),
                payable(msg.sender)
            );
    }

    function _readCmd() internal view returns (bytes memory) {
        address target = 0xaaeE1A9723aaDB7afA2810263653A34bA2C21C7a; // MOG token.
        EVMCallRequestV1[] memory readRequests = new EVMCallRequestV1[](1);
        bytes memory callData = abi.encodeWithSignature("totalSupply()");
        readRequests[0] = EVMCallRequestV1({
            appRequestLabel: 1,
            targetEid: _lzTargetEid(),
            isBlockNum: false,
            blockNumOrTimestamp: uint64(block.timestamp),
            confirmations: 2,
            to: target,
            callData: callData
        });
        EVMCallComputeV1 memory computeSettings = EVMCallComputeV1({
            computeSetting: 2, // `lzMap() and lzReduce()`. I tried other stuff, but no go.
            targetEid: ILayerZeroEndpointV2(endpoint).eid(),
            isBlockNum: false,
            blockNumOrTimestamp: uint64(block.timestamp),
            confirmations: 15,
            to: address(this)
        });
        return ReadCodecV1.encode(0, readRequests, computeSettings);
    }
    
    function lzMap(bytes calldata, bytes calldata response) external pure returns (bytes memory) {
        return response;
    }

    function lzReduce(bytes calldata, bytes[] calldata responses) external pure returns (bytes memory) {
        return responses[0];
    }

    /// @dev For the `lzRead`.
    function _lzReceive(
        Origin calldata origin,
        bytes32 ,
        bytes calldata message,
        address ,
        bytes calldata 
    ) internal virtual override {
        if (origin.srcEid == _lzReadChannel()) {
            emit LogBytes(message);
        }
    }

    /// @dev Returns the options bytes used for estimating gas LayerZero gas payment.
    function _lzOptions() internal pure returns (bytes memory) {
    	// I have no idea what this means, i just ripped it off from
    	// https://arbiscan.io/address/0xac40e69e4808e28b59f619d353bb7fb83ad7cc87#readContract
        return hex"000301001505000000000000000000000000000186a000000064";
    }

    /*«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-*/
    /*                    LAYERZERO FUNCTIONS                     */
    /*-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»*/

    /// @dev Returns the LayerZero target EID.
    function _lzTargetEid() internal view returns (uint32) {
        if (block.chainid == _CHAIN_ID_ETHEREUM) return _LZ_EID_ARBITRUM;
        if (block.chainid == _CHAIN_ID_ARBITRUM) return _LZ_EID_ETHEREUM;
        if (block.chainid == _CHAIN_ID_SEPOLIA) return _LZ_EID_ARBITRUM_SEPOLIA;
        if (block.chainid == _CHAIN_ID_ARBITRUM_SEPOLIA) return _LZ_EID_ARBITRUM;
        revert UnsupportedChainId();
    }

    function _lzReadChannel() internal view returns (uint32) {
        if (block.chainid == _CHAIN_ID_ARBITRUM) return 4294967295;
        revert UnsupportedChainId();
    }

    /// @dev Returns the LayerZero endpoint.
    function _lzEndpoint() internal view returns (address) {
        if (block.chainid == _CHAIN_ID_ETHEREUM) return _LZ_ENDPOINT;
        if (block.chainid == _CHAIN_ID_ARBITRUM) return _LZ_ENDPOINT;
        if (block.chainid == _CHAIN_ID_SEPOLIA) return _LZ_TESTNET_ENDPOINT;
        if (block.chainid == _CHAIN_ID_ARBITRUM_SEPOLIA) return _LZ_TESTNET_ENDPOINT;
        revert UnsupportedChainId();
    }

    receive() external payable {}
}