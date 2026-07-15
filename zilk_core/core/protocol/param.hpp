// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>

#include <evmc/evmc.hpp>
#include <zilk_core/core/common/base.hpp>

namespace silkworm::protocol {
// Gas fee schedule—see Appendix G of the Yellow Paper
// https://ethereum.github.io/yellowpaper/paper.pdf
namespace fee {

    inline constexpr uint64_t kAccessListStorageKeyCost{1'900};  // EIP-2930
    inline constexpr uint64_t kAccessListAddressCost{2'400};     // EIP-2930

    inline constexpr uint64_t kGCodeDeposit{200};

    inline constexpr uint64_t kGTransaction{21'000};
    inline constexpr uint64_t kGTxCreate{32'000};
    inline constexpr uint64_t kGTxDataZero{4};
    inline constexpr uint64_t kGTxDataNonZeroFrontier{68};
    inline constexpr uint64_t kGTxDataNonZeroIstanbul{16};  // EIP-2028

    inline constexpr uint64_t kInitCodeWordCost{2};  // EIP-3860

    inline constexpr uint64_t kTotalCostFloorPerToken{10};  // EIP-7623: Increase calldata cost
    inline constexpr uint64_t kPerEmptyAccountCost{25000};  // EIP-7702 Set EOA account code

    // ── Amsterdam (EIP-2780/7708/7976/7981/8037/8038) ─────────────────────
    namespace amsterdam {
        inline constexpr uint64_t kTxBase{12'000};                // EIP-2780
        inline constexpr uint64_t kTxValueCost{4'244};            // EIP-2780
        inline constexpr uint64_t kTransferLogCost{1'756};        // EIP-7708
        inline constexpr uint64_t kColdAccountAccess{3'000};      // EIP-8038
        inline constexpr uint64_t kColdStorageAccess{3'000};      // EIP-8038
        inline constexpr uint64_t kWarmAccess{100};
        inline constexpr uint64_t kAccountWrite{8'000};
        inline constexpr uint64_t kStorageWrite{10'000};
        inline constexpr uint64_t kCreateAccess{kAccountWrite + kColdStorageAccess};  // 11'000
        inline constexpr uint64_t kDataTokenStandard{4};
        inline constexpr uint64_t kDataTokenFloor{16};            // EIP-7976
        inline constexpr uint64_t kAccessListAddressFloorTokens{80};
        inline constexpr uint64_t kAccessListStorageKeyFloorTokens{128};
        // 101 * 16 + ecrecover 3000 + cold 3000 + 2 * warm 100 = 7'816
        inline constexpr uint64_t kRegularPerAuthBase{101 * kDataTokenFloor + 3'000 + kColdAccountAccess + 2 * kWarmAccess};
        // EIP-8037 state gas: bytes * 1530
        inline constexpr uint64_t kCostPerStateByte{1'530};
        inline constexpr uint64_t kStateGasNewAccount{120 * kCostPerStateByte};   // 183'600
        inline constexpr uint64_t kStateGasStorageSet{64 * kCostPerStateByte};    //  97'920
        inline constexpr uint64_t kStateGasAuthBase{23 * kCostPerStateByte};      //  35'190
        // EIP-7825 cap binds only the regular-gas dimension in Amsterdam.
        inline constexpr uint64_t kTxMaxGasLimit{16'777'216};
    }  // namespace amsterdam

}  // namespace fee

inline constexpr uint64_t kMinGasLimit{5000};
// https://github.com/ethereum/go-ethereum/blob/v1.13.4/params/protocol_params.go#L28
// EIP-1985: Sane limits for certain EVM parameters
inline constexpr uint64_t kMaxGasLimit{INT64_MAX};  // 2^63-1

inline constexpr size_t kMaxCodeSize{0x6000};                // EIP-170
inline constexpr size_t kMaxInitCodeSize{2 * kMaxCodeSize};  // EIP-3860

inline constexpr uint64_t kMaxExtraDataBytes{32};

inline constexpr uint64_t kBlockRewardFrontier{5 * kEther};
inline constexpr uint64_t kBlockRewardByzantium{3 * kEther};       // EIP-649
inline constexpr uint64_t kBlockRewardConstantinople{2 * kEther};  // EIP-1234

// EIP-3529: Reduction in refunds
inline constexpr uint64_t kMaxRefundQuotientFrontier{2};
inline constexpr uint64_t kMaxRefundQuotientLondon{5};

// EIP-1559: Fee market change for ETH 1.0 chain
inline constexpr uint64_t kInitialBaseFee{kGiga};
inline constexpr uint64_t kBaseFeeMaxChangeDenominator{8};
inline constexpr uint64_t kElasticityMultiplier{2};

// EIP-4844: Shard Blob Transactions
inline constexpr uint8_t kBlobCommitmentVersionKzg{1};
inline constexpr uint64_t kGasPerBlob{1u << 17};
inline constexpr uint64_t kMinBlobGasPrice{1};

using namespace evmc::literals;
inline constexpr uint64_t kSystemCallGasLimit{30'000'000};
inline constexpr evmc::address kSystemAddress{0xfffffffffffffffffffffffffffffffffffffffe_address};

// EIP-6110: Supply validator deposits on chain
inline constexpr auto kDepositContractAddress{0x00000000219ab540356cbb839cbe05303d7705fa_address};

// Used in Bor
inline constexpr size_t kExtraSealSize{65};

}  // namespace silkworm::protocol
