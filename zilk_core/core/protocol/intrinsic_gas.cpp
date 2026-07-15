// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "intrinsic_gas.hpp"

#include <algorithm>

#include "param.hpp"

namespace silkworm::protocol {

namespace {

// Amsterdam recipient/value regular-gas component, shared by the intrinsic
// cost and the calldata floor anchor (EELS calculate_intrinsic_cost).
uint64_t amsterdam_recipient_gas(const UnsignedTransaction& txn,
                                 const std::optional<evmc::address>& sender) noexcept {
    namespace ams = fee::amsterdam;
    const bool contract_creation{!txn.to};
    if (contract_creation) {
        uint64_t g{ams::kCreateAccess};
        if (txn.value > 0) g += ams::kTransferLogCost;
        return g;
    }
    if (sender && *txn.to == *sender) return 0;  // self-transfer
    uint64_t g{ams::kColdAccountAccess};
    if (txn.value > 0) g += ams::kTransferLogCost + ams::kTxValueCost;
    return g;
}

// Amsterdam access-list floor tokens (EIP-7976): 80 per address + 128 per key.
uint64_t amsterdam_access_list_floor_tokens(const UnsignedTransaction& txn) noexcept {
    namespace ams = fee::amsterdam;
    uint64_t tokens{0};
    for (const AccessListEntry& e : txn.access_list) {
        tokens += ams::kAccessListAddressFloorTokens;
        tokens += e.storage_keys.size() * ams::kAccessListStorageKeyFloorTokens;
    }
    return tokens;
}

// Amsterdam intrinsic regular gas (EELS calculate_intrinsic_cost .regular).
intx::uint128 amsterdam_intrinsic_gas(const UnsignedTransaction& txn,
                                      const std::optional<evmc::address>& sender) noexcept {
    namespace ams = fee::amsterdam;
    intx::uint128 gas{ams::kTxBase};
    gas += amsterdam_recipient_gas(txn, sender);

    const bool contract_creation{!txn.to};
    if (contract_creation) {
        gas += num_words(txn.data.size()) * fee::kInitCodeWordCost;
    }

    const uint64_t data_len{txn.data.size()};
    const uint64_t zero_bytes{static_cast<uint64_t>(std::ranges::count(txn.data, 0))};
    const uint64_t tokens{zero_bytes + (data_len - zero_bytes) * 4};
    gas += intx::uint128{tokens} * ams::kDataTokenStandard;

    // EIP-7981: access list entries priced at the cold access costs, plus
    // floor-token data cost for the access list bytes.
    intx::uint128 al_cost{0};
    for (const AccessListEntry& e : txn.access_list) {
        al_cost += ams::kColdAccountAccess;
        al_cost += intx::uint128{e.storage_keys.size()} * ams::kColdStorageAccess;
    }
    al_cost += intx::uint128{amsterdam_access_list_floor_tokens(txn)} * ams::kDataTokenFloor;
    gas += al_cost;

    gas += intx::uint128{txn.authorizations.size()} * ams::kRegularPerAuthBase;
    return gas;
}

}  // namespace

intx::uint128 intrinsic_gas(const UnsignedTransaction& txn, const evmc_revision rev,
                            const std::optional<evmc::address>& sender) noexcept {
    if (rev >= EVMC_AMSTERDAM) {
        return amsterdam_intrinsic_gas(txn, sender);
    }
    intx::uint128 gas{fee::kGTransaction};

    const bool contract_creation{!txn.to};
    if (contract_creation && rev >= EVMC_HOMESTEAD) {
        gas += fee::kGTxCreate;
    }

    // EIP-2930: Optional access lists
    gas += intx::uint128{txn.access_list.size()} * fee::kAccessListAddressCost;
    intx::uint128 total_num_of_storage_keys{0};
    for (const AccessListEntry& e : txn.access_list) {
        total_num_of_storage_keys += e.storage_keys.size();
    }
    gas += total_num_of_storage_keys * fee::kAccessListStorageKeyCost;

    // EIP-7702 Set EOA account code
    gas += txn.authorizations.size() * fee::kPerEmptyAccountCost;

    const uint64_t data_len{txn.data.size()};
    if (data_len == 0) {
        return gas;
    }

    const intx::uint128 non_zero_bytes{std::ranges::count_if(txn.data, [](uint8_t c) { return c != 0; })};
    const intx::uint128 non_zero_gas{rev >= EVMC_ISTANBUL ? fee::kGTxDataNonZeroIstanbul : fee::kGTxDataNonZeroFrontier};
    gas += non_zero_bytes * non_zero_gas;
    const intx::uint128 zero_bytes{data_len - non_zero_bytes};
    gas += zero_bytes * fee::kGTxDataZero;

    // EIP-3860: Limit and meter initcode
    if (contract_creation && rev >= EVMC_SHANGHAI) {
        gas += num_words(data_len) * fee::kInitCodeWordCost;
    }

    return gas;
}

// EIP-7623 (Prague..Osaka) / EIP-7976 (Amsterdam): calldata floor cost.
uint64_t floor_cost(const UnsignedTransaction& txn, const evmc_revision rev,
                    const std::optional<evmc::address>& sender) noexcept {
    if (rev >= EVMC_AMSTERDAM) {
        namespace ams = fee::amsterdam;
        // Uniform calldata tokens (every byte counts 4) + access-list floor
        // tokens, at 16 gas per token, anchored on the intrinsic base.
        const uint64_t floor_tokens =
            txn.data.size() * ams::kDataTokenStandard + amsterdam_access_list_floor_tokens(txn);
        return floor_tokens * ams::kDataTokenFloor + ams::kTxBase +
               amsterdam_recipient_gas(txn, sender);
    }
    const uint64_t zero_bytes = static_cast<uint64_t>(std::ranges::count(txn.data, 0));
    const uint64_t non_zero_bytes{txn.data.size() - zero_bytes};
    return fee::kGTransaction + (zero_bytes + non_zero_bytes * 4) * fee::kTotalCostFloorPerToken;
}

}  // namespace silkworm::protocol
