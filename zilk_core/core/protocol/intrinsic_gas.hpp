// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <intx/intx.hpp>
#include <zilk_core/core/types/transaction.hpp>

namespace silkworm {

// Words in EVM are 32-bytes long
constexpr uint64_t num_words(uint64_t num_bytes) noexcept {
    return num_bytes / 32 + static_cast<uint64_t>(num_bytes % 32 != 0);
}

namespace protocol {

    // Returns the intrinsic gas of a transaction.
    // Refer to g0 in Section 6.2 "Execution" of the Yellow Paper
    // and EIP-3860 "Limit and meter initcode".
    // From Amsterdam (EIP-2780 et al.) the intrinsic cost depends on the
    // sender (self-transfers skip the recipient/value components), so the
    // recovered sender must be supplied for rev >= EVMC_AMSTERDAM.
    intx::uint128 intrinsic_gas(const UnsignedTransaction& txn, evmc_revision rev,
                                const std::optional<evmc::address>& sender = std::nullopt) noexcept;

    // Returns the floor cost (valid since Pectra).
    // Refer to: EIP-7623 (Prague..Osaka) and EIP-7976 (Amsterdam: floor token
    // cost 16, uniform calldata tokens, access-list floor tokens, anchored on
    // the intrinsic regular base instead of TX_BASE alone).
    uint64_t floor_cost(const UnsignedTransaction& txn, evmc_revision rev = EVMC_PRAGUE,
                        const std::optional<evmc::address>& sender = std::nullopt) noexcept;

}  // namespace protocol

}  // namespace silkworm
