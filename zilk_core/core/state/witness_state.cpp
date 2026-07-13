// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
#include "witness_state.hpp"

#include <intx/intx.hpp>
#include <zilk_core/core/rlp/decode.hpp>
// mpt_walk.hpp pulls in mpt.hpp (keccak_bytes / keccak_bytes32) with its
// include-order prerequisites satisfied.
#include <zilk_core/core/trie_zz/mpt_walk.hpp>  // mpt_get

namespace silkworm {

namespace {

// Decodes a canonical RLP account leaf value:
//   list[ nonce: u64 BE, balance: u256 BE, storage_root: b32, code_hash: b32 ]
std::optional<Account> decode_rlp_account(ByteView rlp_view) {
    const auto list_header = rlp::decode_header(rlp_view);
    if (!list_header || !list_header->list ||
        list_header->payload_length > rlp_view.size()) {
        return std::nullopt;
    }

    // Reads one RLP string of at most `max_len` bytes into the *last* bytes
    // of `out` (big-endian scalar convention), zero-padding the front.
    const auto read_scalar = [&rlp_view](size_t max_len, uint8_t* out) -> bool {
        const auto h = rlp::decode_header(rlp_view);
        if (!h || h->list || h->payload_length > max_len ||
            h->payload_length > rlp_view.size()) {
            return false;
        }
        std::memset(out, 0, max_len);
        std::memcpy(out + (max_len - h->payload_length), rlp_view.data(),
                    h->payload_length);
        rlp_view.remove_prefix(h->payload_length);
        return true;
    };

    uint8_t nonce_be[8];
    uint8_t balance_be[32];
    Account account;
    if (!read_scalar(8, nonce_be) || !read_scalar(32, balance_be) ||
        !read_scalar(32, account.storage_root_.bytes) ||
        !read_scalar(32, account.code_hash.bytes)) {
        return std::nullopt;
    }
    for (size_t i = 0; i < 8; ++i) {
        account.nonce = (account.nonce << 8) | nonce_be[i];
    }
    account.balance = intx::be::load<intx::uint256>(balance_be);
    return account;
}

}  // namespace

std::optional<Account> WitnessState::read_account(const evmc::address& address) const noexcept {
    if (account_checked_.contains(address)) {
        return InMemoryState::read_account(address);
    }
    // In-block writes (create/modify/delete) make the base maps authoritative
    // even if the address was never faulted in (defensive: normal execution
    // reads before writing, but don't rely on it).
    for (const auto& [_, changes] : account_changes_) {
        if (changes.contains(address)) {
            account_checked_.insert(address);
            return InMemoryState::read_account(address);
        }
    }
    account_checked_.insert(address);
    return fault_in_account(address);
}

std::optional<Account> WitnessState::fault_in_account(const evmc::address& address) const noexcept {
    Bytes leaf_value;
    const bytes32 hashed_key = keccak_bytes(ByteView{address.bytes, sizeof(address.bytes)});
    if (mpt_get(node_store_, pre_state_root_, hashed_key, leaf_value) !=
        mpt::WalkResult::Found) {
        // ProvenAbsent, or MissingNode (incomplete witness — treated as
        // absent; the post-state root check rejects the block if this lie
        // ever mattered).
        return std::nullopt;
    }
    std::optional<Account> account = decode_rlp_account(leaf_value);
    if (!account) {
        return std::nullopt;
    }
    const_cast<WitnessState*>(this)->accounts_[address] = *account;
    return account;
}

evmc::bytes32 WitnessState::read_storage(const evmc::address& address,
                                         const evmc::bytes32& location) const noexcept {
    FlatHashSet<evmc::bytes32>& checked = storage_checked_[address];
    if (checked.contains(location)) {
        return InMemoryState::read_storage(address, location);
    }
    // A slot written this block is authoritative in the base maps — note the
    // base *erases* zero-valued slots, so presence in storage_changes_ (not
    // storage_) is the only reliable "written this block" signal.
    for (const auto& [_, changes] : storage_changes_) {
        const auto it = changes.find(address);
        if (it != changes.end() && it->second.contains(location)) {
            checked.insert(location);
            return InMemoryState::read_storage(address, location);
        }
    }
    checked.insert(location);

    // Resolve the account's storage root (faulting the account in if needed).
    const std::optional<Account> account = read_account(address);
    if (!account) {
        return {};
    }

    Bytes leaf_value;
    if (mpt_get(node_store_, account->storage_root_, keccak_bytes32(location), leaf_value) !=
        mpt::WalkResult::Found) {
        return {};
    }
    // Storage leaf value: RLP string of the zeroless big-endian word.
    ByteView view{leaf_value};
    const auto h = rlp::decode_header(view);
    if (!h || h->list || h->payload_length > 32 || h->payload_length > view.size()) {
        return {};
    }
    evmc::bytes32 value{};
    std::memcpy(value.bytes + (32 - h->payload_length), view.data(), h->payload_length);
    if (!is_zero(value)) {
        const_cast<WitnessState*>(this)->storage_[address][location] = value;
    }
    return value;
}

}  // namespace silkworm
