// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// WitnessState — read-through state over the canonical stateless witness.
//
// The canonical witness (EIP-8025 / stateless_ssz.py `ExecutionWitness`)
// carries raw MPT node preimages keyed by keccak256, so an address-keyed
// pre-state cannot be materialized eagerly (keccak keys are not invertible).
// Instead, reads are resolved lazily: at execution time the address/slot is
// known, so it is hashed and walked from the pre-state root through the node
// store, and the result is cached in the underlying InMemoryState so that
// all downstream machinery (change tracking, post-state delta rebuild)
// behaves exactly as with a materialized pre-state.
//
// Missing witness nodes are treated as "absent" — execution then diverges
// and the recomputed post-state root fails the block, which is the correct
// stateless failure mode (never abort).

#pragma once

#include <zilk_core/core/state/in_memory_state.hpp>
#include <zilk_core/core/trie_zz/node_store_i.hpp>

namespace silkworm {

class WitnessState final : public InMemoryState {
  public:
    WitnessState(const mpt::NodeStore& node_store, const evmc::bytes32& pre_state_root)
        : node_store_{node_store}, pre_state_root_{pre_state_root} {}

    std::optional<Account> read_account(const evmc::address& address) const noexcept override;

    evmc::bytes32 read_storage(const evmc::address& address,
                               const evmc::bytes32& location) const noexcept override;


  private:
    // Fault the account for `address` in from the witness trie if this is the
    // first time it is seen. Returns the account if it exists (cached or
    // proven present).
    std::optional<Account> fault_in_account(const evmc::address& address) const noexcept;

    const mpt::NodeStore& node_store_;
    evmc::bytes32 pre_state_root_;

    // Keys already resolved against the witness (present or absent): the
    // underlying InMemoryState is authoritative for them from then on
    // (including subsequent in-block writes/deletes). Mutable: reads are
    // const, caching is an implementation detail.
    mutable FlatHashSet<evmc::address> account_checked_;
    mutable FlatHashMap<evmc::address, FlatHashSet<evmc::bytes32>> storage_checked_;
};

}  // namespace silkworm
