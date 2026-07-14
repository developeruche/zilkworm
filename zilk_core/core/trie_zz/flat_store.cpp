// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
#include "flat_store.hpp"

#include <evmone_precompiles/keccak.hpp>  // ethash_keccak256 (mpt.hpp depends on it)
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/rlp/decode.hpp>
#include <zilk_core/print.hpp>

#include "mpt.hpp"  // keccak_bytes

namespace silkworm::mpt {

[[gnu::always_inline]] inline DecodingResult decode8(ByteView& from, uint64_t& to) noexcept {
    if (from.size() < 33) [[unlikely]] {
        return std::unexpected{DecodingError::kInputTooShort};
    }
    if (from[0] != 0xA0) [[unlikely]] {
        return std::unexpected{DecodingError::kUnexpectedLength};
    }
    from.remove_prefix(1);

    std::memcpy(&to, from.data(), 8);
    from.remove_prefix(32);
    return {};
}

// Function to populate a FlatNodeStore from the given trie_rlp structure
// Layout is [rlp{32-byte hash, bytes}, rlp{32-byte hash, bytes}, ...]
void FlatNodeStore::populate_from_rlp(ByteView trie_rlp) {
    auto trie_header{fast_decode_header(trie_rlp)};
    if (!trie_header.list) {
        sys_println("Invalid trie_header in populate_from_rlp");
        return;
    }

    ByteView trie_view = trie_rlp.substr(0, trie_header.payload_length);

    // Clear old entries (keeps bucket capacity), higher load factor = fewer buckets = fewer allocs
    storage_.clear();
    collisions_.clear();
    storage_.max_load_factor(4.0f);
    storage_.reserve(trie_header.payload_length / 70);

    while (!trie_view.empty()) {
        uint64_t node_hash;
        const uint8_t* hash_start = trie_view.data() + 1;  // skip 0xA0, points to 32-byte hash

        if (DecodingResult res = decode8(trie_view, node_hash); !res) [[unlikely]] {
            sys_println("Failed to decode node_hash from trie_view");
            break;
        }

        // Record start of full node RLP (before stripping the list header).
        const uint8_t* node_rlp_start = trie_view.data();  // = hash_start + 32
        auto hdr = fast_decode_header(trie_view);           // advances past list header
        uint32_t header_size = static_cast<uint32_t>(trie_view.data() - node_rlp_start);
        // payload_off: offset from hash_start to the start of the full node RLP.
        uint32_t payload_off = static_cast<uint32_t>(node_rlp_start - hash_start);  // == 32
        // payload_len: length of the FULL node RLP (list header + list payload).
        uint32_t payload_len = header_size + static_cast<uint32_t>(hdr.payload_length);
        uint64_t off_len = (static_cast<uint64_t>(payload_off) << 32) | payload_len;
        trie_view.remove_prefix(hdr.payload_length);

        auto [it, inserted] = storage_.emplace(node_hash, NodeRef{hash_start, off_len});
        if (!inserted) [[unlikely]] {
            if (it->second.hash_ptr != nullptr) {
                collisions_.push_back(it->second.hash_ptr);
                it->second = {nullptr, 0};
            }
            collisions_.push_back(hash_start);
        }
    }
}

// Populate from raw node preimages (canonical stateless witness format):
// keccak each node, own [hash | rlp-string(node)] so pointers stay valid and
// the collision fallback (fast_rlp_view at hash+32) decodes the same way it
// does for packed-format entries.
void FlatNodeStore::populate_from_preimages(std::span<const ByteView> nodes) {
    storage_.max_load_factor(4.0f);
    storage_.reserve(storage_.size() + nodes.size());

    for (const ByteView& node : nodes) {
        if (node.empty()) continue;

        const bytes32 hash = keccak_bytes(node);

        // Entry: hash(32) || RLP string header || node bytes.
        Bytes& entry = owned_.emplace_back();
        entry.reserve(32 + 3 + node.size());
        entry.append(hash.bytes, 32);
        const size_t n = node.size();
        if (n <= 55) {
            entry.push_back(static_cast<uint8_t>(0x80 + n));
        } else if (n <= 0xFF) {
            entry.push_back(0xB8);
            entry.push_back(static_cast<uint8_t>(n));
        } else {
            entry.push_back(0xB9);
            entry.push_back(static_cast<uint8_t>(n >> 8));
            entry.push_back(static_cast<uint8_t>(n & 0xFF));
        }
        const uint32_t payload_off = static_cast<uint32_t>(entry.size());  // node bytes start
        entry.append(node.data(), node.size());

        const uint8_t* hash_start = entry.data();
        const uint64_t off_len =
            (static_cast<uint64_t>(payload_off) << 32) | static_cast<uint32_t>(n);

        auto [it, inserted] = storage_.emplace(key8(hash), NodeRef{hash_start, off_len});
        if (!inserted) [[unlikely]] {
            if (it->second.hash_ptr != nullptr) {
                // First collision on this 8-byte prefix: demote the existing
                // entry to the linear-scan list. Skip exact duplicates.
                if (std::memcmp(it->second.hash_ptr, hash.bytes, 32) == 0) {
                    owned_.pop_back();
                    continue;
                }
                collisions_.push_back(it->second.hash_ptr);
                it->second = {nullptr, 0};
            }
            collisions_.push_back(hash_start);
        }
    }
}

}  // namespace silkworm::mpt
