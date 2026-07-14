// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Point lookup over a NodeStore-backed Merkle Patricia Trie.
//
// GridMPT only performs update-based root recomputation; stateless
// validation against the canonical witness (raw node preimages) additionally
// needs `get`: resolve a hashed key from a state/storage root through the
// node preimages at execution time. Keys are always keccak256 outputs
// (64 nibbles), which is what account and storage tries use.
//
// Absence semantics matter for statelessness:
//   Found        — a leaf with exactly this key exists; `value_out` is set.
//   ProvenAbsent — the available nodes prove no such key exists
//                  (path divergence / empty branch slot / empty root).
//   MissingNode  — the path runs into a node the witness does not contain.
//                  Callers treat this as "absent" and rely on the final
//                  state-root check to reject blocks with incomplete
//                  witnesses — never abort.

#pragma once

#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>

#include "node_store_i.hpp"
#include "flat_store.hpp"  // fast_decode_header
#include "rlp_sw.hpp"      // decode_branch / decode_ext_or_leaf / nibbles64


namespace silkworm::mpt {

enum class WalkResult : uint8_t {
    Found,
    ProvenAbsent,
    MissingNode,
};

// Resolves `hashed_key` (a 32-byte keccak output → 64 nibbles) from `root`.
// On `Found`, copies the leaf value payload into `value_out` (copied because
// embedded nodes are decoded into stack-local buffers during the walk).
inline WalkResult mpt_get(const NodeStore& store, const bytes32& root,
                          const bytes32& hashed_key, Bytes& value_out) {
    if (root == kEmptyRoot || root == bytes32{}) {
        return WalkResult::ProvenAbsent;
    }

    const nibbles64 key = nibbles64::from_bytes32(hashed_key);
    uint8_t pos = 0;  // consumed key nibbles

    // Current node RLP: either a view into the store/input (hash-referenced)
    // or a copy of an embedded (<32-byte) node in `embedded_buf`.
    uint8_t embedded_buf[33];
    ByteView node_rlp;
    {
        auto rlp = store.get_rlp(root);
        if (!rlp) return WalkResult::MissingNode;
        node_rlp = *rlp;
    }

    while (true) {
        // Strip the node's outer list header. Use the size-safe decoder:
        // fast_decode_header requires >= 8 bytes, but legitimate hash-
        // referenced root nodes can be tiny (e.g. a 3-byte single-slot
        // storage-trie leaf).
        ByteView payload = node_rlp;
        const auto hdr = rlp::decode_header(payload);
        if (!hdr || !hdr->list || hdr->payload_length > payload.size()) [[unlikely]] {
            // Malformed node — treat as unusable witness data.
            return WalkResult::MissingNode;
        }
        payload = payload.substr(0, hdr->payload_length);

        bool is_leaf = false;
        std::array<uint8_t, 64> path{};
        uint8_t plen = 0;
        ByteView second;

        if (decode_ext_or_leaf(payload, is_leaf, path, plen, second)) {
            if (is_leaf) {
                // Leaf: remaining key must match the leaf path exactly.
                if (plen != 64 - pos ||
                    std::memcmp(path.data(), key.nib.data() + pos, plen) != 0) {
                    return WalkResult::ProvenAbsent;
                }
                value_out.assign(second.data(), second.size());
                return WalkResult::Found;
            }
            // Extension: its path must be a prefix of the remaining key.
            if (plen > 64 - pos ||
                std::memcmp(path.data(), key.nib.data() + pos, plen) != 0) {
                return WalkResult::ProvenAbsent;
            }
            pos += plen;
            if (second.size() == 32) {
                // Hash reference.
                bytes32 child_hash;
                std::memcpy(child_hash.bytes, second.data(), 32);
                auto rlp = store.get_rlp(child_hash);
                if (!rlp) return WalkResult::MissingNode;
                node_rlp = *rlp;
            } else {
                // Embedded child: full RLP, decode from a stable local copy.
                // Embedded nodes are < 32 bytes by MPT definition; anything
                // larger is malformed — never copy past the buffer.
                if (second.size() > sizeof(embedded_buf)) [[unlikely]] {
                    return WalkResult::MissingNode;
                }
                // memmove: when the current node is itself embedded, `second`
                // points into embedded_buf and the copy overlaps.
                std::memmove(embedded_buf, second.data(), second.size());
                node_rlp = ByteView{embedded_buf, second.size()};
            }
            continue;
        }

        // Not a 2-item node — must be a branch.
        BranchNode branch;
        if (!decode_branch(payload, branch)) [[unlikely]] {
            return WalkResult::MissingNode;
        }
        if (pos == 64) {
            // Keys are fixed-length keccak outputs, so values never terminate
            // at a branch in these tries; defensive handling only.
            if (branch.value.empty()) return WalkResult::ProvenAbsent;
            value_out.assign(branch.value.data(), branch.value.size());
            return WalkResult::Found;
        }
        const uint8_t slot = key.nib[pos++];
        if (!(branch.mask & (1u << slot))) {
            return WalkResult::ProvenAbsent;
        }
        const uint8_t child_len = branch.child_len[slot];
        if (child_len == 32) {
            auto rlp = store.get_rlp(branch.child[slot]);
            if (!rlp) return WalkResult::MissingNode;
            node_rlp = *rlp;
        } else if (child_len > 0 && child_len <= sizeof(embedded_buf)) {
            // Embedded child: decode_branch kept the full RLP (header byte
            // included) in child[slot].bytes (a stack copy — no overlap).
            std::memcpy(embedded_buf, branch.child[slot].bytes, child_len);
            node_rlp = ByteView{embedded_buf, child_len};
        } else [[unlikely]] {
            return WalkResult::MissingNode;
        }
    }
}

}  // namespace silkworm::mpt
