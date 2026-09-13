// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <cstdint>
#include <string>

#ifdef __cplusplus
extern "C" {
#endif

// Run one fixture envelope. The input format (EEST JSON or MFBD) is picked from
// the leading 4-byte magic, so no out-of-band tag is needed.
// Returns a ctest-compatible exit code:
// 0 = success (block's gas_used is logged via sys_println)
// 1 = StateTransition::kRunFailure
// 2 = StateTransition::kRunSkipped
uint64_t sample_run_wrapped(std::string envelope_str);

#ifdef __cplusplus
}
#endif
