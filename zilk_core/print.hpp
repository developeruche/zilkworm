// Copyright The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
#pragma once
#ifdef SP1
#include <sp1_syscalls.hpp>
#elif defined(OPENVM)
// openvm_syscalls.hpp is on the global include path of the OpenVM guest
// build. print_str is a phantom instruction: visible under the executor,
// a no-op in proofs.
#include <openvm_syscalls.hpp>

#include <cstring>
#include <string_view>
inline void sys_print(const char* msg) { openvm::print_str(msg, std::strlen(msg)); }
inline void sys_println(const char* msg) {
    sys_print(msg);
    openvm::print_str("\n", 1);
}
inline void sys_print(std::string_view msg) { openvm::print_str(msg.data(), msg.size()); }
inline void sys_println(std::string_view msg) {
    sys_print(msg);
    openvm::print_str("\n", 1);
}
[[noreturn]] inline void syscall_halt(uint8_t) {
    openvm::terminate_failure();
}
#elif defined(QEMU_DEBUG)
#include <semihosting.hpp>
#else
#include <iostream>
#include <string_view>
inline void sys_println(const char* msg) {
    std::cout << "stdout: " << msg << std::endl;
}
inline void sys_print(const char* msg) {
    std::cout << "stdout: " << msg;
}
inline void sys_println(std::string_view msg) {
    std::cout << "stdout: " << msg << std::endl;
}
inline void sys_print(std::string_view msg) {
    std::cout << "stdout: " << msg;
}

[[noreturn]] inline void syscall_halt(uint8_t exit_code) {
    std::exit(exit_code);
}

#endif
