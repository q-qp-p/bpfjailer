// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// Linux 7.4 (16959c469f23, "lsm: expose mount idmaps to inode hooks") put a
// `const struct mnt_idmap *` in front of the inode_create, inode_link,
// inode_symlink, inode_mkdir, inode_mknod and inode_permission hooks, so on
// those kernels every argument, and the LSM verdict after the last one, sits
// one ctx slot later than BPF_PROG would read it.
union security_list_options___bpfj_idmap {
  int (*inode_link)(
      const struct mnt_idmap* idmap,
      struct dentry* old_dentry,
      struct inode* dir,
      struct dentry* new_dentry);
};

#define BPFJ_LSM_INODE_HAS_IDMAP() \
  bpf_core_type_matches(union security_list_options___bpfj_idmap)

// The verifier only accepts a ctx load at a constant instruction offset, and
// asm keeps clang from merging the two layouts' loads into one load from a
// selected address.
#define ___bpfj_lsm_inode_arg(slot)                      \
  ({                                                     \
    unsigned long long ___v;                             \
    asm volatile("%[v] = *(u64 *)(%[c] + %[off])"        \
                 : [v] "=r"(___v)                        \
                 : [c] "r"(ctx), [off] "i"((slot) * 8)); \
    (void*)___v;                                         \
  })

#define ___bpfj_lsm_inode_args0(s) ctx
#define ___bpfj_lsm_inode_args1(s, x) \
  ___bpfj_lsm_inode_args0(s), ___bpfj_lsm_inode_arg((s) + 0)
#define ___bpfj_lsm_inode_args2(s, x, args...) \
  ___bpfj_lsm_inode_args1(s, args), ___bpfj_lsm_inode_arg((s) + 1)
#define ___bpfj_lsm_inode_args3(s, x, args...) \
  ___bpfj_lsm_inode_args2(s, args), ___bpfj_lsm_inode_arg((s) + 2)
#define ___bpfj_lsm_inode_args4(s, x, args...) \
  ___bpfj_lsm_inode_args3(s, args), ___bpfj_lsm_inode_arg((s) + 3)
#define ___bpfj_lsm_inode_args5(s, x, args...) \
  ___bpfj_lsm_inode_args4(s, args), ___bpfj_lsm_inode_arg((s) + 4)
#define ___bpfj_lsm_inode_args(s, args...) \
  ___bpf_apply(___bpfj_lsm_inode_args, ___bpf_narg(args))(s, args)

// BPF_PROG for the hooks above, declared with the pre-7.4 arguments (no
// idmap) and the trailing verdict; it loads them from whichever slots the
// running kernel uses.
// clang-format off
#define BPFJ_LSM_INODE_PROG(name, args...)                              \
  name(unsigned long long* ctx);                                        \
  static __always_inline typeof(name(0))                                \
      ____##name(unsigned long long* ctx, ##args);                      \
  typeof(name(0)) name(unsigned long long* ctx) {                       \
    _Pragma("GCC diagnostic push")                                      \
    _Pragma("GCC diagnostic ignored \"-Wint-conversion\"")              \
    if (BPFJ_LSM_INODE_HAS_IDMAP())                                     \
      return ____##name(___bpfj_lsm_inode_args(1, args));               \
    return ____##name(___bpfj_lsm_inode_args(0, args));                 \
    _Pragma("GCC diagnostic pop")                                       \
  }                                                                     \
  static __always_inline typeof(name(0))                                \
      ____##name(unsigned long long* ctx, ##args)
// clang-format on
