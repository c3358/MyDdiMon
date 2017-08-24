// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/// @file
/// @brief Declares interfaces to shadow hook functions.

#ifndef DDIMON_SHADOW_HOOK_H_
#define DDIMON_SHADOW_HOOK_H_

#include <fltKernel.h>
#include <ntimage.h>

#define NTSTRSAFE_NO_CB_FUNCTIONS

#include <ntstrsafe.h>

#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "../HyperPlatform/HyperPlatform/ept.h"

#undef _HAS_EXCEPTIONS

#define _HAS_EXCEPTIONS 0

#include <vector>
#include <memory>
#include <algorithm>

#include "capstone.h"

struct Page {// Copy of a page seen by a guest as a result of memory shadowing
    UCHAR* page;  // A page aligned copy of a page
    Page();
    ~Page();
};

struct HookInformation {// Contains a single steal thook information
    void* patch_address;  // An address where a hook is installed
    void* handler;        // An address of the handler routine

                          // A copy of a pages where patch_address belongs to.
                          // shadow_page_base_for_rw is exposed to a guest for read and write operation against the page of patch_address, and shadow_page_base_for_exec is exposed for execution.
    std::shared_ptr<Page> shadow_page_base_for_rw;
    std::shared_ptr<Page> shadow_page_base_for_exec;

    // Physical address of the above two copied pages
    ULONG64 pa_base_for_rw;
    ULONG64 pa_base_for_exec;
};

struct SharedShadowHookData {// Data structure shared across all processors
    std::vector<std::unique_ptr<HookInformation>> hooks;  // Hold installed hooks
};

struct ShadowHookData {// Data structure for each processor
    const HookInformation* last_hook_info;  // Remember which hook hit the last
};

// A structure reflects inline hook code.
#include <pshpack1.h>
#if defined(_AMD64_)
struct TrampolineCode {
    UCHAR nop;
    UCHAR jmp[6];
    void* address;
};
static_assert(sizeof(TrampolineCode) == 15, "Size check");
#else
struct TrampolineCode {
    UCHAR nop;
    UCHAR push;
    void* address;
    UCHAR ret;
};
static_assert(sizeof(TrampolineCode) == 7, "Size check");
#endif
#include <poppack.h>

struct EptData;
struct ShadowHookData;
struct SharedShadowHookData;

struct ShadowHookTarget {// Expresses where to install hooks by a function name, and its handlers
  UNICODE_STRING target_name;  // An export name to hook
  void* handler;               // An address of a hook handler
  void* original_call;// An address of a trampoline code to call original function. Initialized by a successful call of ShInstallHook().
};

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C ShadowHookData* ShAllocateShadowHookData();
_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C void ShFreeShadowHookData(_In_ ShadowHookData* sh_data);
_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C SharedShadowHookData* ShAllocateSharedShaowHookData();
_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C void ShFreeSharedShadowHookData(_In_ SharedShadowHookData* shared_sh_data);
_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C NTSTATUS ShEnableHooks();
_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C NTSTATUS ShDisableHooks();
_IRQL_requires_min_(DISPATCH_LEVEL) void ShEnablePageShadowing(_In_ EptData* ept_data, _In_ const SharedShadowHookData* shared_sh_data);
_IRQL_requires_min_(DISPATCH_LEVEL) void ShVmCallDisablePageShadowing(_In_ EptData* ept_data, _In_ const SharedShadowHookData* shared_sh_data);
_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C bool ShInstallHook(_In_ SharedShadowHookData* shared_sh_data, _In_ void* address, _In_ ShadowHookTarget* target);
_IRQL_requires_min_(DISPATCH_LEVEL) bool ShHandleBreakpoint(_In_ ShadowHookData* sh_data, _In_ const SharedShadowHookData* shared_sh_data, _In_ void* guest_ip);
_IRQL_requires_min_(DISPATCH_LEVEL) void ShHandleMonitorTrapFlag(_In_ ShadowHookData* sh_data, _In_ const SharedShadowHookData* shared_sh_data, _In_ EptData* ept_data);
_IRQL_requires_min_(DISPATCH_LEVEL) void ShHandleEptViolation(
    _In_ ShadowHookData* sh_data,
    _In_ const SharedShadowHookData* shared_sh_data, _In_ EptData* ept_data,
    _In_ void* fault_va);

#endif
