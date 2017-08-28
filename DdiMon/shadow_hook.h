// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

#pragma once

#undef _HAS_EXCEPTIONS
#define _HAS_EXCEPTIONS 0
#define NTSTRSAFE_NO_CB_FUNCTIONS

#include <fltKernel.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <vector>
#include <memory>
#include <algorithm>
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "../HyperPlatform/HyperPlatform/ept.h"
#include "capstone.h"

struct Page {// Copy of a page seen by a guest as a result of memory shadowing
    UCHAR* page;  // A page aligned copy of a page
    Page();
    ~Page();
};

struct HookInformation {  // Contains a single steal thook information
    void* patch_address;  // 要被hook函数的地址。
    void* HookFunction;   // 自己写的hook 函数的地址。

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
    HookInformation* last_hook_info;  // Remember which hook hit the last
};

// A structure reflects inline hook code.
#include <pshpack1.h>
#if defined(_AMD64_)
struct TrampolineCode {
    UCHAR nop; //这个是干啥用的？内存对齐？设置断点供调试使用？
    UCHAR jmp[6];
    void* address;
};
static_assert(sizeof(TrampolineCode) == 15, "Size check");
#else
struct TrampolineCode {
    UCHAR nop;//这个是干啥用的？内存对齐？设置断点供调试使用？
    UCHAR push;
    void* address;
    UCHAR ret;
};
static_assert(sizeof(TrampolineCode) == 7, "Size check");
#endif
#include <poppack.h>

struct ShadowHookTarget {
  UNICODE_STRING target_name;  // 注释见别处。
  void* hook_handler;          // 自己写的处理函数。
  void* fake_caller;           // 中间的临时转换函数，调用原始函数。
};

ShadowHookData* ShAllocateShadowHookData();
void ShFreeShadowHookData(_In_ ShadowHookData* sh_data);
SharedShadowHookData* ShAllocateSharedShaowHookData();
void ShFreeSharedShadowHookData(_In_ SharedShadowHookData* shared_sh_data);
NTSTATUS ShEnableHooks();
NTSTATUS ShDisableHooks();
void ShEnablePageShadowing(_In_ EptData* ept_data, _In_ const SharedShadowHookData* shared_sh_data);
void ShVmCallDisablePageShadowing(_In_ EptData* ept_data, _In_ const SharedShadowHookData* shared_sh_data);
bool ShInstallHook(_In_ SharedShadowHookData* shared_sh_data, _In_ void* address, _In_ ShadowHookTarget* target);
bool ShHandleBreakpoint(_In_ ShadowHookData* sh_data, _In_ const SharedShadowHookData* shared_sh_data, _In_ void* guest_ip);
void ShHandleMonitorTrapFlag(_In_ ShadowHookData* sh_data, _In_ const SharedShadowHookData* shared_sh_data, _In_ EptData* ept_data);
void ShHandleEptViolation(_In_ ShadowHookData* sh_data, _In_ const SharedShadowHookData* shared_sh_data, _In_ EptData* ept_data, _In_ void* fault_va);
