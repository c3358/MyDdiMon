// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/// @file
/// @brief Declares interfaces to DdiMon functions.

#ifndef DDIMON_DDI_MON_H_
#define DDIMON_DDI_MON_H_

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

#include <array>

#include "shadow_hook.h"

union PoolTag {// A helper type for parsing a PoolTag value
    ULONG value;
    UCHAR chars[4];
};

// A callback type for EnumExportedSymbols()
using EnumExportedSymbolsCallbackType = bool(*)(ULONG index, ULONG_PTR base_address, PIMAGE_EXPORT_DIRECTORY directory, ULONG_PTR directory_base, ULONG_PTR directory_end, void* context);

enum SystemInformationClass {// For SystemProcessInformation
    kSystemProcessInformation = 5,
};

struct SystemProcessInformation {// For NtQuerySystemInformation
    ULONG next_entry_offset;
    ULONG number_of_threads;
    LARGE_INTEGER working_set_private_size;
    ULONG hard_fault_count;
    ULONG number_of_threads_high_watermark;
    ULONG64 cycle_time;
    LARGE_INTEGER create_time;
    LARGE_INTEGER user_time;
    LARGE_INTEGER kernel_time;
    UNICODE_STRING image_name;
    // omitted. see ole32!_SYSTEM_PROCESS_INFORMATION
};

struct SharedShadowHookData;

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C NTSTATUS DdimonInitialization(_In_ SharedShadowHookData* shared_sh_data);
_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C void DdimonTermination();

#endif
