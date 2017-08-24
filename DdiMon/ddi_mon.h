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

// A callback type for EnumExportedSymbols()
using EnumExportedSymbolsCallbackType = bool(*)(ULONG index, ULONG_PTR base_address, PIMAGE_EXPORT_DIRECTORY directory, ULONG_PTR directory_base, ULONG_PTR directory_end, void* context);

struct SharedShadowHookData;

EXTERN_C NTSTATUS DdimonInitialization(_In_ SharedShadowHookData* shared_sh_data);
EXTERN_C void DdimonTermination();

#endif
