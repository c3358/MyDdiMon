// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

#pragma once

#undef _HAS_EXCEPTIONS
#define _HAS_EXCEPTIONS 0
#define NTSTRSAFE_NO_CB_FUNCTIONS

#include <fltKernel.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <array>
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "../HyperPlatform/HyperPlatform/ept.h"
#include "shadow_hook.h"

NTSTATUS DdimonInitialization(_In_ SharedShadowHookData* shared_sh_data);
void DdimonTermination();
