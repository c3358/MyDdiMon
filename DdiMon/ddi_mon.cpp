// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

#include "ddi_mon.h"

template <typename T> static T DdimonpFindOrignal(T handler);


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS HookNtCreateFile(
    _Out_    PHANDLE            FileHandle,
    _In_     ACCESS_MASK        DesiredAccess,
    _In_     POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_    PIO_STATUS_BLOCK   IoStatusBlock,
    _In_opt_ PLARGE_INTEGER     AllocationSize,
    _In_     ULONG              FileAttributes,
    _In_     ULONG              ShareAccess,
    _In_     ULONG              CreateDisposition,
    _In_     ULONG              CreateOptions,
    _In_     PVOID              EaBuffer,
    _In_     ULONG              EaLength
)
{
    const auto original = DdimonpFindOrignal(HookNtCreateFile);
    const auto result = original(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
    auto return_addr = _ReturnAddress();
    void * p = UtilPcToFileHeader(return_addr);//这个地址当然是内核的基地址，经测试验证也是的。

    HYPERPLATFORM_LOG_INFO_SAFE("NtCreateFile is inside image:%p.", p);

    return result;
}


//上面是HOOK函数。
//////////////////////////////////////////////////////////////////////////////////////////////////
//下面是HOOK框架。


// Defines where to install shadow hooks and their handlers
//
// Because of simplified implementation of DdiMon, DdiMon is unable to handle any of following exports properly:
//  - already unmapped exports (eg, ones on the INIT section) because it no longer exists on memory
//  - exported data because setting 0xcc does not make any sense in this case
//  - functions does not comply x64 calling conventions, for example Zw* functions.
//    Because contents of stack do not hold expected values leading handlers to failure of parameter analysis that may result in bug check.
//
// Also the following care should be taken:
//  - Function parameters may be an user-address space pointer and not trusted.
//    Even a kernel-address space pointer should not be trusted for production level security.
//    Verity and capture all contents from user supplied address to VMM, then use them.
/*
这里有几个限制：
1.函数必须是ntos*.exe中的。
2.函数必须是导出的。
3.函数的名字要大写。
*/
ShadowHookTarget g_ddimonp_hook_targets[] = {
    { RTL_CONSTANT_STRING(L"NTCREATEFILE"),   HookNtCreateFile,  nullptr },//NtCreateFile
};


template <typename T> static T DdimonpFindOrignal(T handler)// Finds a handler to call an original function
{
    for (const auto& target : g_ddimonp_hook_targets)
    {
        if (target.handler == handler)
        {
            NT_ASSERT(target.original_call);//有时target.original_call == 0。
            return reinterpret_cast<T>(target.original_call);
        }
    }

    NT_ASSERT(false);
    return nullptr;
}


void DdimonpFreeAllocatedTrampolineRegions()
{
    PAGED_CODE();

    for (auto& target : g_ddimonp_hook_targets)
    {
        if (target.original_call)
        {
            ExFreePoolWithTag(target.original_call, kHyperPlatformCommonPoolTag);
            target.original_call = nullptr;
        }
    }
}


bool DdimonpEnumExportedSymbolsCallback(ULONG index, ULONG_PTR base_address, PIMAGE_EXPORT_DIRECTORY directory, ULONG_PTR directory_base, ULONG_PTR directory_end, void* context)
// Checks if the export is listed as a hook target, and if so install a hook.
{
    PAGED_CODE();

    if (!context) {
        return false;
    }

    auto functions = reinterpret_cast<ULONG*>(base_address + directory->AddressOfFunctions);
    auto ordinals = reinterpret_cast<USHORT*>(base_address + directory->AddressOfNameOrdinals);
    auto names = reinterpret_cast<ULONG*>(base_address + directory->AddressOfNames);
    auto ord = ordinals[index];
    auto export_address = base_address + functions[ord];
    auto export_name = reinterpret_cast<const char*>(base_address + names[index]);

    if (UtilIsInBounds(export_address, directory_base, directory_end)) {// Check if an export is forwarded one? If so, ignore it.
        return true;
    }

    // convert the name to UNICODE_STRING
    wchar_t name[100];
    auto status = RtlStringCchPrintfW(name, RTL_NUMBER_OF(name), L"%S", export_name);
    if (!NT_SUCCESS(status)) {
        return true;
    }
    UNICODE_STRING name_u = {};
    RtlInitUnicodeString(&name_u, name);

    for (auto& target : g_ddimonp_hook_targets)
    {
        if (!FsRtlIsNameInExpression(&target.target_name, &name_u, TRUE, nullptr))
        {// Is this export listed as a target
            continue;
        }

        if (!ShInstallHook(reinterpret_cast<SharedShadowHookData*>(context), reinterpret_cast<void*>(export_address), &target))
        {// Yes, install a hook to the export
            DdimonpFreeAllocatedTrampolineRegions();// This is an error which should not happen
            return false;
        }
    }

    return true;
}


NTSTATUS DdimonpEnumExportedSymbols(ULONG_PTR base_address, void* context)// Enumerates all exports in a module specified by base_address.
{
    PAGED_CODE();

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base_address);
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base_address + dos->e_lfanew);
    auto dir = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(&nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (!dir->Size || !dir->VirtualAddress)
    {
        return STATUS_SUCCESS;
    }

    auto dir_base = base_address + dir->VirtualAddress;
    auto dir_end = base_address + dir->VirtualAddress + dir->Size - 1;
    auto exp_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base_address + dir->VirtualAddress);
    for (auto i = 0ul; i < exp_dir->NumberOfNames; i++)
    {
        if (!DdimonpEnumExportedSymbolsCallback(i, base_address, exp_dir, dir_base, dir_end, context))
        {
            return STATUS_SUCCESS;
        }
    }

    return STATUS_SUCCESS;
}


//以上是私有的函数。
//////////////////////////////////////////////////////////////////////////////////////////////////
//一下是导出的函数。


EXTERN_C NTSTATUS DdimonInitialization(SharedShadowHookData* shared_sh_data)// Initializes DdiMon
{
    auto nt_base = UtilPcToFileHeader(KdDebuggerEnabled);//获取内核基地址是如此之简单，看来RtlPcToFileHeader还有别的用途，不信请细看。
    ASSERT(nt_base);

    // Install hooks by enumerating exports of ntoskrnl, but not activate them yet
    auto status = DdimonpEnumExportedSymbols(reinterpret_cast<ULONG_PTR>(nt_base), shared_sh_data);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ShEnableHooks();// Activate installed hooks
    if (!NT_SUCCESS(status)) {
        DdimonpFreeAllocatedTrampolineRegions();
        return status;
    }

    return status;
}


EXTERN_C void DdimonTermination()// Terminates DdiMon
{
    PAGED_CODE();

    ShDisableHooks();
    UtilSleep(1000);
    DdimonpFreeAllocatedTrampolineRegions();
}
