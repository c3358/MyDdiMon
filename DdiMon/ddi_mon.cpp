// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/// @file
/// Implements DdiMon functions.

#include "ddi_mon.h"

static VOID DdimonpHandleExQueueWorkItem(_Inout_ PWORK_QUEUE_ITEM work_item, _In_ WORK_QUEUE_TYPE queue_type);
static PVOID DdimonpHandleExAllocatePoolWithTag(_In_ POOL_TYPE pool_type, _In_ SIZE_T number_of_bytes, _In_ ULONG tag);
static VOID DdimonpHandleExFreePool(_Pre_notnull_ PVOID p);
static VOID DdimonpHandleExFreePoolWithTag(_Pre_notnull_ PVOID p, _In_ ULONG tag);
static NTSTATUS DdimonpHandleNtQuerySystemInformation(_In_ SystemInformationClass SystemInformationClass, _Inout_ PVOID SystemInformation, _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength);

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
static ShadowHookTarget g_ddimonp_hook_targets[] = {
    {RTL_CONSTANT_STRING(L"EXQUEUEWORKITEM"),            DdimonpHandleExQueueWorkItem,           nullptr},
    {RTL_CONSTANT_STRING(L"EXALLOCATEPOOLWITHTAG"),      DdimonpHandleExAllocatePoolWithTag,     nullptr},
    {RTL_CONSTANT_STRING(L"EXFREEPOOL"),                 DdimonpHandleExFreePool,                nullptr},
    {RTL_CONSTANT_STRING(L"EXFREEPOOLWITHTAG"),          DdimonpHandleExFreePoolWithTag,         nullptr},
    {RTL_CONSTANT_STRING(L"NTQUERYSYSTEMINFORMATION"),   DdimonpHandleNtQuerySystemInformation,  nullptr},
};


_Use_decl_annotations_ EXTERN_C static void DdimonpFreeAllocatedTrampolineRegions()
// Frees trampoline code allocated and stored in g_ddimonp_hook_targets by DdimonpEnumExportedSymbolsCallback()
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


_Use_decl_annotations_ EXTERN_C static NTSTATUS DdimonpEnumExportedSymbols(ULONG_PTR base_address, EnumExportedSymbolsCallbackType callback, void* context)
// Enumerates all exports in a module specified by base_address.
{
    PAGED_CODE();

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base_address);
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base_address + dos->e_lfanew);
    auto dir = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(&nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (!dir->Size || !dir->VirtualAddress) {
        return STATUS_SUCCESS;
    }

    auto dir_base = base_address + dir->VirtualAddress;
    auto dir_end = base_address + dir->VirtualAddress + dir->Size - 1;
    auto exp_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base_address + dir->VirtualAddress);
    for (auto i = 0ul; i < exp_dir->NumberOfNames; i++)
    {
        if (!callback(i, base_address, exp_dir, dir_base, dir_end, context)) {
            return STATUS_SUCCESS;
        }
    }

    return STATUS_SUCCESS;
}


_Use_decl_annotations_ EXTERN_C static bool DdimonpEnumExportedSymbolsCallback(
    ULONG index,
    ULONG_PTR base_address,
    PIMAGE_EXPORT_DIRECTORY directory,
    ULONG_PTR directory_base,
    ULONG_PTR directory_end,
    void* context)
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
        if (!FsRtlIsNameInExpression(&target.target_name, &name_u, TRUE, nullptr)) {// Is this export listed as a target
            continue;
        }

        if (!ShInstallHook(reinterpret_cast<SharedShadowHookData*>(context), reinterpret_cast<void*>(export_address), &target)) {// Yes, install a hook to the export
            DdimonpFreeAllocatedTrampolineRegions();// This is an error which should not happen
            return false;
        }

        HYPERPLATFORM_LOG_INFO("Hook has been installed at %p %s.", export_address, export_name);
    }

    return true;
}


_Use_decl_annotations_ EXTERN_C NTSTATUS DdimonInitialization(SharedShadowHookData* shared_sh_data)// Initializes DdiMon
{
    auto nt_base = UtilPcToFileHeader(KdDebuggerEnabled);// Get a base address of ntoskrnl
    if (!nt_base) {
        return STATUS_UNSUCCESSFUL;
    }

    // Install hooks by enumerating exports of ntoskrnl, but not activate them yet
    auto status = DdimonpEnumExportedSymbols(reinterpret_cast<ULONG_PTR>(nt_base), DdimonpEnumExportedSymbolsCallback, shared_sh_data);
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


_Use_decl_annotations_ EXTERN_C void DdimonTermination()// Terminates DdiMon
{
    PAGED_CODE();

    ShDisableHooks();
    UtilSleep(1000);
    DdimonpFreeAllocatedTrampolineRegions();
    HYPERPLATFORM_LOG_INFO("DdiMon has been terminated.");
}


_Use_decl_annotations_ static std::array<char, 5> DdimonpTagToString(ULONG tag_value)
// Converts a pool tag in integer to a printable string
{
    PoolTag tag = { tag_value };
    for (auto& c : tag.chars)
    {
        if (!c && isspace(c)) {
            c = ' ';
        }
        if (!isprint(c)) {
            c = '.';
        }
    }

    std::array<char, 5> str;
    auto status = RtlStringCchPrintfA(str.data(), str.size(), "%c%c%c%c", tag.chars[0], tag.chars[1], tag.chars[2], tag.chars[3]);
    NT_VERIFY(NT_SUCCESS(status));
    return str;
}


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


_Use_decl_annotations_ static VOID DdimonpHandleExFreePool(PVOID p)
// The hook handler for ExFreePool(). Logs if ExFreePool() is called from where not backed by any image
{
    const auto original = DdimonpFindOrignal(DdimonpHandleExFreePool);
    original(p);
    
    auto return_addr = _ReturnAddress();
    if (UtilPcToFileHeader(return_addr)) {// Is inside image?
        return;
    }

    HYPERPLATFORM_LOG_INFO_SAFE("%p: ExFreePool(P= %p)", return_addr, p);
}


_Use_decl_annotations_ static VOID DdimonpHandleExFreePoolWithTag(PVOID p, ULONG tag)
// The hook handler for ExFreePoolWithTag(). Logs if ExFreePoolWithTag() is called from where not backed by any image.
{
    const auto original = DdimonpFindOrignal(DdimonpHandleExFreePoolWithTag);
    original(p, tag);
    
    /*
    开启pchunter的内核钩子里的内核钩子(这里常检测出inline hook)，能检测到pte hook.
    但是pchunter进程会占用一个CPU，且没有反应，这时退出，下面一行概率性的蓝屏，是写操作。
    */
    auto return_addr = _ReturnAddress();//这一行偶尔蓝屏。
    if (UtilPcToFileHeader(return_addr)) {// Is inside image?
        return;
    }

    HYPERPLATFORM_LOG_INFO_SAFE("%p: ExFreePoolWithTag(P= %p, Tag= %s)", return_addr, p, DdimonpTagToString(tag).data());
}


_Use_decl_annotations_ static VOID DdimonpHandleExQueueWorkItem(PWORK_QUEUE_ITEM work_item, WORK_QUEUE_TYPE queue_type)
// The hook handler for ExQueueWorkItem(). Logs if a WorkerRoutine points to where not backed by any image.
{
    const auto original = DdimonpFindOrignal(DdimonpHandleExQueueWorkItem);

    if (UtilPcToFileHeader(work_item->WorkerRoutine)) {// Is inside image?
      // Call an original after checking parameters.
      // It is common that a work routine frees a work_item object resulting in wrong analysis.
        original(work_item, queue_type);
        return;
    }

    auto return_addr = _ReturnAddress();
    HYPERPLATFORM_LOG_INFO_SAFE("%p: ExQueueWorkItem({Routine= %p, Parameter= %p}, %d)", return_addr, work_item->WorkerRoutine, work_item->Parameter, queue_type);
    original(work_item, queue_type);
}


_Use_decl_annotations_ static PVOID DdimonpHandleExAllocatePoolWithTag(POOL_TYPE pool_type, SIZE_T number_of_bytes, ULONG tag)
// The hook handler for ExAllocatePoolWithTag(). Logs if ExAllocatePoolWithTag() is called from where not backed by any image.
{
    const auto original = DdimonpFindOrignal(DdimonpHandleExAllocatePoolWithTag);
    const auto result = original(pool_type, number_of_bytes, tag);
    auto return_addr = _ReturnAddress();

    if (UtilPcToFileHeader(return_addr)) {// Is inside image?
        return result;
    }

    HYPERPLATFORM_LOG_INFO_SAFE("%p: ExAllocatePoolWithTag(POOL_TYPE= %08x, NumberOfBytes= %08X, Tag= %s) => %p", return_addr, pool_type, number_of_bytes, DdimonpTagToString(tag).data(), result);
    return result;
}


_Use_decl_annotations_ static NTSTATUS DdimonpHandleNtQuerySystemInformation(SystemInformationClass system_information_class, PVOID system_information, ULONG system_information_length, PULONG return_length)
// The hook handler for NtQuerySystemInformation(). Removes an entry for cmd.exe and hides it from being listed.
{
    const auto original = DdimonpFindOrignal(DdimonpHandleNtQuerySystemInformation);
    const auto result = original(system_information_class, system_information, system_information_length, return_length);
    if (!NT_SUCCESS(result)) {
        return result;
    }
    if (system_information_class != kSystemProcessInformation) {
        return result;
    }

    auto next = reinterpret_cast<SystemProcessInformation*>(system_information);
    while (next->next_entry_offset)
    {
        auto curr = next;
        next = reinterpret_cast<SystemProcessInformation*>(reinterpret_cast<UCHAR*>(curr) + curr->next_entry_offset);
        if (_wcsnicmp(next->image_name.Buffer, L"cmd.exe", 7) == 0) {
            if (next->next_entry_offset) {
                curr->next_entry_offset += next->next_entry_offset;
            } else {
                curr->next_entry_offset = 0;
            }
            next = curr;
        }
    }

    return result;
}
