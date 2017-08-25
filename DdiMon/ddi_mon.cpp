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
/*
�˲����У��������HYPERPLATFORM_LOG_INFO_SAFE֮��ĺ�������Щ�����ǲ����ֵ���NtCreateFile��
*/
{
    const auto original = DdimonpFindOrignal(HookNtCreateFile);
    if (!original)
    {
        KdPrint(("NtCreateFile���ڵ��ã�����HOOK����ʧЧ��������ж�ز����Ѿ�����������ĳЩ����ʧ�ܣ���������֪���ģ�.\r\n"));
        KdPrint(("������Ӧ�õ���ԭ����������Ļ��ƻ�û��������������Ǿ����Ի��ǿ��Եģ�������û����ɶ����.\r\n"));
        const auto result = NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
        return result;
    }

    const auto result = original(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
    auto return_addr = _ReturnAddress();
    void * p = UtilPcToFileHeader(return_addr);//�����ַ��Ȼ���ں˵Ļ���ַ����������֤Ҳ�ǵġ�

    KdPrint(("NtCreateFile is inside image:%p.\r\n", p));

    return result;
}


//������HOOK������
//////////////////////////////////////////////////////////////////////////////////////////////////
//������HOOK��ܡ�


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
�����м������ƣ�
1.����������ntos*.exe�еġ�
2.���������ǵ����ġ�
3.����������Ҫ��д��
4.Zwϵ�еĺ���Ҳ������ʹ�ã�����Ҳ˵�ˣ����о�����ֻ�����ں��б����ã�ʣ�µĻ����ǣ�Ӧ�ò��ǲ�����õģ��������⡣
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
            if (0 == target.original_call)
            {
                /*
                ���룺
                1.�˺�����������NtCreateFile�����С�
                2.HYPERPLATFORM_LOG_INFO_SAFE֮��ĺ���������NtCreateFile�ĺ���ʵ�ֵġ�
                �����ɶ�������ν����
                �ļ�������������ָ����һ�㣬�����ĺ�����
                */
                KdPrint(("ж�أ�ĳЩʧ�ܣ���֪���ģ��������Ե�������.\r\n"));
            }

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
            target.original_call = nullptr;//�������Ҫ�����õı��ϰ�ߡ�
        }
    }
}


bool DdimonpEnumExportedSymbolsCallback(ULONG index, ULONG_PTR base_address, void* context)
// Checks if the export is listed as a hook target, and if so install a hook.
{
    PAGED_CODE();

    ASSERT(context);

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base_address);
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base_address + dos->e_lfanew);
    auto dir = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(&nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    ASSERT(dir->Size && dir->VirtualAddress);

    auto directory_base = base_address + dir->VirtualAddress;
    auto directory_end = base_address + dir->VirtualAddress + dir->Size - 1;
    auto directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base_address + dir->VirtualAddress);

    auto functions = reinterpret_cast<ULONG*>(base_address + directory->AddressOfFunctions);
    auto ordinals = reinterpret_cast<USHORT*>(base_address + directory->AddressOfNameOrdinals);
    auto names = reinterpret_cast<ULONG*>(base_address + directory->AddressOfNames);
    auto ord = ordinals[index];
    auto export_address = base_address + functions[ord];
    auto export_name = reinterpret_cast<const char*>(base_address + names[index]);

    if (UtilIsInBounds(export_address, directory_base, directory_end))
    {
        return true;// Check if an export is forwarded one? If so, ignore it.
    }

    wchar_t name[100];
    auto status = RtlStringCchPrintfW(name, RTL_NUMBER_OF(name), L"%S", export_name); ASSERT(NT_SUCCESS(status));
    UNICODE_STRING name_u = {};
    RtlInitUnicodeString(&name_u, name);

    for (auto& target : g_ddimonp_hook_targets)
    {
        if (!FsRtlIsNameInExpression(&target.target_name, &name_u, TRUE, nullptr))
        {
            continue;
        }

        if (!ShInstallHook(reinterpret_cast<SharedShadowHookData*>(context), reinterpret_cast<void*>(export_address), &target))// Yes, install a hook to the export
        {
            DdimonpFreeAllocatedTrampolineRegions();// This is an error which should not happen
            return false;
        }
    }

    return true;
}


void DdimonpEnumExportedSymbols(void* context)
{
    PAGED_CODE();

    ULONG_PTR base_address = (ULONG_PTR)UtilPcToFileHeader(KdDebuggerEnabled);//��ȡ�ں˻���ַ�����֮�򵥣�����RtlPcToFileHeader���б����;��������ϸ����
    ASSERT(base_address);

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base_address);
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base_address + dos->e_lfanew);
    auto dir = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(&nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    ASSERT (dir->Size && dir->VirtualAddress);

    auto exp_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base_address + dir->VirtualAddress);
    for (auto i = 0ul; i < exp_dir->NumberOfNames; i++)
    {
        if (!DdimonpEnumExportedSymbolsCallback(i, base_address, context))
        {
            return;
        }
    }
}


//������˽�еĺ�����
//////////////////////////////////////////////////////////////////////////////////////////////////
//һ���ǵ����ĺ�����


EXTERN_C NTSTATUS DdimonInitialization(SharedShadowHookData* shared_sh_data)// Initializes DdiMon
{
    DdimonpEnumExportedSymbols(shared_sh_data);// Install hooks by enumerating exports of ntoskrnl, but not activate them yet

    auto status = ShEnableHooks();// Activate installed hooks
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
