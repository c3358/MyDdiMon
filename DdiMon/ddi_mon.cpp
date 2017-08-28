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
此操作中，如果调用HYPERPLATFORM_LOG_INFO_SAFE之类的函数，这些函数是不是又调用NtCreateFile？
*/
{
    const auto original = DdimonpFindOrignal(HookNtCreateFile);
    if (!original)
    {
        KdPrint(("NtCreateFile正在调用，但是HOOK机制失效，估计是卸载操作已经发生，或者某些操作失败（我想你是知道的）.\r\n"));
        KdPrint(("我想是应该调用原函数，具体的机制还没有深入分析，但是经测试还是可以的，走这里没出现啥问题.\r\n"));
        const auto result = NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
        return result;
    }

    const auto result = original(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

    auto return_addr = _ReturnAddress();
    void * p = UtilPcToFileHeader(return_addr);//这个地址当然是内核的基地址，经测试验证也是的。
    KdPrint(("NtCreateFile is inside image:%p.\r\n", p));

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
4.Zw系列的函数也不建议使用，上面也说了，还有就是这只会再内核中被调用，剩下的话就是：应用层是不会调用的，除非特殊。
5.有时间改进下，改进为无论函数导出与否，都支持，只要有地址，因为有好些没有导出的函数。
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
                试想：
                1.此函数被调用在NtCreateFile操作中。
                2.HYPERPLATFORM_LOG_INFO_SAFE之类的函数又是用NtCreateFile的函数实现的。
                会出现啥情况？如何解决？
                文件过滤驱动可以指定下一层，或更深的函数。

                在开启本驱动的验证器的条件下，且开启了debugview，KdPrint会导致栈的递归调用，从而导致了蓝屏。
                */
                //KdPrint(("卸载/（或某些失败，你知道的）后会概率性的走这里.\r\n"));
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
            target.original_call = nullptr;//这个很重要，良好的编程习惯。
        }
    }
}


bool DdimonpEnumExportedSymbolsCallback(ULONG index, ULONG_PTR base_address, SharedShadowHookData* context)
// Checks if the export is listed as a hook target, and if so install a hook.
{
    PAGED_CODE();

    ASSERT(context);

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base_address);
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base_address + dos->e_lfanew);
    auto dir = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(&nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    ASSERT(dir->Size && dir->VirtualAddress);

    auto directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base_address + dir->VirtualAddress);
    auto functions = reinterpret_cast<ULONG*>(base_address + directory->AddressOfFunctions);
    auto ordinals = reinterpret_cast<USHORT*>(base_address + directory->AddressOfNameOrdinals);
    auto names = reinterpret_cast<ULONG*>(base_address + directory->AddressOfNames);
    auto ord = ordinals[index];
    void * export_address = reinterpret_cast<void*>(base_address + functions[ord]);
    auto export_name = reinterpret_cast<const char*>(base_address + names[index]);

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

        bool b = ShInstallHook(context, export_address, &target); ASSERT(b);
    }

    return true;
}


void DdimonpEnumExportedSymbols(SharedShadowHookData* context)
{
    PAGED_CODE();

    ULONG_PTR base_address = (ULONG_PTR)UtilPcToFileHeader(KdDebuggerEnabled);//获取内核基地址是如此之简单，看来RtlPcToFileHeader还有别的用途，不信请细看。
    ASSERT(base_address);

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base_address);
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base_address + dos->e_lfanew);
    auto dir = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(&nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    ASSERT (dir->Size && dir->VirtualAddress);

    auto exp_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base_address + dir->VirtualAddress);
    for (auto i = 0ul; i < exp_dir->NumberOfNames; i++)
    {
        bool b = DdimonpEnumExportedSymbolsCallback(i, base_address, context);
        if (!b)
        {
            return;
        }
    }
}


//以上是私有的函数。
//////////////////////////////////////////////////////////////////////////////////////////////////
//一下是导出的函数。


NTSTATUS DdimonInitialization(SharedShadowHookData* context)
{
    DdimonpEnumExportedSymbols(context);// Install hooks by enumerating exports of ntoskrnl, but not activate them yet

    auto status = ShEnableHooks();// Activate installed hooks
    if (!NT_SUCCESS(status)) {
        DdimonpFreeAllocatedTrampolineRegions();
        return status;
    }

    return status;
}


void DdimonTermination()
{
    PAGED_CODE();

    ShDisableHooks();
    UtilSleep(1000);
    DdimonpFreeAllocatedTrampolineRegions();
}
