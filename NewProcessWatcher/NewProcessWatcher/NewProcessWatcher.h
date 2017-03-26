#ifndef _NEW_PROCESS_WATCHER_H__
#define _NEW_PROCESS_WATCHER_H__

#include <windows.h>
#include <winnt.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <tchar.h>


// Based on the code of Sven B. Schreiber on:
// http://www.informit.com/articles/article.aspx?p=22442&seqNum=5
typedef LONG KPRIORITY;
typedef LONG NTSTATUS;

#define PROTECT_READ 1
#define PROTECT_WRITE 2

#define STATUS_SUCCESS              ((NTSTATUS) 0x00000000)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS) 0xC0000004)

enum KWAIT_REASON
{
    Executive,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrEventPair,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    Spare2,
    Spare3,
    Spare4,
    Spare5,
    Spare6,
    WrKernel,
    MaximumWaitReason
};

enum THREAD_STATE
{
    Running = 2,
    Waiting = 5,
};

#pragma pack(push,4)

struct CLIENT_ID
{
    HANDLE UniqueProcess; // Process ID
    HANDLE UniqueThread;  // Thread ID
};

struct SYSTEM_THREAD
{
    FILETIME     ftKernelTime;
    FILETIME     ftUserTime;
    FILETIME     ftCreateTime;
    DWORD        dWaitTime;
    PVOID        pStartAddress;
    CLIENT_ID    Cid;
    DWORD        dPriority;
    DWORD        dBasePriority;
    DWORD        dContextSwitches;
    THREAD_STATE dThreadState;
    KWAIT_REASON WaitReason;
    DWORD        dReserved01;
};

struct VM_COUNTERS // virtual memory of process
{
    DWORD PeakVirtualSize;
    DWORD VirtualSize;
    DWORD PageFaultCount;
    DWORD PeakWorkingSetSize;
    DWORD WorkingSetSize;
    DWORD QuotaPeakPagedPoolUsage;
    DWORD QuotaPagedPoolUsage;
    DWORD QuotaPeakNonPagedPoolUsage;
    DWORD QuotaNonPagedPoolUsage;
    DWORD PagefileUsage;
    DWORD PeakPagefileUsage;
};

struct SYSTEM_PROCESS
{
    DWORD          dNext;         // relative offset
    DWORD          dThreadCount;
    DWORD          dReserved01;
    DWORD          dReserved02;
    DWORD          dReserved03;
    DWORD          dReserved04;
    DWORD          dReserved05;
    DWORD          dReserved06;
    FILETIME       ftCreateTime;
    FILETIME       ftUserTime;
    FILETIME       ftKernelTime;
    UNICODE_STRING usName;        // process name (unicode)
    KPRIORITY      BasePriority;
    DWORD          dUniqueProcessId;
    DWORD          dInheritedFromUniqueProcessId;
    DWORD          dHandleCount;
    DWORD          dReserved07;
    DWORD          dReserved08;
    VM_COUNTERS    VmCounters;    // see ntddk.h
    DWORD          dCommitCharge; // bytes
    IO_COUNTERS    IoCounters;    // see ntddk.h
    SYSTEM_THREAD  aThreads;      // thread array
};

#pragma pack(pop)

typedef NTSTATUS(WINAPI* t_NtQueryInfo)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG,
    PULONG);

class cProcInfo
{
public:
    cProcInfo()
    {
        mu32_DataSize = 1000;
        mp_Data = NULL;
        mf_NtQueryInfo = NULL;
    }
    virtual ~cProcInfo()
    {
        if (mp_Data)
        {
            LocalFree(mp_Data);
        }
    }

    // Capture all running processes and all their threads.
    // returns an API or NTSTATUS Error code or zero if successfull
    DWORD Capture()
    {
        if (!mf_NtQueryInfo)
        {
            mf_NtQueryInfo = (t_NtQueryInfo)GetProcAddress(GetModuleHandleA("NtDll.dll"),
                "NtQuerySystemInformation");
            if (!mf_NtQueryInfo)
            {
                return GetLastError();
            }
        }

        // This must run in a loop because in the mean time a new process may have started
        // and we need more buffer than u32_Needed !!
        while (true)
        {
            if (!mp_Data)
            {
                mp_Data = (BYTE*)LocalAlloc(LMEM_FIXED, mu32_DataSize);
                if (!mp_Data)
                {
                    return GetLastError();
                }
            }

            ULONG u32_Needed = 0;
            NTSTATUS s32_Status = mf_NtQueryInfo(SystemProcessInformation, mp_Data,
                mu32_DataSize, &u32_Needed);

            if (s32_Status == STATUS_INFO_LENGTH_MISMATCH) // The buffer was too small
            {
                mu32_DataSize = u32_Needed + 4000;
                LocalFree(mp_Data);
                mp_Data = NULL;
                continue;
            }
            return s32_Status;
        }
    }

    // Searches a process by a given Process Identifier
    // Capture() must have been called before!
    SYSTEM_PROCESS* FindProcessByPid(DWORD u32_PID)
    {
        if (!mp_Data)
        {
            return NULL;
        }

        SYSTEM_PROCESS* pk_Proc = (SYSTEM_PROCESS*)mp_Data;
        while (TRUE)
        {
            if (pk_Proc->dUniqueProcessId == u32_PID)
            {
                return pk_Proc;
            }

            if (!pk_Proc->dNext)
            {
                return NULL;
            }

            pk_Proc = (SYSTEM_PROCESS*)((BYTE*)pk_Proc + pk_Proc->dNext);
        }
    }

    SYSTEM_THREAD* FindThreadByTid(SYSTEM_PROCESS* pk_Proc, DWORD u32_TID)
    {
        if (!pk_Proc)
        {
            return NULL;
        }

        SYSTEM_THREAD* pk_Thread = &pk_Proc->aThreads;

        for (DWORD i = 0; i < pk_Proc->dThreadCount; i++)
        {
            if (pk_Thread->Cid.UniqueThread == (HANDLE)(DWORD_PTR)u32_TID)
            {
                return pk_Thread;
            }

            pk_Thread++;
        }
        return NULL;
    }

    DWORD IsThreadSuspended(SYSTEM_THREAD* pk_Thread, BOOL* pb_Suspended)
    {
        if (!pk_Thread)
        {
            return ERROR_INVALID_PARAMETER;
        }

        *pb_Suspended = (pk_Thread->dThreadState == Waiting &&
            pk_Thread->WaitReason == Suspended);
        return 0;
    }

private:
    BYTE*         mp_Data;
    DWORD       mu32_DataSize;
    t_NtQueryInfo mf_NtQueryInfo;
};
// end based code

#endif /* _NEW_PROCESS_WATCHER_H__ */