//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information. 
//

#ifndef GCENV_H_
#define GCENV_H_

//
// Extra VM headers required to compile GC-related files
//

#include "finalizerthread.h"

#include "threadsuspend.h"

#ifdef FEATURE_COMINTEROP
#include <windows.ui.xaml.h>
#endif

#include "stubhelpers.h"

#include "eeprofinterfaces.inl"

#ifdef GC_PROFILING
#include "eetoprofinterfaceimpl.h"
#include "eetoprofinterfaceimpl.inl"
#include "profilepriv.h"
#endif

#ifdef DEBUGGING_SUPPORTED
#include "dbginterface.h"
#endif

#ifdef FEATURE_COMINTEROP
#include "runtimecallablewrapper.h"
#endif // FEATURE_COMINTEROP

#ifdef FEATURE_REMOTING
#include "remoting.h"
#endif 

#ifdef FEATURE_UEF_CHAINMANAGER
// This is required to register our UEF callback with the UEF chain manager
#include <mscoruefwrapper.h>
#endif // FEATURE_UEF_CHAINMANAGER


struct ScanContext;
class CrawlFrame;

typedef void promote_func(PTR_PTR_Object, ScanContext*, DWORD);

typedef struct
{
    promote_func*  f;
    ScanContext*   sc;
    CrawlFrame *   cf;
} GCCONTEXT;


class GCToEEInterface
{
public:
    //
    // Suspend/Resume callbacks
    //
    typedef enum
    {
        SUSPEND_FOR_GC = 1,
        SUSPEND_FOR_GC_PREP = 6
    } SUSPEND_REASON;

    static void SuspendEE(SUSPEND_REASON reason);
    static void RestartEE(BOOL bFinishedGC); //resume threads.

    // 
    // The GC roots enumeration callback
    //
    static void ScanStackRoots(Thread * pThread, promote_func* fn, ScanContext* sc);

    // Optional static GC refs scanning for better parallelization of server GC marking
    static void ScanStaticGCRefsOpportunistically(promote_func* fn, ScanContext* sc);

    // 
    // Callbacks issues during GC that the execution engine can do its own bookeeping
    //

    // start of GC call back - single threaded
    static void GcStartWork(int condemned, int max_gen); 

    //EE can perform post stack scanning action, while the 
    // user threads are still suspended 
    static void AfterGcScanRoots(int condemned, int max_gen, ScanContext* sc);

    // Called before BGC starts sweeping, the heap is walkable
    static void GcBeforeBGCSweepWork();

    // post-gc callback.
    static void GcDone(int condemned);

    // Promote refcounted handle callback
    static bool RefCountedHandleCallbacks(Object * pObject);

    // Sync block cache management
    static void SyncBlockCacheWeakPtrScan(HANDLESCANPROC scanProc, LPARAM lp1, LPARAM lp2);
    static void SyncBlockCacheDemote(int max_gen);
    static void SyncBlockCachePromotionsGranted(int max_gen);

    // Thread functions
    static bool IsPreemptiveGCDisabled(Thread * pThread)
    {
        WRAPPER_NO_CONTRACT;
        return !!pThread->PreemptiveGCDisabled();
    }

    static void EnablePreemptiveGC(Thread * pThread)
    {
        WRAPPER_NO_CONTRACT;
        pThread->EnablePreemptiveGC();
    }

    static void DisablePreemptiveGC(Thread * pThread)
    {
        WRAPPER_NO_CONTRACT;
        pThread->DisablePreemptiveGC();
    }

    static void SetGCSpecial(Thread * pThread);
    static alloc_context * GetAllocContext(Thread * pThread);
    static bool CatchAtSafePoint(Thread * pThread);

    static Thread * GetThreadList(Thread * pThread);
};

#undef InitializeCriticalSection
#undef DeleteCriticalSection
#undef EnterCriticalSection
#undef LeaveCriticalSection

class GCToOSInterface
{
public:
    static void Initialize();
    static void Shutdown();

    static void InitializeCriticalSection(CRITICAL_SECTION * lpCriticalSection);
    static void DeleteCriticalSection(CRITICAL_SECTION * lpCriticalSection);
    static void EnterCriticalSection(CRITICAL_SECTION * lpCriticalSection);
    static void LeaveCriticalSection(CRITICAL_SECTION * lpCriticalSection);

    static void* VirtualCommit(void* lpAddress, size_t dwSize);
    static void* VirtualReserve(void* lpAddress, size_t dwSize, DWORD protect, size_t alignment, bool fWatch = false);
    static void VirtualReset(void* lpAddress, size_t dwSize);
    static bool VirtualDecommit(void* lpAddress, size_t dwSize);
    static bool VirtualRelease(void* lpAddress, size_t dwSize);
    static void ResetWriteWatch(void* lpAddress, size_t dwSize);

    static void WriteLog(const char *fmt, va_list args);
    static bool IsLogOpen();

    static bool SwitchToThread(uint32_t dwSleepMSec, uint32_t dwSwitchCount);
    static size_t GetCurrentThreadId();
    static bool SetCurrentThreadIdealProcessor(int processorIndex, int groupIndex);
    static void YieldProcessor();

    static DWORD GetCurrentProcessorNumber();
    static bool CanGetCurrentProcessorNumber();
    static bool HasGetGetCurrentProcessorNumber();

    static void FlushProcessWriteBuffers();

    static void DebugBreak();
    static size_t GetLargestOnDieCacheSize(BOOL bTrueSize = TRUE);
    static DWORD GetLogicalCpuCount();

    static bool GetCurrentProcessAffinityMask(DWORD_PTR* pmask, DWORD_PTR* smask);
    static DWORD GetCurrentProcessCpuCount();
    static void GetCurrentProcessMemoryLoad(LPMEMORYSTATUSEX ms);

    static size_t GetHighResolutionTimeStamp();
    static unsigned int GetLowResolutionTimeStamp();

    static int32_t FastInterlockIncrement(int32_t volatile *lpAddend);
    static int32_t FastInterlockDecrement(int32_t volatile *lpAddend);
    static int32_t FastInterlockExchange(int32_t volatile *Target, int32_t Value);
    static int32_t FastInterlockCompareExchange(int32_t volatile *Destination, int32_t Exchange, int32_t Comperand);
    static int32_t FastInterlockExchangeAdd(int32_t volatile *Addend, int32_t Value);
    static void* FastInterlockExchangePointer(void * volatile *Target, void * Value);
    static void* FastInterlockCompareExchangePointer(void * volatile *Destination, void * Exchange, void * Comperand);
    static void FastInterlockOr(uint32_t volatile *p, uint32_t msk);

};

#endif // GCENV_H_