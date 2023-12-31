///////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2023 Oliver Schneider (assarbad.net)
//
// Permission is hereby granted, free of charge, to any person or organization
// obtaining a copy of the software and accompanying documentation covered by
// this license (the "Software") to use, reproduce, display, distribute,
// execute, and transmit the Software, and to prepare derivative works of the
// Software, and to permit third-parties to whom the Software is furnished to
// do so, all subject to the following:
//
// The copyright notices in the Software and this entire statement, including
// the above license grant, this restriction and the following disclaimer,
// must be included in all copies of the Software, in whole or in part, and
// all derivative works of the Software, unless such copies or derivative
// works are solely in the form of machine-executable object code generated by
// a source language processor.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
// SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE
// FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
//
// [Boost Software License - Version 1.0 - August 17th, 2003]
//
// SPDX-License-Identifier: BSL-1.0
//
///////////////////////////////////////////////////////////////////////////////

#ifndef __RUNASSYS_H_VERSION__
#define __RUNASSYS_H_VERSION__ 2023100723

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#    pragma once
#endif

#define NtCurrentTeb NtCurrentTeb_Mock
#include "exeversion.h"
#include <Windows.h>
#include <tchar.h>
#include <WinSvc.h>
#include <strsafe.h>
#include <userenv.h>
#ifndef _MSVC_LANG
#    pragma warning(push)
#    pragma warning(disable : 4995)
#endif // _MSVC_LANG
#include <cstdio>
#ifndef _MSVC_LANG
#    pragma warning(pop)
#endif // _MSVC_LANG
#undef NtCurrentTeb
#include "ntnative.h"

#ifndef _MSVC_LANG
#    define nullptr NULL //-V1059
#endif

namespace RAS
{
#if !defined(SECURITY_DYNAMIC_TRACKING) && !defined(SECURITY_STATIC_TRACKING)
#    define SECURITY_DYNAMIC_TRACKING (TRUE)
#    define SECURITY_STATIC_TRACKING  (FALSE)

    typedef BOOLEAN SECURITY_CONTEXT_TRACKING_MODE, *PSECURITY_CONTEXT_TRACKING_MODE;

    typedef struct _SECURITY_QUALITY_OF_SERVICE
    {
        DWORD Length;
        SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
        SECURITY_CONTEXT_TRACKING_MODE ContextTrackingMode;
        BOOLEAN EffectiveOnly;
    } SECURITY_QUALITY_OF_SERVICE, *PSECURITY_QUALITY_OF_SERVICE;
#endif

    namespace impl
    {
        BOOL WINAPI DuplicateTokenEx(HANDLE hExistingToken,
                                     DWORD dwDesiredAccess,
                                     LPSECURITY_ATTRIBUTES lpTokenAttributes,
                                     SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
                                     TOKEN_TYPE TokenType,
                                     PHANDLE phNewToken)
        {
            OBJECT_ATTRIBUTES oa;
            InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

            if (lpTokenAttributes)
            {
                oa.SecurityDescriptor = lpTokenAttributes->lpSecurityDescriptor;
                oa.Attributes = (lpTokenAttributes->bInheritHandle) ? OBJ_INHERIT : 0;
            }
            SECURITY_QUALITY_OF_SERVICE sqs = {sizeof(SECURITY_QUALITY_OF_SERVICE), ImpersonationLevel, SECURITY_STATIC_TRACKING, TRUE};
            oa.SecurityQualityOfService = &sqs;
            NTSTATUS Status = ::NtDuplicateToken(hExistingToken, dwDesiredAccess, &oa, 0, TokenType, phNewToken);
            if (NT_SUCCESS(Status))
            {
                return TRUE;
            }
            ::RtlSetLastWin32ErrorAndNtStatusFromNtStatus(Status);
            return FALSE;
        }
    } // namespace impl

    class CLocalServiceMgr
    {
        SC_HANDLE m_hSCM; //-V122
        LONG m_lLastError;

      public:
        CLocalServiceMgr(__in LPCWSTR lpDatabaseName = SERVICES_ACTIVE_DATABASE, __in DWORD dwDesiredAccess = SC_MANAGER_CONNECT)
            : m_hSCM(NULL)
            , m_lLastError(ERROR_SUCCESS)
        {
            m_hSCM = ::OpenSCManager(NULL, lpDatabaseName, dwDesiredAccess);
            if (!m_hSCM)
            {
                m_lLastError = ::GetLastError();
                fwprintf(stderr, L"ERROR: failed to open local SCM database\n");
            }
        }

        inline bool operator!() const
        {
            return (m_lLastError != ERROR_SUCCESS);
        }

        inline operator bool() const
        {
            return !operator!();
        }

        inline LONG LastError() const
        {
            return m_lLastError;
        }

        inline void Close()
        {
            if (m_hSCM)
            {
                if (!::CloseServiceHandle(m_hSCM))
                {
                    m_lLastError = ::GetLastError();
                    fwprintf(stderr, L"ERROR: failed to close handle to local SCM database\n");
                }
                m_hSCM = NULL; // even if closing failed there is nothing we can do here
            }
        }

        inline ~CLocalServiceMgr()
        {
            Close();
        }

      private:
#ifdef _MSVC_LANG
        CLocalServiceMgr& operator=(CLocalServiceMgr const&) = delete;
        CLocalServiceMgr(CLocalServiceMgr const&) = delete;
#else
        CLocalServiceMgr& operator=(CLocalServiceMgr const&);
        CLocalServiceMgr(CLocalServiceMgr const&);
#endif
        friend class CSvcHandle;
    };

    class CSvcHandle
    {
        CLocalServiceMgr& m_SCM;
        SC_HANDLE m_hSvc; //-V122
        mutable LONG m_lLastError;
        mutable BOOL m_bProcessInfoQueried;
#ifdef _MSVC_LANG
        mutable SERVICE_STATUS_PROCESS m_StatusProcessInfo{};
#else
        mutable SERVICE_STATUS_PROCESS m_StatusProcessInfo;
#endif

      public:
        CSvcHandle(CLocalServiceMgr& scm, __in LPCTSTR lpServiceName, __in DWORD dwDesiredAccess)
            : m_SCM(scm)
            , m_hSvc(NULL)
            , m_lLastError(ERROR_SUCCESS)
            , m_bProcessInfoQueried(FALSE)
        {
            m_hSvc = ::OpenService(m_SCM.m_hSCM, lpServiceName, dwDesiredAccess);
            if (!m_hSvc)
            {
                m_lLastError = ::GetLastError();
                fwprintf(stderr, L"ERROR: failed to open service handle for '%s' (access=%08X)\n", lpServiceName, dwDesiredAccess);
                return;
            }
            ZeroMemory(&m_StatusProcessInfo, sizeof(m_StatusProcessInfo));
        }

        inline bool operator!() const
        {
            return (m_lLastError != ERROR_SUCCESS);
        }

        inline operator bool() const
        {
            return !operator!();
        }

        inline LONG LastError() const
        {
            return m_lLastError;
        }

        inline DWORD GetProcessId(BOOL bQueryAnew = FALSE) const
        {
            QueryStatusProcessInfo_(bQueryAnew);
            return m_bProcessInfoQueried ? m_StatusProcessInfo.dwProcessId : 0;
        }

        inline DWORD GetType(BOOL bQueryAnew = FALSE) const
        {
            QueryStatusProcessInfo_(bQueryAnew);
            return m_bProcessInfoQueried ? m_StatusProcessInfo.dwServiceType : 0;
        }

        inline bool IsRunning(BOOL bQueryAnew = FALSE) const
        {
            QueryStatusProcessInfo_(bQueryAnew);
            return (m_StatusProcessInfo.dwCurrentState == SERVICE_RUNNING);
        }

        inline bool IsPending(BOOL bQueryAnew = FALSE) const
        {
            QueryStatusProcessInfo_(bQueryAnew);
            return (m_StatusProcessInfo.dwCurrentState == SERVICE_START_PENDING) || (m_StatusProcessInfo.dwCurrentState == SERVICE_STOP_PENDING) ||
                   (m_StatusProcessInfo.dwCurrentState == SERVICE_CONTINUE_PENDING) || (m_StatusProcessInfo.dwCurrentState == SERVICE_PAUSE_PENDING);
        }

        inline bool IsPaused(BOOL bQueryAnew = FALSE) const
        {
            QueryStatusProcessInfo_(bQueryAnew);
            return (m_StatusProcessInfo.dwCurrentState == SERVICE_PAUSED);
        }

        inline bool IsStopped(BOOL bQueryAnew = FALSE) const
        {
            QueryStatusProcessInfo_(bQueryAnew);
            return (m_StatusProcessInfo.dwCurrentState == SERVICE_STOPPED);
        }

        inline bool Start()
        {
            if (!::StartService(m_hSvc, 0, NULL))
            {
                m_lLastError = ::GetLastError();
                return false;
            }
            InvalidateProcessInfo();
            return true;
        }

        inline void InvalidateProcessInfo()
        {
            m_bProcessInfoQueried = FALSE;
            ZeroMemory(&m_StatusProcessInfo, sizeof(m_StatusProcessInfo));
        }

        inline void Close()
        {
            if (m_hSvc)
            {
                if (!::CloseServiceHandle(m_hSvc))
                {
                    m_lLastError = ::GetLastError();
                    fwprintf(stderr, L"ERROR: failed to close service handle\n");
                }
                m_hSvc = NULL; // even if closing failed there is nothing we can do here
            }
        }

        inline ~CSvcHandle()
        {
            Close();
        }

      private:
        inline void QueryStatusProcessInfo_(BOOL bQueryAnew = FALSE) const
        {
            if (!m_bProcessInfoQueried || bQueryAnew)
            {
                DWORD dwNeeded = 0;
                m_bProcessInfoQueried =
                    ::QueryServiceStatusEx(m_hSvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&m_StatusProcessInfo, sizeof(m_StatusProcessInfo), &dwNeeded);
                if (!m_bProcessInfoQueried)
                {
                    m_lLastError = ::GetLastError();
                    fwprintf(stderr, L"ERROR: failed to query service process info (needed=%u)\n", dwNeeded);
                }
            }
        }

#ifdef _MSVC_LANG
        CSvcHandle() = delete;
        CSvcHandle& operator=(CSvcHandle const&) = delete;
        CSvcHandle(CSvcHandle const&) = delete;
#else
        CSvcHandle();
        CSvcHandle& operator=(CSvcHandle const&);
        CSvcHandle(CSvcHandle const&);
#endif
    };

    class CToken
    {
      protected:
        class CEnvironmentBlock
        {
          protected:
            LPVOID m_lpEnvironmentBlock; //-V122
            LONG m_lLastError;

          public:
            CEnvironmentBlock(CToken& Token, BOOL bInherit = FALSE)
                : m_lpEnvironmentBlock(NULL)
                , m_lLastError(ERROR_SUCCESS)
            {
                if (!::CreateEnvironmentBlock(&m_lpEnvironmentBlock, Token.m_hToken, bInherit))
                {
                    m_lLastError = ::GetLastError();
                    fwprintf(stderr, L"ERROR: failed to create environment block (status=%d)\n", m_lLastError);
                }
            }

            inline bool operator!() const
            {
                return (m_lLastError != ERROR_SUCCESS) || (m_lpEnvironmentBlock == NULL);
            }

            inline operator bool() const
            {
                return !operator!();
            }

            inline LONG LastError() const
            {
                return m_lLastError;
            }

            void Destroy()
            {
                if (m_lpEnvironmentBlock)
                {
                    if (!::DestroyEnvironmentBlock(m_lpEnvironmentBlock))
                    {
                        m_lLastError = ::GetLastError();
                        fwprintf(stderr, L"ERROR: failed to destroy environment block (status=%d)\n", m_lLastError);
                    }
                    m_lpEnvironmentBlock = NULL;
                }
            }

            ~CEnvironmentBlock()
            {
                Destroy();
            }

#ifdef _MSVC_LANG
            CEnvironmentBlock() = delete;
            CEnvironmentBlock& operator=(CEnvironmentBlock const&) = delete;
            CEnvironmentBlock(CEnvironmentBlock const&) = delete;
#else
            CEnvironmentBlock();
            CEnvironmentBlock& operator=(CEnvironmentBlock const&);
            CEnvironmentBlock(CEnvironmentBlock const&);
#endif
            friend class CToken;
        };

        HANDLE m_hToken; //-V122
        mutable LONG m_lLastError;

        explicit CToken(HANDLE hToken)
            : m_hToken(hToken)
            , m_lLastError(ERROR_SUCCESS)
        {
        }

      public:
        inline CToken& operator=(CToken& rvalue)
        {
            if (&rvalue != this)
            {
                m_hToken = rvalue.m_hToken;
                m_lLastError = rvalue.m_lLastError;
                rvalue.m_hToken = NULL;
                rvalue.m_lLastError = ERROR_SUCCESS;
            }
            return *this;
        }

        CToken(CToken& rvalue)
            : m_hToken(rvalue.m_hToken)
            , m_lLastError(rvalue.m_lLastError)
        {
            rvalue.m_hToken = NULL;
            rvalue.m_lLastError = ERROR_SUCCESS;
        }

        ~CToken()
        {
            Close();
        }

        inline void Close()
        {
            if (m_hToken)
            {
                if (!::CloseHandle(m_hToken))
                {
                    m_lLastError = ::GetLastError();
                    fwprintf(stderr, L"ERROR: failed to close token handle\n");
                }
                m_hToken = NULL;
            }
        }

        PROCESS_INFORMATION CreateProcessAsUser(LPWSTR lpCommandLine = NULL,
                                                LPCWSTR lpCurrentDirectory = NULL,
                                                DWORD dwCreationFlags = CREATE_BREAKAWAY_FROM_JOB)
        {
            dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT; // needed with CreateEnvironmentBlock() below
            STARTUPINFO si = {0};
            si.cb = sizeof(STARTUPINFO);
            si.lpDesktop = (LPWSTR)L"WinSta0\\Default"; // TODO/FIXME: must be correctly determined
            PROCESS_INFORMATION pi = {0};

            if (!lpCurrentDirectory)
            {
                lpCurrentDirectory = NT::SystemRoot; // szSystemDirectory;
            }

            WCHAR szCommandLine[MAX_PATH] = {0};
            if (!lpCommandLine)
            {
                memcpy(szCommandLine, NT::SystemRoot, sizeof(szCommandLine));
                (void)wcsncat_s(szCommandLine, L"\\System32\\cmd.exe", _countof(szCommandLine));
                lpCommandLine = szCommandLine;
            }

            CEnvironmentBlock EnvBlock(*this);
            if (!::CreateProcessAsUser(
                    m_hToken, NULL, lpCommandLine, NULL, NULL, TRUE, dwCreationFlags, EnvBlock.m_lpEnvironmentBlock, lpCurrentDirectory, &si, &pi))
            {
                m_lLastError = ::GetLastError();
                fwprintf(stderr, L"ERROR: CreateProcessAsUser() failed (status=%d)\n", m_lLastError);
                ZeroMemory(&pi, sizeof(pi));
                return pi;
            }
            return pi;
        }

        inline CToken Duplicate(DWORD dwDesiredAccess, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType) const
        {
            HANDLE hDuplicatedToken = NULL;
            if (m_hToken)
            {
                if (!impl::DuplicateTokenEx(m_hToken, dwDesiredAccess, NULL, ImpersonationLevel, TokenType, &hDuplicatedToken))
                {
                    fwprintf(stderr, L"ERROR: DuplicateTokenEx() failed (status=%u)\n", ::GetLastError());
                }
            }
            return CToken(hDuplicatedToken);
        }

        inline CToken Duplicate(SECURITY_IMPERSONATION_LEVEL ImpersonationLevel) const
        {
            return Duplicate(TOKEN_IMPERSONATE | TOKEN_QUERY, ImpersonationLevel, TokenImpersonation);
        }

        inline bool SetCurrentThreadToken() const
        {
            if (!::SetThreadToken(NULL, m_hToken))
            {
                m_lLastError = ::GetLastError();
                fwprintf(stderr, L"ERROR: call to SetThreadToken() failed (status=%d)\n", m_lLastError);
                return false;
            }
            return true;
        }

        inline bool operator!() const
        {
            return (m_lLastError != ERROR_SUCCESS) || (m_hToken == NULL);
        }

        inline operator bool() const
        {
            return !operator!();
        }

        inline LONG LastError() const
        {
            return m_lLastError;
        }

        inline BOOL SetPrivilege(LPCTSTR lpPrivilegeName, BOOL bEnable) const
        {
            if (!*this)
            {
                return FALSE;
            }
            LUID luid;

            if (!::LookupPrivilegeValue(NULL, lpPrivilegeName, &luid))
            {
                m_lLastError = ::GetLastError();
                fwprintf(stderr, L"ERROR: failed to look up LUID for privilege %s\n", lpPrivilegeName);
                return FALSE;
            }

            TOKEN_PRIVILEGES tp = {0};
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = 0; // don't change but also don't disable
            TOKEN_PRIVILEGES tpPrevious = {0};
            DWORD cbPrevious = 0;

            if (!::AdjustTokenPrivileges(m_hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &tpPrevious, &cbPrevious))
            {
                m_lLastError = ::GetLastError();
                fwprintf(stderr, L"ERROR: failed %s privilege %s\n", (bEnable) ? L"enable" : L"disable", lpPrivilegeName);
                return FALSE;
            }

            tpPrevious.PrivilegeCount = 1;
            tpPrevious.Privileges[0].Luid = luid;

            if (bEnable)
                tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
            else
                tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED & tpPrevious.Privileges[0].Attributes);

            if (!::AdjustTokenPrivileges(m_hToken, FALSE, &tpPrevious, NULL, NULL, NULL))
            {
                m_lLastError = ::GetLastError();
                return FALSE;
            }
            m_lLastError = ERROR_SUCCESS;
            return TRUE;
        }

        inline BOOL EnablePrivilege(LPCTSTR lpPrivilegeName) const
        {
            return SetPrivilege(lpPrivilegeName, TRUE);
        }

        inline BOOL DisablePrivilege(LPCTSTR lpPrivilegeName) const
        {
            return SetPrivilege(lpPrivilegeName, FALSE);
        }

      protected:
        static inline HANDLE OpenProcessToken_(HANDLE hProcess, DWORD dwDesiredAccess)
        {
            HANDLE hToken = NULL;
            NTSTATUS Status = ::NtOpenProcessToken(hProcess, dwDesiredAccess, &hToken);
            if (!NT_SUCCESS(Status))
            {
                return NULL;
            }
            return hToken;
        }

        static inline HANDLE OpenThreadToken_(HANDLE hThread, DWORD dwDesiredAccess, BOOLEAN OpenAsSelf = FALSE)
        {
            HANDLE hToken = NULL;
            NTSTATUS Status = ::NtOpenThreadToken(hThread, dwDesiredAccess, OpenAsSelf, &hToken);
            if (!NT_SUCCESS(Status))
            {
                return NULL;
            }
            return hToken;
        }

#ifdef _MSVC_LANG
        CToken() = delete;
#else
        CToken();
#endif
        friend class CEnvironmentBlock;
        friend class CTokenInfo;
    };

    class CTokenInfo
    {
        HANDLE const& m_hToken; //-V122
        mutable LONG m_lLastError;

      public:
        explicit CTokenInfo(HANDLE hToken)
            : m_hToken(hToken)
            , m_lLastError(ERROR_SUCCESS)
        {
        }

        explicit CTokenInfo(CToken const& rvalue)
            : m_hToken(rvalue.m_hToken)
            , m_lLastError(ERROR_SUCCESS)
        {
        }

        ~CTokenInfo()
        {
        }

        inline bool operator!() const
        {
            return (m_lLastError != ERROR_SUCCESS) || (m_hToken == NULL);
        }

        inline operator bool() const
        {
            return !operator!();
        }

        inline LONG LastError() const
        {
            return m_lLastError;
        }

        inline void GetTokenInfo()
        {
            //::GetTokenInformation(m_hToken, )
            // TokenUser
            // TokenGroups
            // TokenPrivileges
            // TokenOwner
            // TokenPrimaryGroup
            // TokenDefaultDacl
            // TokenSource
            // TokenType
            // TokenImpersonationLevel
            // TokenStatistics (possibly can be used to save on some of the other types)
            // TokenRestrictedSids
            // TokenSessionId
            // TokenGroupsAndPrivileges
            // TokenSandBoxInert
            // TokenOrigin // max. in W2K3
            // TokenElevationType
            // TokenLinkedToken
            // TokenElevation
            // TokenHasRestrictions (filtered?)
            // TokenAccessInformation
            // TokenVirtualizationAllowed
            // TokenVirtualizationEnabled
            // TokenIntegrityLevel
            // TokenUIAccess
            // TokenMandatoryPolicy
            // TokenLogonSid
        }

        inline void CacheTokenInfo()
        {
        }

      private:
#ifdef _MSVC_LANG
        CTokenInfo(CTokenInfo&) = delete;
        CTokenInfo& operator=(CTokenInfo&) = delete;
#else
        CTokenInfo(CTokenInfo&);
        CTokenInfo& operator=(CTokenInfo&);
#endif
    };

    class CThreadToken : public CToken
    {
        typedef CToken Inherited;

      public:
        explicit CThreadToken(DWORD dwDesiredAccess = TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, BOOLEAN OpenAsSelf = FALSE)
            : Inherited(Inherited::OpenThreadToken_(NtCurrentThread(), dwDesiredAccess, OpenAsSelf))
        {
            if (!Inherited::m_hToken)
            {
                m_lLastError = ::GetLastError();
            }
        }

        explicit CThreadToken(HANDLE hThread, DWORD dwDesiredAccess = TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, BOOLEAN OpenAsSelf = FALSE)
            : Inherited(Inherited::OpenThreadToken_(hThread, dwDesiredAccess, OpenAsSelf))
        {
            if (!Inherited::m_hToken)
            {
                m_lLastError = ::GetLastError();
            }
        }

        ~CThreadToken()
        {
            Inherited::Close();
        }

#ifdef _MSVC_LANG
        CThreadToken& operator=(CThreadToken const&) = delete;
        CThreadToken(CThreadToken const&) = delete;
#else
        CThreadToken& operator=(CThreadToken const&);
        CThreadToken(CThreadToken const&);
#endif
    };

    class CProcessToken : public CToken
    {
        typedef CToken Inherited;

      public:
        explicit CProcessToken(DWORD dwDesiredAccess = TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)
            : Inherited(Inherited::OpenProcessToken_(NtCurrentProcess(), dwDesiredAccess))
        {
            if (!Inherited::m_hToken)
            {
                m_lLastError = ::GetLastError();
            }
        }

        CProcessToken(HANDLE hProcess, DWORD dwDesiredAccess = TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)
            : Inherited(Inherited::OpenProcessToken_(hProcess, dwDesiredAccess))
        {
            if (!Inherited::m_hToken)
            {
                m_lLastError = ::GetLastError();
            }
        }

        ~CProcessToken()
        {
            Inherited::Close();
        }

#ifdef _MSVC_LANG
        CProcessToken& operator=(CProcessToken const&) = delete;
        CProcessToken(CProcessToken const&) = delete;
#else
        CProcessToken& operator=(CProcessToken const&);
        CProcessToken(CProcessToken const&);
#endif
    };

    class CCreatedProcess
    {
        HANDLE m_hParentProc; //-V122
        LONG m_lLastError;
        BOOL m_bFullyInitialized;
#ifdef _MSVC_LANG
        STARTUPINFOEX m_StartupInfo{};
        PROCESS_INFORMATION m_ProcessInfo{};
#else
        STARTUPINFOEX m_StartupInfo;
        PROCESS_INFORMATION m_ProcessInfo;
#endif

      public:
        CCreatedProcess(DWORD dwParentPid, LPCTSTR lpCmdLine = TEXT("C:\\Windows\\System32\\cleanmgr.exe"))
            : m_hParentProc(NULL)
            , m_lLastError(ERROR_SUCCESS)
            , m_bFullyInitialized(FALSE)
        {
            CProcessToken proctk;
            if (!proctk || !proctk.EnablePrivilege(SE_DEBUG_NAME))
            {
                m_lLastError = proctk.LastError();
                fwprintf(stderr, L"ERROR: failed enable privilege %s\n", SE_DEBUG_NAME);
                return;
            }
            (void)proctk.Close();
            m_hParentProc = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwParentPid);
            if (!m_hParentProc)
            {
                m_lLastError = ::GetLastError();
                fwprintf(stderr, L"ERROR: failed to open process with PID %u\n", dwParentPid);
                return;
            }

            ZeroMemory(&m_StartupInfo, sizeof(m_StartupInfo));
            m_StartupInfo.StartupInfo.cb = sizeof(m_StartupInfo);
            m_StartupInfo.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
            m_StartupInfo.StartupInfo.wShowWindow = SW_HIDE;

            SIZE_T sNeeded = 0;
            if (!::InitializeProcThreadAttributeList(NULL, 1, 0, &sNeeded) && ERROR_INSUFFICIENT_BUFFER == ::GetLastError()) // expected to fail
            {
                m_StartupInfo.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)::GlobalAlloc(GPTR, sNeeded);
            }
            if (!m_StartupInfo.lpAttributeList)
            {
                m_lLastError = ::GetLastError();
                fwprintf(stderr, L"ERROR: failed allocate memory for process thread attribute list\n");
                return;
            }
            if (!::InitializeProcThreadAttributeList(m_StartupInfo.lpAttributeList, 1, 0, &sNeeded))
            {
                m_lLastError = ::GetLastError();
                fwprintf(stderr, L"ERROR: failed to initialize process thread attribute list\n");
                (void)::GlobalFree((HGLOBAL)m_StartupInfo.lpAttributeList); // needed so we don't accidentally call DeleteProcThreadAttributeList()
                m_StartupInfo.lpAttributeList = NULL;
                return;
            }
            if (!::UpdateProcThreadAttribute(
                    m_StartupInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &m_hParentProc, sizeof(m_hParentProc), NULL, NULL)) //-V616
            {
                m_lLastError = ::GetLastError();
                fwprintf(stderr, L"ERROR: failed to update process thread attribute\n");
                return;
            }

            ZeroMemory(&m_ProcessInfo, sizeof(m_ProcessInfo));
            // Create a "process from within "trusted" process from within SystemRoot
            if (!::CreateProcess(lpCmdLine,
                                 NULL,
                                 NULL,
                                 NULL,
                                 TRUE,
                                 EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_SUSPENDED,
                                 NULL,
                                 NULL,
                                 (LPSTARTUPINFO)&m_StartupInfo,
                                 &m_ProcessInfo))
            {
                m_lLastError = ::GetLastError();
                fwprintf(stderr, L"ERROR: failed create child process of parent (PID=%u)\n", dwParentPid);
                return;
            }
            m_bFullyInitialized = TRUE;
        }

        explicit CCreatedProcess(PROCESS_INFORMATION const& pi)
            : m_hParentProc(NULL)
            , m_lLastError(ERROR_SUCCESS)
            , m_bFullyInitialized(FALSE)
        {
            if (&m_ProcessInfo != &pi)
            {
                memcpy(&m_ProcessInfo, &pi, sizeof(PROCESS_INFORMATION));
            }
            m_bFullyInitialized = TRUE;
        }

        inline bool operator!() const
        {
            return m_bFullyInitialized && (m_lLastError != ERROR_SUCCESS);
        }

        inline operator bool() const
        {
            return !operator!();
        }

        inline LONG LastError() const
        {
            return m_lLastError;
        }

        inline PROCESS_INFORMATION const& ProcessInfo() const
        {
            return m_ProcessInfo;
        }

        inline void WaitForever() const
        {
            (void)::WaitForSingleObject(m_ProcessInfo.hProcess, INFINITE);
        }

        inline bool Resume()
        {
            DWORD dwResult = ::ResumeThread(m_ProcessInfo.hThread);
            if ((DWORD)-1 == dwResult)
            {
                m_lLastError = ::GetLastError();
                return false;
            }
            return true;
        }

        inline bool Terminate(UINT uExitCode = 0)
        {
            if (!::TerminateProcess(m_ProcessInfo.hProcess, uExitCode))
            {
                m_lLastError = ::GetLastError();
                fwprintf(stderr, L"ERROR: failed to terminate created process (status=%d)\n", m_lLastError);
                return false;
            }
            return true;
        }

        void Close(BOOL bAlsoKillChild = FALSE)
        {
            if (m_hParentProc)
            {
                if (!::CloseHandle(m_hParentProc))
                {
                    m_lLastError = ::GetLastError();
                    fwprintf(stderr, L"ERROR: failed to close handle to parent process (status=%d)\n", m_lLastError);
                }
                m_hParentProc = NULL;
                if (m_StartupInfo.lpAttributeList) // cannot happen without valid parent process handle
                {
                    ::DeleteProcThreadAttributeList(m_StartupInfo.lpAttributeList);
                    (void)::GlobalFree((HGLOBAL)m_StartupInfo.lpAttributeList);
                    m_StartupInfo.lpAttributeList = NULL;
                }
            }
            if (m_ProcessInfo.hProcess)
            {
                if (bAlsoKillChild)
                {
                    Terminate(0);
                }
                if (!::CloseHandle(m_ProcessInfo.hProcess))
                {
                    m_lLastError = ::GetLastError();
                    fwprintf(stderr, L"ERROR: failed to close handle to created child process (PID=%u; status=%d)\n", m_ProcessInfo.dwProcessId, m_lLastError);
                }
                m_ProcessInfo.hProcess = NULL;
            }
            if (m_ProcessInfo.hThread)
            {
                if (!::CloseHandle(m_ProcessInfo.hThread))
                {
                    m_lLastError = ::GetLastError();
                    fwprintf(stderr,
                             L"ERROR: failed to close handle to main thread (TID=%u) in created child process (status=%d)\n",
                             m_ProcessInfo.dwThreadId,
                             m_lLastError);
                }
                m_ProcessInfo.hThread = NULL;
            }
        }

        ~CCreatedProcess()
        {
            Close();
        }

      private:
#ifdef _MSVC_LANG
        CCreatedProcess() = delete;
        CCreatedProcess& operator=(CCreatedProcess const&) = delete;
        CCreatedProcess(CCreatedProcess const&) = delete;
#else
        CCreatedProcess();
        CCreatedProcess& operator=(CCreatedProcess const&);
        CCreatedProcess(CCreatedProcess const&);
#endif
    };

    DWORD GetServiceProcessId(LPCTSTR lpServiceName)
    {
        CLocalServiceMgr scm;
        if (!scm)
        {
            return 0;
        }
        CSvcHandle svc(scm, lpServiceName, SERVICE_QUERY_STATUS | SERVICE_START);
        if (!svc)
        {
            return 0;
        }
        if (svc.IsRunning() && svc.GetType() == SERVICE_WIN32_OWN_PROCESS)
        {
            DWORD const dwPID = svc.GetProcessId();
            fwprintf(stderr, L"INFO: %s service already running (PID=%u)\n", lpServiceName, dwPID);
            return dwPID;
        }
        if (!svc.Start())
        {
            fwprintf(stderr, L"INFO: starting %s service\n", lpServiceName);
            return 0;
        }
        if (svc.IsPending())
        {
            DWORD const dwMaxRetries = 10;
            DWORD const dwSleepDuration = 250;
            DWORD dwCount = dwMaxRetries;
            do
            {
                if (svc.IsRunning(TRUE))
                {
                    break;
                }
                ::Sleep(dwSleepDuration);
            } while (--dwCount);
        }
        if (svc.IsRunning() && svc.GetType() == SERVICE_WIN32_OWN_PROCESS)
        {
            DWORD const dwPID = svc.GetProcessId();
            fwprintf(stderr, L"INFO: %s service now running (PID=%u)\n", lpServiceName, dwPID);
            return dwPID;
        }
        return 0;
    }
} // namespace RAS

#endif // __RUNASSYS_H_VERSION__
