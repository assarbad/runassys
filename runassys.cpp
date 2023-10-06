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

///////////////////////////////////////////////////////////////////////////////
// #define UNICODE
// #define _UNICODE
// These two defines are given implicitly through the settings of C_DEFINES in
// the SOURCES file of the project. Hence change them there and there only.
///////////////////////////////////////////////////////////////////////////////
#ifndef _UNICODE
#    error Must be built with wide character support enabled
#endif

#include "runassys.h"
#include <cstdlib>

#pragma comment(lib, "userenv.lib")

int StartAsLocalSystem()
{
    using namespace RAS;
    // First see if the TrustedInstaller service is already running, if not start it and either way retrieve its PID
    LPCTSTR lpServiceName = TEXT("TrustedInstaller");
    DWORD dwTrustedInstallerProcessId = RAS::GetServiceProcessId(lpServiceName);
    if (!dwTrustedInstallerProcessId)
    {
        fwprintf(stderr, L"FATAL: failed to retrieve PID for TrustedInstaller service. Cannot proceed.\n");
        return EXIT_FAILURE;
    }

    // Fake a (suspended) child process of the above by setting the process thread attributes
    CCreatedProcess TrustedInstallerChildProcess(dwTrustedInstallerProcessId);
    if (!TrustedInstallerChildProcess)
    {
        // TODO/FIXME: show last error
        fwprintf(stderr, L"FATAL: failed to retrieve PID for TrustedInstaller service. Cannot proceed.\n");
        return EXIT_FAILURE;
    }
    // SE_DEBUG_NAME should still be active from the above upon success
    PROCESS_INFORMATION const& pi = TrustedInstallerChildProcess.ProcessInfo();

    // Open token assigned to the created child process
    CProcessToken ChildToken(pi.hProcess, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY);
    if (!ChildToken)
    {
        // TODO/FIXME: show last error
        fwprintf(stderr, L"FATAL: failed to open child process token. Cannot proceed.\n");
        return EXIT_FAILURE;
    }

    // Duplicate the token as an impersonation token
    CToken ImpersonationToken(ChildToken.Duplicate(SecurityImpersonation));
    if (!ImpersonationToken)
    {
        // TODO/FIXME: show last error
        fwprintf(stderr, L"FATAL: failed to duplicate child process token. Cannot proceed.\n");
        return EXIT_FAILURE;
    }

    // Impersonate the above retrieved token in our current thread
    if (!ImpersonationToken.SetCurrentThreadToken())
    {
        // TODO/FIXME: show last error
        fwprintf(stderr, L"FATAL: failed to set current thread token. Cannot proceed.\n");
        return EXIT_FAILURE;
    }
    ImpersonationToken.Close();

    // Retrieve the current thread's token anew (should now match the above already)
    CThreadToken SystemToken(TOKEN_ALL_ACCESS);
    // We need the SE_ASSIGNPRIMARYTOKEN_NAME privilege first and foremost
    if (!SystemToken || !SystemToken.EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME) ||
        !SystemToken.EnablePrivilege(SE_INCREASE_QUOTA_NAME)) // needed for CreateProcessAsUser
    {
        // TODO/FIXME: show last error
        fwprintf(stderr, L"FATAL: failed to enable privileges for current thread. Cannot proceed.\n");
        return EXIT_FAILURE;
    }
    ChildToken.Close();

    // Convert the existing impersonation token to a primary token usable with CreateProcessAsUser()
    CToken PrimaryToken(SystemToken.Duplicate(TOKEN_ALL_ACCESS, SecurityImpersonation, TokenPrimary));
    if (!PrimaryToken)
    {
        // TODO/FIXME: show last error
        fwprintf(stderr, L"FATAL: failed to duplicate child process token. Cannot proceed.\n");
        return EXIT_FAILURE;
    }
    SystemToken.Close();
    TrustedInstallerChildProcess.Close(TRUE);

    // Now create the process we're interested in (but first suspended, so we don't run into garbled output issues)
    CCreatedProcess SystemProcess(PrimaryToken.CreateProcessAsUser(NULL, NULL, CREATE_BREAKAWAY_FROM_JOB | CREATE_SUSPENDED));
    if (!SystemProcess)
    {
        // TODO/FIXME: show last error
        fwprintf(stderr, L"FATAL: failed to create NT AUTHORITY\\SYSTEM process. Cannot proceed.\n");
        fflush(stderr);
        return EXIT_FAILURE;
    }

    fflush(stderr);
    fwprintf(stdout, L"Running as NT AUTHORITY\\SYSTEM\n");
    // TODO: output some token info
    fflush(stdout);
    if (!SystemProcess.Resume()) // resume the main thread of whatever we started only gets to run now
    {
        fwprintf(stderr, L"FATAL: failed to resume newly created process. Cannot proceed.\n");
        SystemProcess.Close(TRUE);
        return EXIT_FAILURE;
    }
    SystemProcess.WaitForever();
    return EXIT_SUCCESS;
}

int __cdecl wmain(int /*argc*/, wchar_t* /*argv*/[])
{
    return StartAsLocalSystem();
}
