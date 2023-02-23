#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>
#include <string>
#include <vector>
#include <io.h>
#include <winver.h>
#include <thread>

#include <filesystem>
#pragma comment(lib, "version.lib")
#pragma comment(lib, "advapi32.lib")
namespace fs = std::filesystem;

void KillProcess(std::string processName){
    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
    PROCESSENTRY32 pEntry;
    pEntry.dwSize = sizeof (pEntry);
    BOOL hRes = Process32First(hSnapShot, &pEntry);
    while (hRes)
    {
        if (strcmp(pEntry.szExeFile, processName.c_str()) == 0)
        {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
                                          (DWORD) pEntry.th32ProcessID);
            if (hProcess != NULL)
            {
                TerminateProcess(hProcess, 9);
                CloseHandle(hProcess);
            }
        }
        hRes = Process32Next(hSnapShot, &pEntry);
    }
    CloseHandle(hSnapShot);
}


void println(const std::basic_string<char>& string) {
    std::printf("%s\n", string.c_str());
}

VOID __stdcall stopService()
{
    SC_HANDLE schSCManager;
    SC_HANDLE schService;

    schSCManager = OpenSCManager(
            NULL,                    // local computer
            NULL,                    // ServicesActive database
            SC_MANAGER_ALL_ACCESS);  // full access rights

    if (NULL == schSCManager)
    {
        printf("获取服务管理器时遇到错误: (%d)\n", GetLastError());
        return;
    }

    // Get a handle to the service.

    schService = OpenService(
            schSCManager,            // SCM database
            "zmserv",               // name of service
            SERVICE_CHANGE_CONFIG);  // need change config access

    if (schService == NULL)
    {
        printf("获取服务实例时遇到错误: (%d)\n", GetLastError());
        CloseServiceHandle(schSCManager);
        return;
    }

    // Change the service start type.

    if (! ChangeServiceConfig(
            schService,        // handle of service
            SERVICE_NO_CHANGE, // service type: no change
            SERVICE_DISABLED,  // service start type
            SERVICE_NO_CHANGE, // error control: no change
            NULL,              // binary path: no change
            NULL,              // load order group: no change
            NULL,              // tag ID: no change
            NULL,              // dependencies: no change
            NULL,              // account name: no change
            NULL,              // password: no change
            NULL) )            // display name: no change
    {
        printf("更改服务配置遇到错误: (%d)\n", GetLastError());
    }
    else printf("已停止机房管理助手系统服务\n");

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
}

VOID __stdcall deleteService()
{
    SC_HANDLE schSCManager;
    SC_HANDLE schService;
    SERVICE_STATUS ssStatus;

    // Get a handle to the SCM database.

    schSCManager = OpenSCManager(
            NULL,                    // local computer
            NULL,                    // ServicesActive database
            SC_MANAGER_ALL_ACCESS);  // full access rights

    if (NULL == schSCManager)
    {
        printf("获取服务管理器时遇到错误: (%d)\n", GetLastError());
        return;
    }

    // Get a handle to the service.

    schService = OpenService(
            schSCManager,       // SCM database
            "zmserv",          // name of service
            DELETE);            // need delete access

    if (schService == NULL)
    {
        printf("获取服务实例时遇到错误: (%d)\n", GetLastError());
        CloseServiceHandle(schSCManager);
        return;
    }

    // Delete the service.

    if (! DeleteService(schService) )
    {
        printf("删除服务时遇到错误: (%d)\n", GetLastError());
    }
    else printf("已删除机房管理助手系统服务\n");

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
}

std::string __stdcall queryProgramPath()
{
    SC_HANDLE schSCManager;
    SC_HANDLE schService;
    LPQUERY_SERVICE_CONFIG lpsc;
    LPSERVICE_DESCRIPTION lpsd;
    DWORD dwBytesNeeded, cbBufSize, dwError;

    // Get a handle to the SCM database.

    schSCManager = OpenSCManager(0, 0, SC_MANAGER_CONNECT);

    if (nullptr == schSCManager)
    {
        printf("获取服务管理器时遇到错误: (%d)\n", GetLastError());
        return nullptr;
    }

    // Get a handle to the service.

    schService = OpenService(schSCManager,"zmserv",SERVICE_QUERY_CONFIG);

    if (schService == nullptr)
    {
        printf("获取服务实例时遇到错误: (%d)\n", GetLastError());
        CloseServiceHandle(schSCManager);
        return nullptr;
    }

    // Get the configuration information.

    if( !QueryServiceConfig(
            schService,
            NULL,
            0,
            &dwBytesNeeded))
    {
        dwError = GetLastError();
        if( ERROR_INSUFFICIENT_BUFFER == dwError )
        {
            cbBufSize = dwBytesNeeded;
            lpsc = (LPQUERY_SERVICE_CONFIG) LocalAlloc(LMEM_FIXED, cbBufSize);
        }
        else
        {
            printf("查询服务详细时遇到错误: (%d)", dwError);
            CloseServiceHandle(schService);
            CloseServiceHandle(schSCManager);
        }
    }

    if( !QueryServiceConfig(
            schService,
            lpsc,
            cbBufSize,
            &dwBytesNeeded) )
    {
        printf("查询服务详细时遇到错误: (%d)", GetLastError());
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
    }

    if( !QueryServiceConfig2(
            schService,
            SERVICE_CONFIG_DESCRIPTION,
            NULL,
            0,
            &dwBytesNeeded))
    {
        dwError = GetLastError();
        if( ERROR_INSUFFICIENT_BUFFER == dwError )
        {
            cbBufSize = dwBytesNeeded;
            lpsd = (LPSERVICE_DESCRIPTION) LocalAlloc(LMEM_FIXED, cbBufSize);
        }
        else
        {
            printf("查询服务详细时遇到错误[2]: (%d)", dwError);
            CloseServiceHandle(schService);
            CloseServiceHandle(schSCManager);
        }
    }

    if (! QueryServiceConfig2(
            schService,
            SERVICE_CONFIG_DESCRIPTION,
            (LPBYTE) lpsd,
            cbBufSize,
            &dwBytesNeeded) )
    {
        printf("查询服务详细时遇到错误[2]: (%d)", GetLastError());
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
    }
    std::string program_path = lpsc->lpBinaryPathName;
    std::string replaced = program_path.replace(program_path.length()-10, program_path.length(), "");
    println("服务应用位置: " + program_path);
    println("安装目录: " + replaced);

    LocalFree(lpsc);
    LocalFree(lpsd);
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return replaced;
}


std::vector<std::string> get_all(std::string root, std::string ext)
{
    std::vector<std::string> paths;

    std::string path = root;
    for (auto &p : fs::recursive_directory_iterator(path))
    {
        if (p.path().extension().string() == ext)
            paths.emplace_back(p.path().stem().string());
    }

    return paths;
}

[[noreturn]] void killProcesses(const std::vector<std::string>& process_files) {
    println("开始杀除线程");
    while (true) {
        for (const auto& file : process_files) {
            KillProcess(file + ".exe");
        }
    }
}

struct LANGANDCODEPAGE {
    WORD wLanguage;
    WORD wCodePage;
} *lpTranslate;

std::string WStringToString(const std::wstring& s)
{
    std::string temp(s.length(), ' ');
    std::copy(s.begin(), s.end(), temp.begin());
    return temp;
}

std::string readFileInfo(const CHAR *fullName)
{
    DWORD dwHandle;

    DWORD dwinfoSize = GetFileVersionInfoSize(fullName, &dwHandle);
    if (!dwinfoSize) return nullptr;

    LPWSTR info = (LPWSTR)calloc(1, dwinfoSize);

    if (info) {
        BOOL bRes = GetFileVersionInfo(fullName, 0, dwinfoSize, info);

        if (bRes) {
            UINT uLen;
            UINT uBytes;
            LPBYTE lpBuffer = NULL;

            if (VerQueryValue(info, "\\VarFileInfo\\Translation", (LPVOID *)&lpTranslate, &uLen)) {
                if (uLen) {
                    WCHAR buf[1024] = { 0 };
                    swprintf(buf, L"\\StringFileInfo\\%04x%04x\\%s", lpTranslate[0].wLanguage, lpTranslate[0].wCodePage, "OriginalFileName");
                    LPCWSTR str = buf;
                    VerQueryValue(info, WStringToString(str).c_str(), (LPVOID*)&lpBuffer, &uBytes); //never return !!!!!!!!!!!!!!
                    return WStringToString((LPWSTR)lpBuffer);
                }
            }
        }

        free(info);
        info = NULL;
    }
    return nullptr;
}

int main() {
    println("学生守护者");
    println("Open Student Defender\n"
            "Version: 1.0.0\n"
            "Powered By FastMCMirror Organization\n"
            "(Reprogrammed to replace legacy KillerProject)");
    std::vector<std::string> files = get_all(queryProgramPath(), ".exe");
    std::thread killThread(killProcesses, std::ref(files));
    println("开始关闭服务");
    stopService();
    deleteService();
    println("请手动卸载机房管理助手后再关闭OpenStudentDefender!");
    killThread.join();
    return 0;
}
