// Developer-only Win32 metadata probe, executed inside the real PSEC policy.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstring>
#include <iostream>
#include <vector>
#pragma comment(lib, "advapi32.lib")

template <typename Function>
Function Resolve(HMODULE module, const char* name) {
  Function function = nullptr;
  const FARPROC address = module == nullptr ? nullptr : GetProcAddress(module, name);
  static_assert(sizeof(function) == sizeof(address));
  std::memcpy(&function, &address, sizeof(function));
  return function;
}

int HostReport() {
  OSVERSIONINFOEXW os{};
  os.dwOSVersionInfoSize = sizeof(os);
  const auto rtl_version = Resolve<LONG(WINAPI*)(OSVERSIONINFOW*)>(
      GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
  if (rtl_version == nullptr || rtl_version(reinterpret_cast<OSVERSIONINFOW*>(&os)) != 0) return 1;
  DWORD revision = 0;
  DWORD size = sizeof(revision);
  RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
      L"UBR", RRF_RT_REG_DWORD, nullptr, &revision, &size);

  HMODULE module = LoadLibraryExW(L"processmodel.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
  const auto version = Resolve<HRESULT(WINAPI*)(DWORD, BOOLEAN*, DWORD*)>(
      module, "IsProcessSecurityEnvironmentVersionSupported");
  const auto support = Resolve<HRESULT(WINAPI*)(UINT64*)>(
      module, "QueryProcessSecurityEnvironmentSupport");
  const bool complete = module != nullptr && version != nullptr && support != nullptr &&
      GetProcAddress(module, "CreateProcessSecurityEnvironment") != nullptr &&
      GetProcAddress(module, "CloseProcessSecurityEnvironment") != nullptr;
  BOOLEAN available = FALSE;
  DWORD minor = 0;
  UINT64 flags = 0;
  const HRESULT version_result = version == nullptr ? E_NOTIMPL : version(1, &available, &minor);
  const HRESULT support_result = support == nullptr ? E_NOTIMPL : support(&flags);
  std::cout << std::boolalpha
      << "{\"kind\":\"agentkeeper.psec-host.v1\",\"os\":{\"build\":" << os.dwBuildNumber
      << ",\"revision\":" << revision
      << ",\"workstation\":" << (os.wProductType == VER_NT_WORKSTATION)
      << "},\"psec\":{\"exportsAvailable\":" << complete
      << ",\"versionQuerySucceeded\":" << SUCCEEDED(version_result)
      << ",\"supportQuerySucceeded\":" << SUCCEEDED(support_result)
      << ",\"available\":" << (available != FALSE)
      << ",\"major\":1,\"minor\":" << minor
      << ",\"supportFlags\":\"0x" << std::hex << flags << "\"}}\n";
  if (module != nullptr) FreeLibrary(module);
  return 0;
}

int wmain(int argc, wchar_t** argv) {
  if (argc == 2 && wcscmp(argv[1], L"--host") == 0) return HostReport();
  std::vector<wchar_t> cwd(32768);
  const DWORD length = GetCurrentDirectoryW(static_cast<DWORD>(cwd.size()), cwd.data());
  if (length == 0 || length >= cwd.size()) {
    std::cout << "GetCurrentDirectory error=" << GetLastError() << '\n';
    return 1;
  }
  HANDLE directory = CreateFileW(cwd.data(), 0,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
  if (directory == INVALID_HANDLE_VALUE) {
    std::cout << "CreateFile(cwd, access=0) error=" << GetLastError() << '\n';
    return 1;
  }
  bool opened_name_available = false;
  for (DWORD flags : {DWORD(FILE_NAME_NORMALIZED), DWORD(FILE_NAME_OPENED)}) {
    std::vector<wchar_t> path(32768);
    const DWORD result = GetFinalPathNameByHandleW(directory, path.data(),
        static_cast<DWORD>(path.size()), flags);
    const DWORD error = result == 0 ? GetLastError() : ERROR_SUCCESS;
    std::cout << "GetFinalPathName flags=" << flags << " length=" << result
              << " error=" << error << '\n';
    if (flags == FILE_NAME_OPENED && result > 0 && result < path.size()) {
      opened_name_available = true;
    }
  }
  CloseHandle(directory);
  return opened_name_available ? 0 : 1;
}
