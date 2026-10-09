// Developer-only Win32 metadata probe, executed inside the real PSEC policy.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <iostream>
#include <vector>

int wmain() {
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
