#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif

#include <windows.h>
#include <aclapi.h>
#include <userenv.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cwctype>
#include <fstream>
#include <limits>
#include <map>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "userenv.lib")

namespace {

constexpr std::uint32_t kRequestVersion = 2;
constexpr std::size_t kMaximumRequestBytes = 16U * 1024U * 1024U;
constexpr std::uint32_t kMaximumItems = 100000U;
constexpr char kRequestMagic[] = "AKSBOX01";

constexpr int kRequestInvalid = 200;
constexpr int kProfileFailed = 201;
constexpr int kSidFailed = 202;
constexpr int kAclFailed = 203;
constexpr int kJobFailed = 204;
constexpr int kProcessFailed = 205;
constexpr int kCleanupFailed = 206;
constexpr int kWaitFailed = 207;

std::atomic<HANDLE> g_job{nullptr};

struct Resource {
  bool subtree = false;
  std::wstring path;
};

enum class DeniedAccess : std::uint32_t {
  kRead = 0,
  kWrite = 1,
};

struct DeniedResource {
  bool subtree = false;
  DeniedAccess access = DeniedAccess::kRead;
  std::wstring path;
};

struct Request {
  std::wstring executable;
  std::wstring cwd;
  std::vector<std::wstring> args;
  std::vector<Resource> reads;
  std::vector<Resource> writes;
  std::vector<DeniedResource> denies;
};

struct CaseInsensitiveLess {
  bool operator()(const std::wstring& left, const std::wstring& right) const {
    return _wcsicmp(left.c_str(), right.c_str()) < 0;
  }
};

struct GrantSpec {
  std::wstring path;
  DWORD access = 0;
  bool inherit = false;
};

class LocalAllocation {
 public:
  explicit LocalAllocation(void* value = nullptr) : value_(value) {}
  LocalAllocation(const LocalAllocation&) = delete;
  LocalAllocation& operator=(const LocalAllocation&) = delete;
  ~LocalAllocation() {
    if (value_ != nullptr) LocalFree(value_);
  }
  void** out() { return &value_; }
  void* get() const { return value_; }

 private:
  void* value_;
};

class SidAllocation {
 public:
  SidAllocation() = default;
  SidAllocation(const SidAllocation&) = delete;
  SidAllocation& operator=(const SidAllocation&) = delete;
  ~SidAllocation() {
    if (value_ != nullptr) FreeSid(value_);
  }
  PSID* out() { return &value_; }
  PSID get() const { return value_; }

 private:
  PSID value_ = nullptr;
};

class Handle {
 public:
  explicit Handle(HANDLE value = nullptr) : value_(value) {}
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  ~Handle() {
    if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_);
  }
  HANDLE get() const { return value_; }
  HANDLE release() {
    HANDLE value = value_;
    value_ = nullptr;
    return value;
  }

 private:
  HANDLE value_;
};

class AttributeList {
 public:
  AttributeList() = default;
  AttributeList(const AttributeList&) = delete;
  AttributeList& operator=(const AttributeList&) = delete;
  ~AttributeList() {
    if (list_ != nullptr) {
      DeleteProcThreadAttributeList(list_);
      HeapFree(GetProcessHeap(), 0, list_);
    }
  }

  bool Initialise(DWORD count) {
    SIZE_T bytes = 0;
    InitializeProcThreadAttributeList(nullptr, count, 0, &bytes);
    if (bytes == 0) return false;
    list_ = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes));
    return list_ != nullptr &&
           InitializeProcThreadAttributeList(list_, count, 0, &bytes) != FALSE;
  }

  bool SetSecurityCapabilities(SECURITY_CAPABILITIES* capabilities) {
    return UpdateProcThreadAttribute(
               list_, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
               capabilities, sizeof(*capabilities), nullptr, nullptr) != FALSE;
  }

  LPPROC_THREAD_ATTRIBUTE_LIST get() const { return list_; }

 private:
  LPPROC_THREAD_ATTRIBUTE_LIST list_ = nullptr;
};

bool IsValidUtf8(const std::string& input, std::wstring* output) {
  if (input.find('\0') != std::string::npos) return false;
  if (input.empty()) {
    output->clear();
    return true;
  }
  const int required = MultiByteToWideChar(
      CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()),
      nullptr, 0);
  if (required <= 0) return false;
  output->resize(static_cast<std::size_t>(required));
  return MultiByteToWideChar(
             CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
             static_cast<int>(input.size()), output->data(), required) == required;
}

class Reader {
 public:
  explicit Reader(std::vector<std::uint8_t> bytes) : bytes_(std::move(bytes)) {}

  bool Bytes(std::size_t count, const std::uint8_t** value) {
    if (count > bytes_.size() - offset_) return false;
    *value = bytes_.data() + offset_;
    offset_ += count;
    return true;
  }

  bool Uint32(std::uint32_t* value) {
    const std::uint8_t* raw = nullptr;
    if (!Bytes(4, &raw)) return false;
    *value = static_cast<std::uint32_t>(raw[0]) |
             (static_cast<std::uint32_t>(raw[1]) << 8U) |
             (static_cast<std::uint32_t>(raw[2]) << 16U) |
             (static_cast<std::uint32_t>(raw[3]) << 24U);
    return true;
  }

  bool String(std::wstring* value) {
    std::uint32_t length = 0;
    if (!Uint32(&length) || length > bytes_.size() - offset_ ||
        length > static_cast<std::uint32_t>(std::numeric_limits<int>::max())) {
      return false;
    }
    const std::uint8_t* raw = nullptr;
    if (!Bytes(length, &raw)) return false;
    return IsValidUtf8(
        std::string(reinterpret_cast<const char*>(raw), length), value);
  }

  bool Strings(std::vector<std::wstring>* values) {
    std::uint32_t count = 0;
    if (!Uint32(&count) || count > kMaximumItems) return false;
    values->reserve(count);
    for (std::uint32_t index = 0; index < count; ++index) {
      std::wstring value;
      if (!String(&value)) return false;
      values->push_back(std::move(value));
    }
    return true;
  }

  bool Resources(std::vector<Resource>* values) {
    std::uint32_t count = 0;
    if (!Uint32(&count) || count > kMaximumItems) return false;
    values->reserve(count);
    for (std::uint32_t index = 0; index < count; ++index) {
      std::uint32_t scope = 0;
      Resource value;
      if (!Uint32(&scope) || scope > 1 || !String(&value.path)) return false;
      value.subtree = scope == 1;
      values->push_back(std::move(value));
    }
    return true;
  }

  bool DeniedResources(std::vector<DeniedResource>* values) {
    std::uint32_t count = 0;
    if (!Uint32(&count) || count > kMaximumItems) return false;
    values->reserve(count);
    for (std::uint32_t index = 0; index < count; ++index) {
      std::uint32_t scope = 0;
      std::uint32_t access = 0;
      DeniedResource value;
      if (!Uint32(&scope) || scope > 1 || !Uint32(&access) || access > 1 ||
          !String(&value.path)) {
        return false;
      }
      value.subtree = scope == 1;
      value.access = access == 0 ? DeniedAccess::kRead : DeniedAccess::kWrite;
      values->push_back(std::move(value));
    }
    return true;
  }

  bool Finished() const { return offset_ == bytes_.size(); }

 private:
  std::vector<std::uint8_t> bytes_;
  std::size_t offset_ = 0;
};

bool ReadRequestFile(const std::wstring& path, Request* request) {
  Handle file(CreateFileW(
      path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
  if (file.get() == INVALID_HANDLE_VALUE) return false;

  LARGE_INTEGER size{};
  if (GetFileSizeEx(file.get(), &size) == FALSE || size.QuadPart < 0 ||
      size.QuadPart > static_cast<LONGLONG>(kMaximumRequestBytes)) {
    return false;
  }
  std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size.QuadPart));
  DWORD read = 0;
  if (!bytes.empty() &&
      (ReadFile(file.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &read,
                nullptr) == FALSE ||
       read != static_cast<DWORD>(bytes.size()))) {
    return false;
  }

  Reader reader(std::move(bytes));
  const std::uint8_t* magic = nullptr;
  std::uint32_t version = 0;
  if (!reader.Bytes(8, &magic) ||
      !std::equal(magic, magic + 8, reinterpret_cast<const std::uint8_t*>(kRequestMagic)) ||
      !reader.Uint32(&version) || version != kRequestVersion ||
      !reader.String(&request->executable) || !reader.String(&request->cwd) ||
      !reader.Strings(&request->args) || !reader.Resources(&request->reads) ||
      !reader.Resources(&request->writes) ||
      !reader.DeniedResources(&request->denies) || !reader.Finished()) {
    return false;
  }
  return !request->executable.empty() && !request->cwd.empty();
}

void NativeSeparators(std::wstring* path) {
  std::replace(path->begin(), path->end(), L'/', L'\\');
}

bool IsDriveAbsolute(const std::wstring& path) {
  return path.size() >= 3 && std::iswalpha(path[0]) != 0 && path[1] == L':' &&
         (path[2] == L'\\' || path[2] == L'/') &&
         path.rfind(L"\\\\?\\", 0) != 0 && path.rfind(L"\\??\\", 0) != 0;
}

bool NormaliseRequest(Request* request) {
  NativeSeparators(&request->executable);
  NativeSeparators(&request->cwd);
  if (!IsDriveAbsolute(request->executable) || !IsDriveAbsolute(request->cwd)) return false;
  for (std::vector<Resource>* resources : {&request->reads, &request->writes}) {
    for (auto& entry : *resources) {
      NativeSeparators(&entry.path);
      if (!IsDriveAbsolute(entry.path)) return false;
    }
  }
  for (auto& entry : request->denies) {
    NativeSeparators(&entry.path);
    if (!IsDriveAbsolute(entry.path)) return false;
  }
  return true;
}

std::wstring ParentPath(const std::wstring& input) {
  std::wstring path = input;
  while (path.size() > 3 && path.back() == L'\\') path.pop_back();
  const std::size_t separator = path.find_last_of(L'\\');
  if (separator == std::wstring::npos || separator <= 2) return path.substr(0, 3);
  return path.substr(0, separator);
}

void MergeGrant(
    std::map<std::wstring, GrantSpec, CaseInsensitiveLess>* grants,
    const std::wstring& path, DWORD access, bool inherit) {
  auto [iterator, inserted] = grants->try_emplace(path, GrantSpec{path, access, inherit});
  if (!inserted) {
    iterator->second.access |= access;
    iterator->second.inherit = iterator->second.inherit || inherit;
  }
}

bool BuildAclChanges(
    const Request& request, std::vector<GrantSpec>* grant_output,
    std::vector<GrantSpec>* deny_output) {
  std::map<std::wstring, GrantSpec, CaseInsensitiveLess> grant_map;
  const auto collect = [&grant_map](const Resource& resource, DWORD access) -> bool {
    const DWORD attributes = GetFileAttributesW(resource.path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) return false;
    const bool directory = (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    if (resource.subtree && !directory) return false;

    std::wstring parent = ParentPath(resource.path);
    while (parent.size() > 3) {
      MergeGrant(
          &grant_map, parent, FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
          false);
      const std::wstring next = ParentPath(parent);
      if (_wcsicmp(next.c_str(), parent.c_str()) == 0) break;
      parent = next;
    }
    MergeGrant(&grant_map, resource.path, access, resource.subtree && directory);
    return true;
  };

  for (const auto& resource : request.reads) {
    if (!collect(resource, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE)) return false;
  }
  for (const auto& resource : request.writes) {
    if (!collect(resource, FILE_GENERIC_WRITE | DELETE)) return false;
  }
  grant_output->reserve(grant_map.size());
  for (const auto& [unused, grant] : grant_map) {
    (void)unused;
    grant_output->push_back(grant);
  }

  std::map<std::wstring, GrantSpec, CaseInsensitiveLess> denied;
  for (const auto& resource : request.denies) {
    const DWORD attributes = GetFileAttributesW(resource.path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) return false;
    const bool directory = (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    if (resource.subtree && !directory) return false;
    const DWORD access = resource.access == DeniedAccess::kRead
                             ? FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
                             : FILE_GENERIC_WRITE | DELETE;
    MergeGrant(&denied, resource.path, access, resource.subtree && directory);
  }
  deny_output->reserve(denied.size());
  for (const auto& [unused, deny] : denied) {
    (void)unused;
    deny_output->push_back(deny);
  }
  return true;
}

DWORD ChangeAcl(const GrantSpec& grant, PSID sid, ACCESS_MODE mode) {
  PACL old_acl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  LPWSTR object_name = const_cast<LPWSTR>(grant.path.c_str());
  const DWORD read_result = GetNamedSecurityInfoW(
      object_name, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr,
      nullptr, &old_acl, nullptr, &descriptor);
  if (read_result != ERROR_SUCCESS) return read_result;
  LocalAllocation descriptor_owner(descriptor);

  EXPLICIT_ACCESSW entry{};
  entry.grfAccessPermissions = mode == REVOKE_ACCESS ? 0 : grant.access;
  entry.grfAccessMode = mode;
  entry.grfInheritance =
      grant.inherit ? SUB_CONTAINERS_AND_OBJECTS_INHERIT : NO_INHERITANCE;
  BuildTrusteeWithSidW(&entry.Trustee, sid);

  PACL replacement = nullptr;
  const DWORD merge_result = SetEntriesInAclW(1, &entry, old_acl, &replacement);
  if (merge_result != ERROR_SUCCESS) return merge_result;
  LocalAllocation replacement_owner(replacement);
  return SetNamedSecurityInfoW(
      object_name, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr,
      replacement, nullptr);
}

bool ApplyAclChanges(
    const std::vector<GrantSpec>& changes, PSID sid, ACCESS_MODE mode,
    std::vector<GrantSpec>* applied) {
  applied->reserve(applied->size() + changes.size());
  for (const auto& change : changes) {
    if (ChangeAcl(change, sid, mode) != ERROR_SUCCESS) return false;
    applied->push_back(change);
  }
  return true;
}

bool RevokeAclChanges(const std::vector<GrantSpec>& changes, PSID sid) {
  bool success = true;
  std::map<std::wstring, bool, CaseInsensitiveLess> revoked;
  for (auto iterator = changes.rbegin(); iterator != changes.rend(); ++iterator) {
    if (!revoked.try_emplace(iterator->path, true).second) continue;
    if (ChangeAcl(*iterator, sid, REVOKE_ACCESS) != ERROR_SUCCESS) success = false;
  }
  return success;
}

std::wstring UniqueProfileName(std::uint32_t attempt) {
  FILETIME now{};
  GetSystemTimeAsFileTime(&now);
  ULARGE_INTEGER ticks{};
  ticks.LowPart = now.dwLowDateTime;
  ticks.HighPart = now.dwHighDateTime;
  std::wostringstream name;
  name << L"Agentkeeper." << GetCurrentProcessId() << L'.' << ticks.QuadPart << L'.'
       << attempt;
  return name.str();
}

HRESULT CreateUniqueProfile(std::wstring* name, SidAllocation* sid) {
  for (std::uint32_t attempt = 0; attempt < 8; ++attempt) {
    *name = UniqueProfileName(attempt);
    const HRESULT result = CreateAppContainerProfile(
        name->c_str(), L"agentkeeper isolated process",
        L"Ephemeral agentkeeper sandbox profile", nullptr, 0, sid->out());
    if (result != HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) return result;
  }
  return HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS);
}

std::wstring QuoteArgument(const std::wstring& argument) {
  if (argument.empty()) return L"\"\"";
  if (argument.find_first_of(L" \t\n\v\"") == std::wstring::npos) return argument;

  std::wstring quoted = L"\"";
  std::size_t backslashes = 0;
  for (const wchar_t character : argument) {
    if (character == L'\\') {
      ++backslashes;
      continue;
    }
    if (character == L'\"') {
      quoted.append(backslashes * 2 + 1, L'\\');
      quoted.push_back(L'\"');
      backslashes = 0;
      continue;
    }
    quoted.append(backslashes, L'\\');
    backslashes = 0;
    quoted.push_back(character);
  }
  quoted.append(backslashes * 2, L'\\');
  quoted.push_back(L'\"');
  return quoted;
}

std::vector<wchar_t> CommandLine(const Request& request) {
  std::wstring value = QuoteArgument(request.executable);
  for (const auto& argument : request.args) {
    value.push_back(L' ');
    value.append(QuoteArgument(argument));
  }
  value.push_back(L'\0');
  return std::vector<wchar_t>(value.begin(), value.end());
}

BOOL WINAPI ConsoleControlHandler(DWORD event) {
  if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT &&
      event != CTRL_CLOSE_EVENT && event != CTRL_LOGOFF_EVENT &&
      event != CTRL_SHUTDOWN_EVENT) {
    return FALSE;
  }
  const HANDLE job = g_job.load();
  if (job != nullptr) TerminateJobObject(job, ERROR_CANCELLED);
  return TRUE;
}

bool TerminateAndDrainJob(HANDLE job, DWORD exit_code) {
  if (TerminateJobObject(job, exit_code) == FALSE) return false;
  for (std::uint32_t attempt = 0; attempt < 500; ++attempt) {
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting{};
    if (QueryInformationJobObject(
            job, JobObjectBasicAccountingInformation, &accounting,
            sizeof(accounting), nullptr) == FALSE) {
      return false;
    }
    if (accounting.ActiveProcesses == 0) return true;
    Sleep(10);
  }
  return false;
}

bool Cleanup(
    const std::vector<GrantSpec>& changes, PSID sid,
    const std::wstring& profile_name) {
  const bool acl_clean = RevokeAclChanges(changes, sid);
  const HRESULT deleted = DeleteAppContainerProfile(profile_name.c_str());
  return acl_clean && SUCCEEDED(deleted);
}

int Diagnose() {
  std::wstring profile_name;
  SidAllocation sid;
  const HRESULT created = CreateUniqueProfile(&profile_name, &sid);
  if (FAILED(created)) return kProfileFailed;
  if (sid.get() == nullptr || IsValidSid(sid.get()) == FALSE) {
    DeleteAppContainerProfile(profile_name.c_str());
    return kSidFailed;
  }
  return SUCCEEDED(DeleteAppContainerProfile(profile_name.c_str())) ? 0 : kCleanupFailed;
}

int Launch(const std::wstring& request_path) {
  Request request;
  if (!ReadRequestFile(request_path, &request) || !NormaliseRequest(&request)) {
    DeleteFileW(request_path.c_str());
    return kRequestInvalid;
  }
  // The request may contain command-line arguments. Remove it before the
  // untrusted child starts so it cannot inventory launcher inputs.
  if (DeleteFileW(request_path.c_str()) == FALSE) return kRequestInvalid;

  std::wstring profile_name;
  SidAllocation sid;
  const HRESULT profile_result = CreateUniqueProfile(&profile_name, &sid);
  if (FAILED(profile_result)) return kProfileFailed;
  if (sid.get() == nullptr || IsValidSid(sid.get()) == FALSE) {
    DeleteAppContainerProfile(profile_name.c_str());
    return kSidFailed;
  }

  std::vector<GrantSpec> desired_grants;
  std::vector<GrantSpec> desired_denies;
  std::vector<GrantSpec> applied_changes;
  if (!BuildAclChanges(request, &desired_grants, &desired_denies) ||
      !ApplyAclChanges(
          desired_grants, sid.get(), GRANT_ACCESS, &applied_changes) ||
      !ApplyAclChanges(
          desired_denies, sid.get(), DENY_ACCESS, &applied_changes)) {
    const bool cleaned = Cleanup(applied_changes, sid.get(), profile_name);
    return cleaned ? kAclFailed : kCleanupFailed;
  }

  SECURITY_CAPABILITIES capabilities{};
  capabilities.AppContainerSid = sid.get();
  // Deliberately zero capabilities: no internetClient/privateNetworkClientServer
  // capability means network is denied by the AppContainer token.
  capabilities.Capabilities = nullptr;
  capabilities.CapabilityCount = 0;
  capabilities.Reserved = 0;

  AttributeList attributes;
  if (!attributes.Initialise(1) || !attributes.SetSecurityCapabilities(&capabilities)) {
    const bool cleaned = Cleanup(applied_changes, sid.get(), profile_name);
    return cleaned ? kProcessFailed : kCleanupFailed;
  }

  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.lpAttributeList = attributes.get();
  PROCESS_INFORMATION process{};
  std::vector<wchar_t> command_line = CommandLine(request);

  // FALSE is a security invariant: the child receives no launcher handles.
  // Console attachment is inherited by the Windows process model, not by a
  // broad HANDLE inheritance set.
  const BOOL created = CreateProcessW(
      request.executable.c_str(), command_line.data(), nullptr, nullptr, FALSE,
      CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT |
          EXTENDED_STARTUPINFO_PRESENT,
      nullptr, request.cwd.c_str(), &startup.StartupInfo, &process);
  if (created == FALSE) {
    const bool cleaned = Cleanup(applied_changes, sid.get(), profile_name);
    return cleaned ? kProcessFailed : kCleanupFailed;
  }
  Handle process_handle(process.hProcess);
  Handle thread_handle(process.hThread);

  Handle job(CreateJobObjectW(nullptr, nullptr));
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limits{};
  job_limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (job.get() == nullptr ||
      SetInformationJobObject(
          job.get(), JobObjectExtendedLimitInformation, &job_limits,
          sizeof(job_limits)) == FALSE ||
      AssignProcessToJobObject(job.get(), process_handle.get()) == FALSE) {
    TerminateProcess(process_handle.get(), ERROR_ACCESS_DENIED);
    WaitForSingleObject(process_handle.get(), INFINITE);
    const bool cleaned = Cleanup(applied_changes, sid.get(), profile_name);
    return cleaned ? kJobFailed : kCleanupFailed;
  }

  g_job.store(job.get());
  if (SetConsoleCtrlHandler(ConsoleControlHandler, TRUE) == FALSE) {
    TerminateAndDrainJob(job.get(), ERROR_ACCESS_DENIED);
    g_job.store(nullptr);
    const bool cleaned = Cleanup(applied_changes, sid.get(), profile_name);
    return cleaned ? kJobFailed : kCleanupFailed;
  }
  if (ResumeThread(thread_handle.get()) == static_cast<DWORD>(-1)) {
    TerminateAndDrainJob(job.get(), ERROR_ACCESS_DENIED);
    g_job.store(nullptr);
    SetConsoleCtrlHandler(ConsoleControlHandler, FALSE);
    const bool cleaned = Cleanup(applied_changes, sid.get(), profile_name);
    return cleaned ? kProcessFailed : kCleanupFailed;
  }

  const DWORD waited = WaitForSingleObject(process_handle.get(), INFINITE);
  DWORD child_exit = 1;
  const bool observed =
      waited == WAIT_OBJECT_0 && GetExitCodeProcess(process_handle.get(), &child_exit) != FALSE;
  const bool process_tree_stopped =
      TerminateAndDrainJob(job.get(), observed ? child_exit : ERROR_PROCESS_ABORTED);
  g_job.store(nullptr);
  SetConsoleCtrlHandler(ConsoleControlHandler, FALSE);

  const bool cleaned = Cleanup(applied_changes, sid.get(), profile_name);
  if (!cleaned) return kCleanupFailed;
  if (!observed || !process_tree_stopped) return kWaitFailed;
  return static_cast<int>(child_exit);
}

}  // namespace

int wmain(int argc, wchar_t* argv[]) {
  if (argc == 2 && wcscmp(argv[1], L"--diagnose") == 0) return Diagnose();
  if (argc == 3 && wcscmp(argv[1], L"--request") == 0) return Launch(argv[2]);
  return kRequestInvalid;
}
