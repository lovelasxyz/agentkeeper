#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
// windows.h defines function-like `min`/`max` macros that collide with
// `std::numeric_limits<T>::max()`. WIN32_LEAN_AND_MEAN does not suppress them.
#define NOMINMAX
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif

#include <windows.h>
#include <aclapi.h>
#include <userenv.h>
#include "windows-path-safety.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cwctype>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <cstdio>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "userenv.lib")

namespace {

constexpr std::uint32_t kRequestVersion = 3;
constexpr std::size_t kMaximumRequestBytes = 16U * 1024U * 1024U;
constexpr std::uint32_t kMaximumItems = 100000U;
constexpr char kRequestMagic[] = "AKSBOX01";
constexpr char kResultMagic[] = "AKSRES01";

constexpr int kRequestInvalid = 200;
constexpr int kProfileFailed = 201;
constexpr int kSidFailed = 202;
constexpr int kAclFailed = 203;
constexpr int kJobFailed = 204;
constexpr int kProcessFailed = 205;
constexpr int kCleanupFailed = 206;
constexpr int kWaitFailed = 207;
// A launcher probe bounds its run; a hung child is reported, never waited on.
constexpr int kChildTimedOut = 208;
constexpr int kResultFailed = 209;
constexpr int kUnsafePath = 210;

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
  /** Milliseconds the child may run; 0 means an unbounded agent session. */
  std::uint32_t timeout_ms = 0;
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
  // The validated object, rather than its mutable name, owns every ACL change
  // and rollback. Roots remain pinned until cleanup has completed.
  std::shared_ptr<class Handle> object;
  bool already_readable = false;
};

struct NativeResult {
  std::uint32_t error;
  std::uint32_t child_exit = 0;
  NativeResult(int native_error) : error(static_cast<std::uint32_t>(native_error)) {}
  static NativeResult Child(DWORD code) {
    NativeResult result(0);
    result.child_exit = code;
    return result;
  }
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

class AclMutationGuard {
 public:
  AclMutationGuard() : mutex_(CreateMutexW(nullptr, FALSE, L"Local\\Agentkeeper.AclMutation.v1")) {}
  ~AclMutationGuard() { if (locked_) ReleaseMutex(mutex_.get()); }
  bool Lock() {
    if (mutex_.get() == nullptr) return false;
    const DWORD waited = WaitForSingleObject(mutex_.get(), 60000);
    locked_ = waited == WAIT_OBJECT_0 || waited == WAIT_ABANDONED;
    // An abandoned writer may have stopped halfway through propagation.
    // Do not call that a successful security transition.
    return waited == WAIT_OBJECT_0;
  }
  void Unlock() {
    if (locked_) {
      ReleaseMutex(mutex_.get());
      locked_ = false;
    }
  }

 private:
  Handle mutex_;
  bool locked_ = false;
};

class AttributeList {
 public:
  AttributeList() = default;
  AttributeList(const AttributeList&) = delete;
  AttributeList& operator=(const AttributeList&) = delete;
  ~AttributeList() {
    if (list_ != nullptr) {
      if (initialised_) DeleteProcThreadAttributeList(list_);
      HeapFree(GetProcessHeap(), 0, list_);
    }
  }

  bool Initialise(DWORD count) {
    SIZE_T bytes = 0;
    InitializeProcThreadAttributeList(nullptr, count, 0, &bytes);
    if (bytes == 0) return false;
    list_ = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes));
    initialised_ = list_ != nullptr &&
                   InitializeProcThreadAttributeList(list_, count, 0, &bytes) != FALSE;
    return initialised_;
  }

  bool SetSecurityCapabilities(SECURITY_CAPABILITIES* capabilities) {
    return UpdateProcThreadAttribute(
               list_, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
               capabilities, sizeof(*capabilities), nullptr, nullptr) != FALSE;
  }

  bool SetHandleList(HANDLE* handles, std::size_t count) {
    return UpdateProcThreadAttribute(list_, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        handles, count * sizeof(HANDLE), nullptr, nullptr) != FALSE;
  }

  LPPROC_THREAD_ATTRIBUTE_LIST get() const { return list_; }

 private:
  LPPROC_THREAD_ATTRIBUTE_LIST list_ = nullptr;
  bool initialised_ = false;
};

class StandardStreams {
 public:
  ~StandardStreams() {
    for (const HANDLE handle : handles_) {
      if (handle != nullptr && handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
    }
  }
  StandardStreams() = default;
  StandardStreams(const StandardStreams&) = delete;
  StandardStreams& operator=(const StandardStreams&) = delete;

  bool Initialise() {
    const DWORD names[] = {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE};
    for (std::size_t index = 0; index < 3; ++index) {
      const HANDLE original = GetStdHandle(names[index]);
      if (original != nullptr && original != INVALID_HANDLE_VALUE) {
        if (!DuplicateHandle(GetCurrentProcess(), original, GetCurrentProcess(),
            &handles_[index], 0, TRUE, DUPLICATE_SAME_ACCESS)) return false;
      } else {
        SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
        handles_[index] = CreateFileW(L"NUL", index == 0 ? GENERIC_READ : GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0, nullptr);
        if (handles_[index] == INVALID_HANDLE_VALUE) return false;
      }
    }
    return true;
  }
  bool Attach(AttributeList* attributes, STARTUPINFOEXW* startup) {
    startup->StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
    startup->StartupInfo.hStdInput = handles_[0];
    startup->StartupInfo.hStdOutput = handles_[1];
    startup->StartupInfo.hStdError = handles_[2];
    return attributes->SetHandleList(handles_, 3);
  }

 private:
  HANDLE handles_[3]{};
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
      !reader.Uint32(&request->timeout_ms) ||
      !reader.String(&request->executable) || !reader.String(&request->cwd) ||
      !reader.Strings(&request->args) || !reader.Resources(&request->reads) ||
      !reader.Resources(&request->writes) ||
      !reader.DeniedResources(&request->denies) || !reader.Finished()) {
    return false;
  }
  return request->timeout_ms != INFINITE &&
         !request->executable.empty() && !request->cwd.empty();
}

void NativeSeparators(std::wstring* path) {
  std::replace(path->begin(), path->end(), L'/', L'\\');
}

bool NormaliseRequest(Request* request) {
  NativeSeparators(&request->executable);
  NativeSeparators(&request->cwd);
  if (!agentkeeper::IsSafeWindowsPath(request->executable) ||
      !agentkeeper::IsSafeWindowsPath(request->cwd)) return false;
  for (std::vector<Resource>* resources : {&request->reads, &request->writes}) {
    for (auto& entry : *resources) {
      NativeSeparators(&entry.path);
      if (!agentkeeper::IsSafeWindowsPath(entry.path)) return false;
    }
  }
  for (auto& entry : request->denies) {
    NativeSeparators(&entry.path);
    if (!agentkeeper::IsSafeWindowsPath(entry.path)) return false;
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
  auto [iterator, inserted] = grants->try_emplace(path, GrantSpec{path, access, inherit, nullptr, false});
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

    // Do not mutate C:\\Users or Program Files just to traverse ancestors.
    // The AppContainer token retains Windows' bypass-traverse privilege;
    // capabilities belong only to the explicitly granted object/subtree.
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

using ObjectPins = std::map<std::wstring, std::shared_ptr<Handle>, CaseInsensitiveLess>;
constexpr std::size_t kMaximumAclObjects = 100000;
constexpr std::size_t kMaximumAclDepth = 128;

bool PinSafeObject(const std::wstring& path, ObjectPins* pins, bool* directory) {
  auto existing = pins->find(path);
  if (existing != pins->end()) {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(existing->second->get(), &info)) return false;
    *directory = (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    return true;
  }
  if (pins->size() >= kMaximumAclObjects) return false;
  auto object = std::make_shared<Handle>(CreateFileW(
      path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
      nullptr, OPEN_EXISTING,
      FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
  if (object->get() == INVALID_HANDLE_VALUE) return false;
  BY_HANDLE_FILE_INFORMATION info{};
  if (!GetFileInformationByHandle(object->get(), &info) ||
      (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) return false;
  *directory = (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
  // NTFS ACLs belong to the file object, shared by all hardlink names. An
  // inherited package grant here would also grant any outside alias.
  if (!*directory && info.nNumberOfLinks != 1) return false;
  pins->emplace(path, std::move(object));
  return true;
}

bool PinSafeAncestors(const std::wstring& path, ObjectPins* pins) {
  for (std::wstring parent = ParentPath(path);;) {
    bool directory = false;
    if (!PinSafeObject(parent, pins, &directory) || !directory) return false;
    if (parent.size() == 3) return true;
    parent = ParentPath(parent);
  }
}

bool PinSafeTree(
    const std::wstring& path, bool subtree, std::size_t depth, ObjectPins* pins) {
  if (depth > kMaximumAclDepth) return false;
  bool directory = false;
  if (!PinSafeObject(path, pins, &directory)) return false;
  if (!subtree) return true;
  if (!directory) return false;
  WIN32_FIND_DATAW found{};
  const std::wstring pattern = path + (path.back() == L'\\' ? L"*" : L"\\*");
  const HANDLE search = FindFirstFileW(pattern.c_str(), &found);
  if (search == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_FILE_NOT_FOUND;
  bool success = true;
  do {
    if (wcscmp(found.cFileName, L".") == 0 || wcscmp(found.cFileName, L"..") == 0) continue;
    const std::wstring child = path + (path.back() == L'\\' ? L"" : L"\\") + found.cFileName;
    if (!agentkeeper::IsSafeWindowsPath(child) ||
        !PinSafeTree(child, (found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0,
                     depth + 1, pins)) {
      success = false;
      break;
    }
  } while (FindNextFileW(search, &found));
  if (success && GetLastError() != ERROR_NO_MORE_FILES) success = false;
  FindClose(search);
  return success;
}

bool ValidateAclObjects(
    const Request& request, const std::vector<GrantSpec>& grants,
    const std::vector<GrantSpec>& denies, ObjectPins* pins) {
  if (!PinSafeAncestors(request.executable, pins) ||
      !PinSafeTree(request.executable, false, 0, pins) ||
      !PinSafeAncestors(request.cwd, pins) || !PinSafeTree(request.cwd, false, 0, pins)) return false;
  for (const auto* changes : {&grants, &denies}) {
    for (const auto& change : *changes) {
      if (!PinSafeAncestors(change.path, pins) ||
          !PinSafeTree(change.path, change.inherit, 0, pins)) return false;
    }
  }
  return true;
}

bool HasCommonReadAccess(HANDLE object, DWORD requested) {
  // Program Files/system runtimes often already grant ALL APPLICATION
  // PACKAGES read/execute. Requiring WRITE_DAC there would need elevation
  // just to add a redundant ACE. This optimisation only skips a mutation;
  // an effective-token denial can still fail the subsequent canary safely.
  if ((requested & ~(FILE_GENERIC_READ | FILE_GENERIC_EXECUTE)) != 0) return false;
  std::vector<BYTE> common_sid(SECURITY_MAX_SID_SIZE);
  DWORD sid_size = static_cast<DWORD>(common_sid.size());
  if (!CreateWellKnownSid(WinBuiltinAnyPackageSid, nullptr, common_sid.data(), &sid_size)) return false;
  PACL acl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (GetSecurityInfo(object, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
      nullptr, nullptr, &acl, nullptr, &descriptor) != ERROR_SUCCESS) return false;
  LocalAllocation descriptor_owner(descriptor);
  if (acl == nullptr) return false;
  DWORD allowed = 0;
  GENERIC_MAPPING mapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
  for (DWORD index = 0; index < acl->AceCount; ++index) {
    void* raw = nullptr;
    if (!GetAce(acl, index, &raw)) return false;
    const auto* header = static_cast<ACE_HEADER*>(raw);
    if ((header->AceFlags & INHERIT_ONLY_ACE) != 0) continue;
    // Unknown/object/conditional ACEs need a real token access check; refuse
    // the shortcut rather than interpreting a richer ACL as a plain allow.
    if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) return false;
    auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
    if (!EqualSid(&ace->SidStart, common_sid.data())) continue;
    DWORD mask = ace->Mask;
    MapGenericMask(&mask, &mapping);
    allowed |= mask;
  }
  return (allowed & requested) == requested;
}

bool OpenAclObjects(std::vector<GrantSpec>* changes, bool allow_common_read) {
  for (auto& change : *changes) {
    if (allow_common_read) {
      auto readable = std::make_shared<Handle>(CreateFileW(
          change.path.c_str(), READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE,
          nullptr, OPEN_EXISTING,
          FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
      if (readable->get() != INVALID_HANDLE_VALUE &&
          HasCommonReadAccess(readable->get(), change.access)) {
        change.object = std::move(readable);
        change.already_readable = true;
        continue;
      }
    }
    change.object = std::make_shared<Handle>(CreateFileW(
        change.path.c_str(), READ_CONTROL | WRITE_DAC, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    if (change.object->get() == INVALID_HANDLE_VALUE) return false;
  }
  return true;
}

DWORD ChangeAcl(const GrantSpec& grant, PSID sid, ACCESS_MODE mode) {
  PACL old_acl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  const DWORD read_result = GetSecurityInfo(
      grant.object->get(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr,
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
  return SetSecurityInfo(
      grant.object->get(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr,
      replacement, nullptr);
}

bool ApplyAclChanges(
    const std::vector<GrantSpec>& changes, PSID sid, ACCESS_MODE mode,
    std::vector<GrantSpec>* applied) {
  applied->reserve(applied->size() + changes.size());
  for (const auto& change : changes) {
    if (change.already_readable) continue;
    // SetSecurityInfo can update the root before propagation fails. Register
    // rollback first, so a partially successful mutation is never forgotten.
    applied->push_back(change);
    const DWORD result = ChangeAcl(change, sid, mode);
    if (result != ERROR_SUCCESS) {
      SetLastError(result);
      return false;
    }
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
  // GetSecurityInfo + SetSecurityInfo is a read/modify/write transaction.
  // Concurrent sessions must not overwrite each other's package ACEs.
  AclMutationGuard mutation;
  const bool acl_clean = changes.empty() || (mutation.Lock() && RevokeAclChanges(changes, sid));
  mutation.Unlock();
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

NativeResult Launch(const std::wstring& request_path) {
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
  if (!BuildAclChanges(request, &desired_grants, &desired_denies)) {
    const bool cleaned = Cleanup(applied_changes, sid.get(), profile_name);
    return cleaned ? kAclFailed : kCleanupFailed;
  }
  ObjectPins topology_pins;
  if (!ValidateAclObjects(request, desired_grants, desired_denies, &topology_pins)) {
    std::fwprintf(stderr, L"agentkeeper sandbox: stage=path-validation win32=%lu\n", GetLastError());
    const bool cleaned = Cleanup(applied_changes, sid.get(), profile_name);
    return cleaned ? kUnsafePath : kCleanupFailed;
  }
  AclMutationGuard mutation;
  if (!mutation.Lock() ||
      !OpenAclObjects(&desired_grants, true) || !OpenAclObjects(&desired_denies, false) ||
      !ApplyAclChanges(
          desired_grants, sid.get(), GRANT_ACCESS, &applied_changes) ||
      !ApplyAclChanges(
          desired_denies, sid.get(), DENY_ACCESS, &applied_changes)) {
    std::fwprintf(stderr, L"agentkeeper sandbox: stage=acl-setup win32=%lu\n", GetLastError());
    const bool cleaned = Cleanup(applied_changes, sid.get(), profile_name);
    return cleaned ? kAclFailed : kCleanupFailed;
  }
  mutation.Unlock();

  SECURITY_CAPABILITIES capabilities{};
  capabilities.AppContainerSid = sid.get();
  // Deliberately zero capabilities: no internetClient/privateNetworkClientServer
  // capability means network is denied by the AppContainer token.
  capabilities.Capabilities = nullptr;
  capabilities.CapabilityCount = 0;
  capabilities.Reserved = 0;

  StandardStreams streams;
  AttributeList attributes;
  if (!attributes.Initialise(2) || !attributes.SetSecurityCapabilities(&capabilities) ||
      !streams.Initialise()) {
    const bool cleaned = Cleanup(applied_changes, sid.get(), profile_name);
    return cleaned ? kProcessFailed : kCleanupFailed;
  }

  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.lpAttributeList = attributes.get();
  if (!streams.Attach(&attributes, &startup)) {
    const bool cleaned = Cleanup(applied_changes, sid.get(), profile_name);
    return cleaned ? kProcessFailed : kCleanupFailed;
  }
  PROCESS_INFORMATION process{};
  std::vector<wchar_t> command_line = CommandLine(request);

  // SystemRoot is needed by Windows runtime/child creation and is not an
  // ambient authority the caller may forge. Obtain it from the OS itself.
  wchar_t windows_directory[MAX_PATH + 1]{};
  const UINT windows_length = GetWindowsDirectoryW(windows_directory, MAX_PATH + 1);
  if (windows_length == 0 || windows_length > MAX_PATH ||
      !SetEnvironmentVariableW(L"SystemRoot", windows_directory) ||
      !SetEnvironmentVariableW(L"WINDIR", windows_directory)) {
    const bool cleaned = Cleanup(applied_changes, sid.get(), profile_name);
    return cleaned ? kProcessFailed : kCleanupFailed;
  }

  // TRUE is required by HANDLE_LIST, which whitelists exactly three stream
  // duplicates. ACL handles, the request, the result and Job never cross the
  // boundary. Explicit stdio also works with redirected/CI pipes: a child
  // cannot assume the launching Node process has an attached console.
  const BOOL created = CreateProcessW(
      request.executable.c_str(), command_line.data(), nullptr, nullptr, TRUE,
      CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT |
          EXTENDED_STARTUPINFO_PRESENT,
      nullptr, request.cwd.c_str(), &startup.StartupInfo, &process);
  if (created == FALSE) {
    std::fwprintf(stderr, L"agentkeeper sandbox: stage=create-process win32=%lu\n", GetLastError());
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
    const bool stopped = TerminateProcess(process_handle.get(), ERROR_ACCESS_DENIED) != FALSE &&
        WaitForSingleObject(process_handle.get(), 5000) == WAIT_OBJECT_0;
    const bool cleaned = Cleanup(applied_changes, sid.get(), profile_name);
    if (!cleaned) return kCleanupFailed;
    return stopped ? kJobFailed : kWaitFailed;
  }

  g_job.store(job.get());
  if (SetConsoleCtrlHandler(ConsoleControlHandler, TRUE) == FALSE) {
    const bool stopped = TerminateAndDrainJob(job.get(), ERROR_ACCESS_DENIED);
    g_job.store(nullptr);
    const bool cleaned = Cleanup(applied_changes, sid.get(), profile_name);
    if (!cleaned) return kCleanupFailed;
    return stopped ? kJobFailed : kWaitFailed;
  }
  // The untrusted process has not run yet. Descendant locks covered ACL
  // propagation; release them now so ordinary workspace edits can rename
  // files. Grant/deny roots retain their handles for object-based rollback.
  topology_pins.clear();
  if (ResumeThread(thread_handle.get()) == static_cast<DWORD>(-1)) {
    const bool stopped = TerminateAndDrainJob(job.get(), ERROR_ACCESS_DENIED);
    g_job.store(nullptr);
    SetConsoleCtrlHandler(ConsoleControlHandler, FALSE);
    const bool cleaned = Cleanup(applied_changes, sid.get(), profile_name);
    if (!cleaned) return kCleanupFailed;
    return stopped ? kProcessFailed : kWaitFailed;
  }

  // Zero means "as long as the user needs": an agent session has no deadline.
  // A probe supplies one, so a child that never exits is reported instead of
  // holding the launcher — and the tree is reclaimed here, by the process that
  // owns the Job, rather than left for someone else to notice.
  const DWORD budget = request.timeout_ms == 0 ? INFINITE : request.timeout_ms;
  const DWORD waited = WaitForSingleObject(process_handle.get(), budget);
  if (waited == WAIT_TIMEOUT) {
    const bool stopped = TerminateAndDrainJob(job.get(), ERROR_TIMEOUT);
    g_job.store(nullptr);
    SetConsoleCtrlHandler(ConsoleControlHandler, FALSE);
    const bool timed_out_cleaned = Cleanup(applied_changes, sid.get(), profile_name);
    if (!timed_out_cleaned) return kCleanupFailed;
    return stopped ? kChildTimedOut : kWaitFailed;
  }
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
  return NativeResult::Child(child_exit);
}

bool WriteResult(HANDLE file, const NativeResult& result) {
  std::uint8_t bytes[16]{};
  std::copy(kResultMagic, kResultMagic + 8, bytes);
  for (std::uint32_t index = 0; index < 4; ++index) {
    bytes[8 + index] = static_cast<std::uint8_t>(result.error >> (index * 8));
    bytes[12 + index] = static_cast<std::uint8_t>(result.child_exit >> (index * 8));
  }
  DWORD written = 0;
  return WriteFile(file, bytes, sizeof(bytes), &written, nullptr) != FALSE &&
         written == sizeof(bytes) && FlushFileBuffers(file) != FALSE;
}

}  // namespace

int wmain(int argc, wchar_t* argv[]) {
  if (argc == 2 && wcscmp(argv[1], L"--diagnose") == 0) return Diagnose();
  if (argc == 5 && wcscmp(argv[1], L"--request") == 0 && wcscmp(argv[3], L"--result") == 0) {
    std::wstring result_path(argv[4]);
    NativeSeparators(&result_path);
    if (!agentkeeper::IsSafeWindowsPath(result_path)) return kResultFailed;
    // Keep the result's namespace pinned too: an open file alone must not
    // let an agent rename its parent and substitute another path for Node.
    ObjectPins result_namespace;
    if (!PinSafeAncestors(result_path, &result_namespace)) return kResultFailed;
    // CREATE_NEW rejects pre-existing aliases. No write/delete sharing and no
    // inheritance: even a broad policy cannot let the confined child forge
    // the launcher result. Launch drains the Job before this handle closes.
    Handle result_file(CreateFileW(result_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
        nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (result_file.get() == INVALID_HANDLE_VALUE) return kResultFailed;
    const NativeResult result = Launch(argv[2]);
    return WriteResult(result_file.get(), result) ? 0 : kResultFailed;
  }
  return kRequestInvalid;
}
