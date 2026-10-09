// Developer-only experiment. This is neither a fallback nor an npm artifact.
// Reuse the candidate's object validation, ACL rollback and Job lifetime code.
#define wmain agentkeeper_legacy_main
#include "../../native/windows/agentkeeper-sandbox.cpp"
#undef wmain
#include <sddl.h>
#include <winternl.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "bcrypt.lib")

namespace {
struct KernelGrant {
  std::shared_ptr<Handle> object;
  SE_OBJECT_TYPE type;
};

DWORD ChangeObjectAcl(HANDLE object, SE_OBJECT_TYPE type, PSID sid,
                      DWORD rights, ACCESS_MODE mode) {
  PACL old_acl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  DWORD result = GetSecurityInfo(object, type, DACL_SECURITY_INFORMATION,
      nullptr, nullptr, &old_acl, nullptr, &descriptor);
  if (result != ERROR_SUCCESS) return result;
  LocalAllocation descriptor_owner(descriptor);
  // A null DACL is already unrestricted. Refuse to silently replace it.
  if (old_acl == nullptr) return ERROR_INVALID_ACL;
  EXPLICIT_ACCESSW entry{};
  entry.grfAccessPermissions = rights;
  entry.grfAccessMode = mode;
  BuildTrusteeWithSidW(&entry.Trustee, sid);
  PACL replacement = nullptr;
  result = SetEntriesInAclW(1, &entry, old_acl, &replacement);
  if (result != ERROR_SUCCESS) return result;
  LocalAllocation replacement_owner(replacement);
  // SetSecurityInfo automatically walks filesystem descendants. Metadata-only
  // ancestor grants must change exactly this object, never walk a whole drive.
  SECURITY_DESCRIPTOR update{};
  if (!InitializeSecurityDescriptor(&update, SECURITY_DESCRIPTOR_REVISION) ||
      !SetSecurityDescriptorDacl(&update, TRUE, replacement, FALSE)) return GetLastError();
  using SetNtSecurity = NTSTATUS(NTAPI*)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
  const auto set = reinterpret_cast<SetNtSecurity>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                                                 "NtSetSecurityObject"));
  if (!set) return ERROR_PROC_NOT_FOUND;
  const NTSTATUS status = set(object, DACL_SECURITY_INFORMATION, &update);
  if (status < 0) {
    std::fprintf(stderr, "restricted probe: object ACL status=0x%lx\n", static_cast<unsigned long>(status));
    return ERROR_ACCESS_DENIED;
  }
  return ERROR_SUCCESS;
}

class KernelGrants {
 public:
  explicit KernelGrants(PSID sid) : sid_(sid) {}
  ~KernelGrants() { if (!closed_) Close(); }
  bool Add(HANDLE object, SE_OBJECT_TYPE type, DWORD rights) {
    if (object == nullptr || object == INVALID_HANDLE_VALUE) return false;
    auto owner = std::make_shared<Handle>(object);
    grants_.push_back({owner, type});
    const DWORD result = ChangeObjectAcl(object, type, sid_, rights, GRANT_ACCESS);
    if (result != ERROR_SUCCESS) { SetLastError(result); return false; }
    return true;
  }
  bool Close() {
    bool success = true;
    for (auto it = grants_.rbegin(); it != grants_.rend(); ++it) {
      if (ChangeObjectAcl(it->object->get(), it->type, sid_, 0, REVOKE_ACCESS)
          != ERROR_SUCCESS) success = false;
    }
    grants_.clear();
    closed_ = true;
    return success;
  }
 private:
  PSID sid_;
  bool closed_ = false;
  std::vector<KernelGrant> grants_;
};

using OpenNtObject = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
HANDLE OpenNamespaceObject(const wchar_t* path, bool directory) {
  const auto library = GetModuleHandleW(L"ntdll.dll");
  const auto open = reinterpret_cast<OpenNtObject>(GetProcAddress(library,
      directory ? "NtOpenDirectoryObject" : "NtOpenSymbolicLinkObject"));
  if (!open) return nullptr;
  UNICODE_STRING name{};
  name.Buffer = const_cast<PWSTR>(path);
  name.Length = static_cast<USHORT>(wcslen(path) * sizeof(wchar_t));
  name.MaximumLength = name.Length;
  OBJECT_ATTRIBUTES attributes{};
  attributes.Length = sizeof(attributes);
  attributes.ObjectName = &name;
  attributes.Attributes = 0x40; // OBJ_CASE_INSENSITIVE
  HANDLE result = nullptr;
  const NTSTATUS status = open(&result, READ_CONTROL | WRITE_DAC, &attributes);
  if (status < 0) {
    std::fwprintf(stderr, L"restricted probe: namespace=%ls status=0x%lx\n", path,
                  static_cast<unsigned long>(status));
    return nullptr;
  }
  return result;
}

bool GrantMetadata(KernelGrants* grants, const Request& request) {
  // These are object-namespace metadata capabilities, not recursive C:\ reads.
  if (!grants->Add(OpenNamespaceObject(L"\\GLOBAL??", true), SE_KERNEL_OBJECT,
                    READ_CONTROL | 1 | 2) ||
      !grants->Add(OpenNamespaceObject(L"\\GLOBAL??\\MountPointManager", false),
                    SE_KERNEL_OBJECT, READ_CONTROL | 1)) return false;
  std::vector<wchar_t> drives;
  for (const auto* path : {&request.cwd, &request.executable}) {
    const wchar_t drive = towupper((*path)[0]);
    if (std::find(drives.begin(), drives.end(), drive) == drives.end()) drives.push_back(drive);
  }
  for (const auto& resource : request.reads) {
    const wchar_t drive = towupper(resource.path[0]);
    if (std::find(drives.begin(), drives.end(), drive) == drives.end()) drives.push_back(drive);
  }
  for (const wchar_t drive : drives) {
    std::wstring name = L"\\GLOBAL??\\";
    name.push_back(drive); name.push_back(L':');
    if (!grants->Add(OpenNamespaceObject(name.c_str(), false), SE_KERNEL_OBJECT,
                      READ_CONTROL | 1)) return false;
  }
  return grants->Add(CreateFileW(L"\\\\.\\MountPointManager", READ_CONTROL | WRITE_DAC,
      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr),
      SE_FILE_OBJECT, FILE_GENERIC_READ);
}

class PrivateDesktop {
 public:
  ~PrivateDesktop() {
    if (desktop_) CloseDesktop(desktop_);
    if (station_) CloseWindowStation(station_);
  }
  bool Initialise(PSID user, PSID restricted, const std::wstring& suffix) {
    LPWSTR user_string = nullptr;
    LPWSTR restricted_string = nullptr;
    if (!ConvertSidToStringSidW(user, &user_string)) return false;
    LocalAllocation user_owner(user_string);
    if (!ConvertSidToStringSidW(restricted, &restricted_string)) return false;
    LocalAllocation restricted_owner(restricted_string);
    const std::wstring sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;" + std::wstring(user_string) +
        L")(A;;GA;;;" + restricted_string + L")S:(ML;;NW;;;LW)";
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),
        SDDL_REVISION_1, &descriptor, nullptr)) return false;
    LocalAllocation owner(descriptor);
    SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
    const std::wstring name = L"AgentkeeperProof." + suffix;
    station_ = CreateWindowStationW(name.c_str(), 0, WINSTA_ALL_ACCESS, &security);
    if (!station_) return false;
    const HWINSTA previous = GetProcessWindowStation();
    if (!SetProcessWindowStation(station_)) return false;
    desktop_ = CreateDesktopW(L"isolated", nullptr, nullptr, 0,
                              STANDARD_RIGHTS_REQUIRED | 0x01ff, &security);
    const bool restored = SetProcessWindowStation(previous) != FALSE;
    name_ = name + L"\\isolated";
    return desktop_ != nullptr && restored;
  }
  wchar_t* name() { return name_.data(); }
 private:
  HWINSTA station_ = nullptr;
  HDESK desktop_ = nullptr;
  std::wstring name_;
};

HANDLE RestrictedToken(PSID sid, std::vector<BYTE>* user) {
  HANDLE raw = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &raw)) return nullptr;
  Handle original(raw);
  DWORD size = 0;
  GetTokenInformation(original.get(), TokenUser, nullptr, 0, &size);
  user->resize(size);
  if (!GetTokenInformation(original.get(), TokenUser, user->data(), size, &size)) return nullptr;
  std::vector<BYTE> common(SECURITY_MAX_SID_SIZE), admin(SECURITY_MAX_SID_SIZE);
  DWORD common_size = static_cast<DWORD>(common.size()), admin_size = static_cast<DWORD>(admin.size());
  if (!CreateWellKnownSid(WinRestrictedCodeSid, nullptr, common.data(), &common_size) ||
      !CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admin.data(), &admin_size)) return nullptr;
  SID_AND_ATTRIBUTES restricted[] = {{sid, 0}, {common.data(), 0}};
  SID_AND_ATTRIBUTES disabled{admin.data(), 0};
  HANDLE result = nullptr;
  // Both reads and writes must pass the restricting-SID access check.
  // WRITE_RESTRICTED would expose the host's readable secrets.
  if (!CreateRestrictedToken(original.get(), DISABLE_MAX_PRIVILEGE, 1, &disabled,
                            0, nullptr, 2, restricted, &result)) {
    std::fprintf(stderr, "restricted probe: CreateRestrictedToken win32=%lu\n", GetLastError());
    return nullptr;
  }
  Handle token(result);
  PACL dacl = nullptr;
  EXPLICIT_ACCESSW entries[2]{};
  for (auto& entry : entries) {
    entry.grfAccessMode = GRANT_ACCESS;
    entry.grfAccessPermissions = GENERIC_ALL;
  }
  BuildTrusteeWithSidW(&entries[0].Trustee, reinterpret_cast<TOKEN_USER*>(user->data())->User.Sid);
  BuildTrusteeWithSidW(&entries[1].Trustee, sid);
  if (SetEntriesInAclW(2, entries, nullptr, &dacl) != ERROR_SUCCESS) return nullptr;
  LocalAllocation dacl_owner(dacl);
  TOKEN_DEFAULT_DACL default_dacl{dacl};
  if (!SetTokenInformation(token.get(), TokenDefaultDacl, &default_dacl, sizeof(default_dacl))) {
    std::fprintf(stderr, "restricted probe: TokenDefaultDacl win32=%lu\n", GetLastError());
    return nullptr;
  }
  PSID low = nullptr;
  if (!ConvertStringSidToSidW(L"S-1-16-4096", &low)) return nullptr;
  LocalAllocation low_owner(low);
  TOKEN_MANDATORY_LABEL label{{low, SE_GROUP_INTEGRITY}};
  if (!SetTokenInformation(token.get(), TokenIntegrityLevel, &label,
          static_cast<DWORD>(sizeof(label) + GetLengthSid(low)))) {
    std::fprintf(stderr, "restricted probe: TokenIntegrityLevel win32=%lu\n", GetLastError());
    return nullptr;
  }
  DWORD appcontainer = 1;
  if (!IsTokenRestricted(token.get()) ||
      !GetTokenInformation(token.get(), TokenIsAppContainer, &appcontainer, sizeof(appcontainer), &size) ||
      appcontainer != 0) {
    std::fprintf(stderr, "restricted probe: token verification win32=%lu appcontainer=%lu\n", GetLastError(), appcontainer);
    return nullptr;
  }
  return token.release();
}

int RunProof(const Request& request, DWORD parent, const std::wstring& outside) {
  std::wstring profile;
  SidAllocation profile_sid;
  if (FAILED(CreateUniqueProfile(&profile, &profile_sid))) return kProfileFailed;
  // This is an ordinary restricting SID, not an AppContainer package identity.
  SidAllocation sid;
  DWORD random[4]{};
  SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
  if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(random), sizeof(random),
      BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 ||
      !AllocateAndInitializeSid(&authority, 5, SECURITY_NT_NON_UNIQUE,
          random[0], random[1], random[2], random[3], 0, 0, 0, sid.out())) {
    DeleteAppContainerProfile(profile.c_str());
    return kSidFailed;
  }
  std::vector<GrantSpec> grants, denies, applied;
  ObjectPins pins;
  KernelGrants kernel(sid.get());
  Handle job(CreateJobObjectW(nullptr, nullptr));
  auto finish = [&](int code) {
    if (code != 0) std::fprintf(stderr, "restricted probe: result=%d win32=%lu\n", code, GetLastError());
    // Drain the tree before revoking any capability or closing its desktop.
    const bool drained = job.get() && TerminateAndDrainJob(job.get(), ERROR_CANCELLED);
    const bool kernel_clean = kernel.Close();
    const bool files_clean = Cleanup(applied, sid.get(), profile);
    return drained && kernel_clean && files_clean ? code : kCleanupFailed;
  };
  if (!BuildAclChanges(request, &grants, &denies) ||
      !ValidateAclObjects(request, grants, denies, &pins)) return finish(kUnsafePath);
  std::fprintf(stderr, "restricted probe: applying workspace/toolchain ACLs\n");
  AclMutationGuard mutation;
  if (!mutation.Lock() || !OpenAclObjects(&grants, false) ||
      !ApplyAclChanges(grants, sid.get(), GRANT_ACCESS, &applied)) {
    mutation.Unlock();
    return finish(kAclFailed);
  }
  mutation.Unlock();
  // Node's realpath needs ancestor attributes. Never grant ancestor file data,
  // inheritable access or trigger descendant propagation at an ancestor.
  std::map<std::wstring, GrantSpec, CaseInsensitiveLess> ancestors;
  for (const auto& resource : request.reads) {
    for (std::wstring path = ParentPath(resource.path);;) {
      MergeGrant(&ancestors, path, FILE_READ_ATTRIBUTES | READ_CONTROL, false);
      if (path.size() == 3) break;
      path = ParentPath(path);
    }
  }
  std::fprintf(stderr, "restricted probe: granting nonrecursive metadata\n");
  for (const auto& [unused, grant] : ancestors) {
    (void)unused;
    if (!kernel.Add(CreateFileW(grant.path.c_str(), READ_CONTROL | WRITE_DAC,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr),
        SE_FILE_OBJECT, grant.access)) return finish(kAclFailed);
  }
  if (!GrantMetadata(&kernel, request)) {
    std::fwprintf(stderr, L"restricted probe: metadata grant win32=%lu\n", GetLastError());
    return finish(kAclFailed);
  }
  std::vector<BYTE> user;
  std::fprintf(stderr, "restricted probe: creating restricted token\n");
  Handle token(RestrictedToken(sid.get(), &user));
  if (!token.get()) return finish(kProcessFailed);
  if (!ImpersonateLoggedOnUser(token.get())) return finish(kProcessFailed);
  Handle parent_control(OpenProcess(PROCESS_DUP_HANDLE | PROCESS_VM_WRITE, FALSE, parent));
  Handle canary_control(CreateFileW(outside.c_str(), WRITE_DAC,
      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
  const bool reverted = RevertToSelf() != FALSE;
  if (!reverted || parent_control.get() || canary_control.get() != INVALID_HANDLE_VALUE) {
    std::fprintf(stderr, "restricted probe: host control was not denied\n");
    return finish(kProcessFailed);
  }
  PrivateDesktop desktop;
  std::fprintf(stderr, "restricted probe: creating private desktop\n");
  if (!desktop.Initialise(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, sid.get(), profile)) {
    std::fwprintf(stderr, L"restricted probe: desktop win32=%lu\n", GetLastError());
    return finish(kProcessFailed);
  }
  StandardStreams streams;
  AttributeList attributes;
  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.StartupInfo.lpDesktop = desktop.name();
  if (!attributes.Initialise(1) || !streams.Initialise() || !streams.Attach(&attributes, &startup))
    return finish(kProcessFailed);
  startup.lpAttributeList = attributes.get();
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!job.get() || !SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation,
      &limits, sizeof(limits))) return finish(kJobFailed);
  PROCESS_INFORMATION child{};
  auto line = CommandLine(request);
  std::fprintf(stderr, "restricted probe: launching confined Node\n");
  if (!CreateProcessAsUserW(token.get(), request.executable.c_str(), line.data(), nullptr, nullptr,
      TRUE, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
      nullptr, request.cwd.c_str(), &startup.StartupInfo, &child)) {
    std::fwprintf(stderr, L"restricted probe: launch win32=%lu\n", GetLastError());
    return finish(kProcessFailed);
  }
  Handle process(child.hProcess), thread(child.hThread);
  if (!AssignProcessToJobObject(job.get(), process.get())) {
    TerminateProcess(process.get(), ERROR_CANCELLED);
    WaitForSingleObject(process.get(), 5000);
    return finish(kJobFailed);
  }
  pins.clear();
  if (ResumeThread(thread.get()) == static_cast<DWORD>(-1)) return finish(kProcessFailed);
  if (WaitForSingleObject(process.get(), 30000) != WAIT_OBJECT_0) return finish(kChildTimedOut);
  DWORD code = 1;
  if (!GetExitCodeProcess(process.get(), &code)) return finish(kWaitFailed);
  return finish(static_cast<int>(code));
}
} // namespace

int wmain(int argc, wchar_t* argv[]) {
  if (argc == 3 && wcscmp(argv[1], L"--runtime-modules") == 0) {
    // Inventory trusted host runtimes so the proof can use ordinary copies,
    // without granting a restricting SID to hard-linked Windows system files.
    // Do not merge this helper's modules into the target's inventory: the
    // target may be x64 Git while the helper and Node are native ARM64.
    {
      const DWORD process = wcstoul(argv[2], nullptr, 10);
      HANDLE raw_snapshot = INVALID_HANDLE_VALUE;
      for (int attempt = 0; attempt < 20; ++attempt) {
        raw_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process);
        if (raw_snapshot != INVALID_HANDLE_VALUE || GetLastError() != ERROR_BAD_LENGTH) break;
        Sleep(10);
      }
      Handle snapshot(raw_snapshot);
      if (snapshot.get() == INVALID_HANDLE_VALUE) {
        std::fprintf(stderr, "runtime inventory: pid=%lu win32=%lu\n", process, GetLastError());
        return kProcessFailed;
      }
      MODULEENTRY32W entry{};
      entry.dwSize = sizeof(entry);
      if (!Module32FirstW(snapshot.get(), &entry)) return kProcessFailed;
      do { std::wprintf(L"%ls\n", entry.szExePath); }
      while (Module32NextW(snapshot.get(), &entry));
      if (GetLastError() != ERROR_NO_MORE_FILES) return kProcessFailed;
    }
    return 0;
  }
  if (argc != 6) return kRequestInvalid;
  Request request;
  request.executable = argv[1];
  request.cwd = argv[3];
  request.args = {request.cwd + L"\\qualification.cjs", argv[4], argv[2], argv[5]};
  request.reads = {{true, request.cwd}, {true, ParentPath(request.executable)},
                   {true, ParentPath(ParentPath(argv[2]))}};
  request.writes = {{true, request.cwd}};
  if (!NormaliseRequest(&request)) return kRequestInvalid;
  std::fprintf(stdout, "restricted token proof: filesystem/stdio/Git only; network is unqualified\n");
  std::fflush(stdout);
  return RunProof(request, wcstoul(argv[5], nullptr, 10), argv[4]);
}
