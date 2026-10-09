#pragma once

#include <string>
#include <string_view>

namespace agentkeeper {

// Accept only unambiguous, normalised local-drive names before any ACL API.
// Win32 aliases (ADS, DOS devices, dot segments, trailing dots/spaces) must not
// turn a policy path into another object. NativeSeparators runs beforehand.
inline bool IsSafeWindowsPath(std::wstring_view path) {
  if (path.size() < 3 || path.size() > 32760 ||
      !((path[0] >= L'A' && path[0] <= L'Z') ||
        (path[0] >= L'a' && path[0] <= L'z')) ||
      path[1] != L':' || path[2] != L'\\') return false;

  std::size_t start = 3;
  while (start < path.size()) {
    const std::size_t separator = path.find(L'\\', start);
    const std::size_t end = separator == std::wstring_view::npos ? path.size() : separator;
    const auto component = path.substr(start, end - start);
    if (component.empty() || component == L"." || component == L".." ||
        component.back() == L'.' || component.back() == L' ') return false;
    for (const auto character : component) {
      if (character < 32 || std::wstring_view(L"<>:\"/|?*").find(character) != std::wstring_view::npos) {
        return false;
      }
    }
    auto base = component.substr(0, component.find(L'.'));
    while (!base.empty() && (base.back() == L' ' || base.back() == L'.')) base.remove_suffix(1);
    std::wstring upper(base);
    for (auto& character : upper) {
      if (character >= L'a' && character <= L'z') {
        character = static_cast<wchar_t>(character - (L'a' - L'A'));
      }
    }
    if (upper == L"CON" || upper == L"PRN" || upper == L"AUX" || upper == L"NUL" ||
        upper == L"CONIN$" || upper == L"CONOUT$") return false;
    if (upper.size() == 4 && (upper.substr(0, 3) == L"COM" || upper.substr(0, 3) == L"LPT") &&
        ((upper[3] >= L'1' && upper[3] <= L'9') || upper[3] == L'\u00b9' ||
         upper[3] == L'\u00b2' || upper[3] == L'\u00b3')) return false;
    if (separator == std::wstring_view::npos) break;
    start = separator + 1;
  }
  return true;
}

}  // namespace agentkeeper
