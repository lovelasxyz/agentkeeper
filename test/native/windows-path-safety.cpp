#include "windows-path-safety.h"
#include <iostream>
#include <string>

int main() {
  struct Case { const wchar_t* path; bool allowed; };
  const Case cases[] = {
    {L"C:\\", true}, {L"C:\\Users\\Dev\\project", true},
    {L"C:\\Program Files\\nodejs\\node.exe", true},
    {L"C:\\workspace\\\u043f\u0440\u043e\u0435\u043a\u0442", true},
    {L"C:\\workspace\\.git", true}, {L"C:\\workspace\\file..txt", true},
    {L"C:relative", false}, {L"relative", false},
    {L"\\\\server\\share", false}, {L"\\\\?\\C:\\secret", false},
    {L"C:\\workspace\\..\\secret", false}, {L"C:\\workspace\\.\\secret", false},
    {L"C:\\workspace\\file:secret", false}, {L"C:\\workspace\\file.", false},
    {L"C:\\workspace\\file ", false}, {L"C:\\workspace\\CON", false},
    {L"C:\\workspace\\nul.txt", false}, {L"C:\\workspace\\LPT1.log", false},
    {L"C:\\workspace\\COM\u00b9.txt", false}, {L"C:\\workspace\\CON .txt", false},
    {L"C:\\workspace\\a?b", false}, {L"C:\\workspace\\a\nb", false},
    {L"C:\\workspace\\a/b", false}, {L"C:\\workspace\\\\secret", false},
  };
  int failures = 0;
  for (const auto& test : cases) {
    if (agentkeeper::IsSafeWindowsPath(test.path) != test.allowed) {
      std::wcerr << L"Wrong path decision: " << test.path << L'\n';
      ++failures;
    }
  }
  if (agentkeeper::IsSafeWindowsPath(std::wstring(33000, L'a'))) ++failures;
  if (agentkeeper::IsSafeWindowsPath(std::wstring(L"C:\\file\0hidden", 14))) ++failures;
  if (failures != 0) return 1;
  std::cout << "Windows path safety: all adversarial cases passed\n";
}
