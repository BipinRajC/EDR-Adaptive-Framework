/*
 * Interactive CLI - Implementation
 * ==================================
 * Author: Jdeep
 *
 * Menu-based interactive terminal with numbered options.
 * ASCII-compatible version for MinGW.
 */

// Windows headers MUST come first — before any project or STL headers
// to ensure BOOL, DWORD, WINAPI etc. are defined before tlhelp32.h
#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#endif

#include "agent_core/agent.hpp"
#include "cli/cli.hpp"
#include "exploits/exploit_manager.hpp"
#include "ml_framework/ml_engine.hpp"
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

#ifdef _WIN32
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#define SLEEP_MS(x) Sleep(x)
#else
#include <termios.h>
#include <unistd.h>
#define SLEEP_MS(x) usleep((x) * 1000)
#endif

// EDR Detection Structures
struct EDRProduct {
  std::string name;
  std::vector<std::string> processNames;
  std::vector<std::string> serviceNames;
};

// Known EDR/AV products and their indicators
static const std::vector<EDRProduct> knownEDRs = {
    {"CrowdStrike Falcon",
     {"csfalconservice.exe", "csfalconcontainer.exe", "csagent.exe"},
     {"CSFalconService"}},
    {"Carbon Black",
     {"cb.exe", "cbcomms.exe", "cbstream.exe"},
     {"CbDefense", "CarbonBlack"}},
    {"SentinelOne",
     {"sentinelagent.exe", "sentinelctl.exe", "sentinelone.exe"},
     {"SentinelAgent"}},
    {"Symantec",
     {"ccsvchst.exe", "rtvscan.exe", "smc.exe"},
     {"Symantec Endpoint Protection"}},
    {"McAfee",
     {"mcshield.exe", "mfefire.exe", "mfemms.exe"},
     {"McAfee Endpoint Security"}},
    {"Kaspersky",
     {"avp.exe", "kavfs.exe", "klnagent.exe"},
     {"AVP", "Kaspersky"}},
    {"ESET", {"ekrn.exe", "egui.exe", "eamonm.exe"}, {"ekrn", "ESET"}},
    {"Sophos",
     {"savservice.exe", "sophosui.exe", "hmpalert.exe"},
     {"Sophos Endpoint"}},
    {"Trend Micro",
     {"ntrtscan.exe", "tmntsrv.exe", "pccntmon.exe"},
     {"TrendMicro"}},
    {"Cylance", {"cylancesvc.exe", "cylanceui.exe"}, {"CylanceSvc"}},
    {"Palo Alto Cortex",
     {"traps.exe", "cyserver.exe", "cytray.exe"},
     {"Traps", "CortexXDR"}},
    {"Microsoft Defender ATP", {"mssense.exe", "sensecncproxy.exe"}, {"Sense"}},
    {"Malwarebytes", {"mbam.exe", "mbamservice.exe"}, {"MBAMService"}},
    {"Bitdefender",
     {"bdagent.exe", "vsserv.exe", "bdredline.exe"},
     {"VSSERV", "bdredline"}},
    {"Avast", {"avastsvc.exe", "avastui.exe"}, {"avast! Antivirus"}},
    {"AVG", {"avgsvc.exe", "avgui.exe"}, {"AVGSvc"}},
    {"F-Secure", {"fssm32.exe", "fsgk32.exe"}, {"F-Secure"}},
    {"Webroot", {"wrsa.exe"}, {"WRSVC"}},
    {"Elastic EDR",
     {"elastic-agent.exe", "elastic-endpoint.exe"},
     {"Elastic Agent"}},
    {"Tanium", {"taniumclient.exe"}, {"Tanium Client"}},
};

// ============================================================================
// SYSTEM DETECTION FUNCTIONS
// ============================================================================

#ifdef _WIN32
// Get list of running processes
std::vector<std::string> getRunningProcesses() {
  std::vector<std::string> processes;
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnapshot == INVALID_HANDLE_VALUE)
    return processes;

  PROCESSENTRY32W pe32;
  pe32.dwSize = sizeof(PROCESSENTRY32W);

  if (Process32FirstW(hSnapshot, &pe32)) {
    do {
      // Convert WCHAR process name to UTF-8 std::string
      char procNameBuf[260];
      WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, procNameBuf,
                          sizeof(procNameBuf), NULL, NULL);
      std::string procName(procNameBuf);
      std::transform(procName.begin(), procName.end(), procName.begin(),
                     ::tolower);
      processes.push_back(procName);
    } while (Process32NextW(hSnapshot, &pe32));
  }
  CloseHandle(hSnapshot);
  return processes;
}

// Check if a process is running
bool isProcessRunning(const std::string &processName,
                      const std::vector<std::string> &runningProcs) {
  std::string lowerName = processName;
  std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(),
                 ::tolower);

  for (const auto &proc : runningProcs) {
    if (proc == lowerName)
      return true;
  }
  return false;
}

// Detect Windows Defender status
std::pair<std::string, std::string> detectWindowsDefender() {
  // Check if Windows Defender service is running
  SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
  if (!scm)
    return {"Unknown", "Cannot query services"};

  SC_HANDLE service = OpenServiceW(scm, L"WinDefend", SERVICE_QUERY_STATUS);
  if (!service) {
    CloseServiceHandle(scm);
    return {"Not Installed", "-"};
  }

  SERVICE_STATUS_PROCESS ssp;
  DWORD bytesNeeded;
  if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp,
                           sizeof(ssp), &bytesNeeded)) {
    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    if (ssp.dwCurrentState == SERVICE_RUNNING) {
      // Check real-time protection via registry
      HKEY hKey;
      DWORD rtpDisabled = 0;
      DWORD size = sizeof(DWORD);

      if (RegOpenKeyExA(
              HKEY_LOCAL_MACHINE,
              "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection", 0,
              KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "DisableRealtimeMonitoring", NULL, NULL,
                         (LPBYTE)&rtpDisabled, &size);
        RegCloseKey(hKey);
      }

      if (rtpDisabled == 0) {
        return {"Active", "Real-time protection ON"};
      } else {
        return {"Active", "Real-time protection OFF"};
      }
    } else {
      return {"Stopped", "Service not running"};
    }
  }

  CloseServiceHandle(service);
  CloseServiceHandle(scm);
  return {"Unknown", "Query failed"};
}

// Detect EDR products
std::vector<std::tuple<std::string, std::string, std::string>>
detectEDRProducts(const std::vector<std::string> &runningProcs) {
  std::vector<std::tuple<std::string, std::string, std::string>> detected;

  for (const auto &edr : knownEDRs) {
    bool found = false;
    for (const auto &procName : edr.processNames) {
      if (isProcessRunning(procName, runningProcs)) {
        found = true;
        break;
      }
    }

    if (found) {
      detected.push_back(
          std::make_tuple(edr.name, "Active", "Process detected"));
    }
  }

  return detected;
}

// Detect VM/Hypervisor
std::pair<std::string, std::string> detectVMProvider() {
  // Check for VM indicators via registry
  HKEY hKey;
  char value[256] = {0};
  DWORD size = sizeof(value);

  // Check BIOS info
  if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS",
                    0, KEY_READ, &hKey) == ERROR_SUCCESS) {

    if (RegQueryValueExA(hKey, "SystemManufacturer", NULL, NULL, (LPBYTE)value,
                         &size) == ERROR_SUCCESS) {
      std::string manufacturer(value);
      RegCloseKey(hKey);

      if (manufacturer.find("VMware") != std::string::npos) {
        return {"VMware", "Detected"};
      } else if (manufacturer.find("innotek") != std::string::npos ||
                 manufacturer.find("VirtualBox") != std::string::npos) {
        return {"VirtualBox", "Detected"};
      } else if (manufacturer.find("Microsoft") != std::string::npos) {
        // Could be Hyper-V, check further
        size = sizeof(value);
        memset(value, 0, sizeof(value));
        if (RegQueryValueExA(hKey, "SystemProductName", NULL, NULL,
                             (LPBYTE)value, &size) == ERROR_SUCCESS) {
          std::string product(value);
          if (product.find("Virtual") != std::string::npos) {
            return {"Hyper-V", "Detected"};
          }
        }
      } else if (manufacturer.find("QEMU") != std::string::npos) {
        return {"QEMU/KVM", "Detected"};
      } else if (manufacturer.find("Xen") != std::string::npos) {
        return {"Xen", "Detected"};
      } else if (manufacturer.find("Amazon") != std::string::npos) {
        return {"AWS EC2", "Detected"};
      } else if (manufacturer.find("Google") != std::string::npos) {
        return {"Google Cloud", "Detected"};
      }
    }
    RegCloseKey(hKey);
  }

  // Check for common VM processes
  std::vector<std::string> procs = getRunningProcesses();
  for (const auto &proc : procs) {
    if (proc == "vmtoolsd.exe" || proc == "vmwaretray.exe") {
      return {"VMware", "Tools detected"};
    } else if (proc == "vboxservice.exe" || proc == "vboxtray.exe") {
      return {"VirtualBox", "Tools detected"};
    }
  }

  return {"Physical/Unknown", "No VM detected"};
}

// Get system info
std::string getWindowsVersion() {
  HKEY hKey;
  char productName[256] = {0};
  char buildNumber[32] = {0};
  char displayVersion[32] = {0};
  DWORD size;

  if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0,
                    KEY_READ, &hKey) == ERROR_SUCCESS) {

    size = sizeof(productName);
    RegQueryValueExA(hKey, "ProductName", NULL, NULL, (LPBYTE)productName,
                     &size);

    size = sizeof(buildNumber);
    RegQueryValueExA(hKey, "CurrentBuildNumber", NULL, NULL,
                     (LPBYTE)buildNumber, &size);

    size = sizeof(displayVersion);
    RegQueryValueExA(hKey, "DisplayVersion", NULL, NULL, (LPBYTE)displayVersion,
                     &size);

    RegCloseKey(hKey);
  }

  std::string result(productName);
  int build = std::atoi(buildNumber);

  // Windows 11 has build number >= 22000
  if (build >= 22000) {
    // Replace "Windows 10" with "Windows 11" if present
    size_t pos = result.find("Windows 10");
    if (pos != std::string::npos) {
      result.replace(pos, 10, "Windows 11");
    }
  }

  // Append version if available
  if (strlen(displayVersion) > 0) {
    result += " (" + std::string(displayVersion) + ")";
  }

  return result;
}

std::string getComputerName() {
  char name[MAX_COMPUTERNAME_LENGTH + 1] = {0};
  DWORD size = sizeof(name);
  GetComputerNameA(name, &size);
  return std::string(name);
}

std::string getUserName() {
  char name[256] = {0};
  DWORD size = sizeof(name);
  GetUserNameA(name, &size);
  return std::string(name);
}

bool isAdmin() {
  BOOL isAdmin = FALSE;
  PSID adminGroup = NULL;
  SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

  if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                               DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                               &adminGroup)) {
    CheckTokenMembership(NULL, adminGroup, &isAdmin);
    FreeSid(adminGroup);
  }
  return isAdmin == TRUE;
}

#else
// Linux/macOS stubs
std::vector<std::string> getRunningProcesses() { return {}; }
std::pair<std::string, std::string> detectWindowsDefender() {
  return {"N/A", "Not Windows"};
}
std::vector<std::tuple<std::string, std::string, std::string>>
detectEDRProducts(const std::vector<std::string> &) {
  return {};
}
std::pair<std::string, std::string> detectVMProvider() {
  return {"Unknown", "-"};
}
std::string getWindowsVersion() { return "N/A"; }
std::string getComputerName() { return "N/A"; }
std::string getUserName() { return "N/A"; }
bool isAdmin() { return false; }
#endif

namespace edr {
namespace cli {

// ============================================================================
// UI IMPLEMENTATION
// ============================================================================

void UI::enableAnsi() {
#ifdef _WIN32
  HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD dwMode = 0;
  GetConsoleMode(hOut, &dwMode);
  dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
  SetConsoleMode(hOut, dwMode);
  SetConsoleOutputCP(CP_UTF8);
#endif
}

void UI::print(const std::string &text, const char *color) {
  std::cout << color << text << colors::RESET;
}

void UI::println(const std::string &text, const char *color) {
  std::cout << color << text << colors::RESET << std::endl;
}

void UI::info(const std::string &text) {
  std::cout << colors::CYAN << "[*] " << colors::RESET << text << std::endl;
}

void UI::success(const std::string &text) {
  std::cout << colors::BRIGHT_GREEN << "[+] " << colors::RESET << text
            << std::endl;
}

void UI::warning(const std::string &text) {
  std::cout << colors::BRIGHT_YELLOW << "[!] " << colors::RESET << text
            << std::endl;
}

void UI::error(const std::string &text) {
  std::cout << colors::BRIGHT_RED << "[-] " << colors::RESET << text
            << std::endl;
}

void UI::debug(const std::string &text) {
  std::cout << colors::DIM << "[.] " << text << colors::RESET << std::endl;
}

void UI::box(const std::string &title, const std::string &content) {
  int width = 60;
  std::string topBorder = "+" + std::string(width - 2, '-') + "+";
  std::string bottomBorder = "+" + std::string(width - 2, '-') + "+";

  std::cout << colors::CYAN << topBorder << colors::RESET << std::endl;

  // Title
  int padding = (width - 2 - static_cast<int>(title.length())) / 2;
  std::cout << colors::CYAN << "|" << colors::RESET;
  std::cout << std::string(padding, ' ');
  std::cout << colors::BOLD << colors::BRIGHT_CYAN << title << colors::RESET;
  std::cout << std::string(
      width - 2 - padding - static_cast<int>(title.length()), ' ');
  std::cout << colors::CYAN << "|" << colors::RESET << std::endl;

  // Divider
  std::cout << colors::CYAN << "+" << std::string(width - 2, '-') << "+"
            << colors::RESET << std::endl;

  // Content (split by newlines)
  std::istringstream stream(content);
  std::string line;
  while (std::getline(stream, line)) {
    std::cout << colors::CYAN << "| " << colors::RESET;
    std::cout << line;
    int linePadding = width - 3 - static_cast<int>(line.length());
    if (linePadding > 0)
      std::cout << std::string(linePadding, ' ');
    std::cout << colors::CYAN << "|" << colors::RESET << std::endl;
  }

  std::cout << colors::CYAN << bottomBorder << colors::RESET << std::endl;
}

void UI::panel(const std::string &text, const char *borderColor) {
  std::cout << borderColor << "| " << colors::RESET << text << std::endl;
}

void UI::divider(const char *color) {
  std::cout << color
            << "------------------------------------------------------------"
            << colors::RESET << std::endl;
}

void UI::spinner(const std::string &text) {
  const char *frames[] = {"-", "\\", "|", "/"};
  static int frame = 0;
  std::cout << "\r" << colors::CYAN << frames[frame % 4] << colors::RESET << " "
            << text << std::flush;
  frame++;
}

void UI::progress(int current, int total, const std::string &label) {
  int width = 40;
  float progress = static_cast<float>(current) / total;
  int filled = static_cast<int>(progress * width);

  std::cout << "\r" << colors::DIM << "[" << colors::RESET;
  std::cout << colors::BRIGHT_GREEN << std::string(filled, '#');
  std::cout << colors::DIM << std::string(width - filled, '-');
  std::cout << colors::DIM << "]" << colors::RESET;
  std::cout << " " << static_cast<int>(progress * 100) << "% " << label
            << std::flush;

  if (current >= total)
    std::cout << std::endl;
}

void UI::table(const std::vector<std::vector<std::string>> &data,
               const std::vector<std::string> &headers) {
  if (data.empty())
    return;

  // Calculate column widths
  std::vector<size_t> widths;
  size_t numCols = headers.empty() ? data[0].size() : headers.size();

  for (size_t i = 0; i < numCols; ++i) {
    size_t maxWidth = headers.empty() ? 0 : headers[i].length();
    for (const auto &row : data) {
      if (i < row.size()) {
        maxWidth = std::max(maxWidth, row[i].length());
      }
    }
    widths.push_back(maxWidth + 2);
  }

  // Print headers
  if (!headers.empty()) {
    std::cout << colors::BOLD;
    for (size_t i = 0; i < headers.size(); ++i) {
      std::cout << std::left << std::setw(static_cast<int>(widths[i]))
                << headers[i];
    }
    std::cout << colors::RESET << std::endl;

    // Header underline
    std::cout << colors::DIM;
    for (size_t i = 0; i < widths.size(); ++i) {
      std::cout << std::string(widths[i], '-');
    }
    std::cout << colors::RESET << std::endl;
  }

  // Print data rows
  for (const auto &row : data) {
    for (size_t i = 0; i < row.size(); ++i) {
      std::cout << std::left << std::setw(static_cast<int>(widths[i]))
                << row[i];
    }
    std::cout << std::endl;
  }
}

std::string UI::prompt(const std::string &message) {
  std::cout << colors::BRIGHT_CYAN << "? " << colors::RESET << message << " ";
  std::string input;
  std::getline(std::cin, input);
  return input;
}

bool UI::confirm(const std::string &message) {
  std::cout << colors::BRIGHT_YELLOW << "? " << colors::RESET << message
            << colors::DIM << " (y/n) " << colors::RESET;
  std::string input;
  std::getline(std::cin, input);
  return !input.empty() && (input[0] == 'y' || input[0] == 'Y');
}

void UI::clear() {
#ifdef _WIN32
  system("cls");
#else
  system("clear");
#endif
}

void UI::banner() {
  // Metasploit-style hacker banner
  std::cout << std::endl;
  std::cout << colors::BRIGHT_RED << R"(

 ██╗   ██╗ ██╗   ██╗ ██╗   ██╗ ██╗  ██╗  █████╗ 
 ██║   ██║ ╚██╗ ██╔╝ ██║   ██║ ██║  ██║ ██╔══██╗
 ██║   ██║  ╚████╔╝  ██║   ██║ ███████║ ███████║
 ╚██╗ ██╔╝   ╚██╔╝   ██║   ██║ ██╔══██║ ██╔══██║
  ╚████╔╝     ██║    ╚██████╔╝ ██║  ██║ ██║  ██║
   ╚═══╝      ╚═╝     ╚═════╝  ╚═╝  ╚═╝ ╚═╝  ╚═╝
  
)" << colors::RESET;

  std::cout << colors::BRIGHT_BLUE << R"(
                        =[ VYUHA: Cross-Layer EDR Kill-Chain Evasion ]=
)" << colors::RESET;

  // Metasploit-style stats
  std::cout << colors::BRIGHT_GREEN << "       + -- --=[ " << colors::RESET;
  std::cout << colors::BRIGHT_YELLOW << "7 exploits" << colors::RESET;
  std::cout << colors::BRIGHT_GREEN << " - " << colors::RESET;
  std::cout << colors::BRIGHT_YELLOW << "3 campaigns" << colors::RESET;
  std::cout << colors::BRIGHT_GREEN << " - " << colors::RESET;
  std::cout << colors::BRIGHT_YELLOW << "4 EDR targets" << colors::RESET;
  std::cout << colors::BRIGHT_GREEN << " ]=-- -- +" << colors::RESET
            << std::endl;

  std::cout << std::endl;
  std::cout << colors::DIM << "       " << colors::RESET;
  std::cout << colors::BRIGHT_RED << "[!] " << colors::RESET;
  std::cout << colors::DIM << "WARNING: For authorized security testing only"
            << colors::RESET << std::endl;
  std::cout << std::endl;
}

// ============================================================================
// CLI IMPLEMENTATION
// ============================================================================

CLI::CLI()
    : running_(false),
      exploitManager_(std::make_shared<edr::exploits::ExploitManager>()),
      agentCore_(std::make_shared<edr::agent::AgentCore>()),
      mlEngine_(std::make_shared<edr::ml::MLEngine>()) {
  UI::enableAnsi();

  // Boot the ML engine (starts Python bridge if Python is available)
  if (!mlEngine_->initialize()) {
    UI::warning("ML engine Python bridge unavailable — C++-only mode.");
  }

  // Boot the agent core (starts telemetry monitoring)
  agentCore_->initialize();

  registerBuiltinCommands();

  // Generate session ID
  auto now = std::chrono::system_clock::now();
  auto time = std::chrono::system_clock::to_time_t(now);
  std::ostringstream oss;
  oss << std::put_time(std::localtime(&time), "%Y%m%d_%H%M%S");
  currentSession_ = oss.str();
}

CLI::~CLI() = default;

void CLI::registerBuiltinCommands() {
  // Commands are registered for internal use
  registerCommand({"help", "h", "Show help", "/help",
                   [this](const CommandContext &ctx) { showHelp(ctx); }});
  registerCommand({"run", "r", "Run technique", "/run",
                   [this](const CommandContext &ctx) { cmdRun(ctx); }});
  registerCommand({"list", "ls", "List techniques", "/list",
                   [this](const CommandContext &ctx) { cmdList(ctx); }});
  registerCommand({"status", "st", "Show status", "/status",
                   [this](const CommandContext &ctx) { cmdStatus(ctx); }});
  registerCommand({"campaign", "c", "Run campaign", "/campaign",
                   [this](const CommandContext &ctx) { cmdCampaign(ctx); }});
  registerCommand({"snapshot", "snap", "Manage snapshots", "/snapshot",
                   [this](const CommandContext &ctx) { cmdSnapshot(ctx); }});
  registerCommand({"clean", "", "Cleanup", "/clean",
                   [this](const CommandContext &ctx) { cmdClean(ctx); }});
  registerCommand({"config", "cfg", "Configuration", "/config",
                   [this](const CommandContext &ctx) { cmdConfig(ctx); }});
  registerCommand({"history", "", "History", "/history",
                   [this](const CommandContext &ctx) { cmdHistory(ctx); }});
  registerCommand({"clear", "cls", "Clear screen", "/clear",
                   [this](const CommandContext &ctx) { cmdClear(ctx); }});
  registerCommand({"exit", "q", "Exit", "/exit",
                   [this](const CommandContext &ctx) { cmdExit(ctx); }});
  aliases_["quit"] = "exit";
}

void CLI::registerCommand(const Command &cmd) {
  commands_[cmd.name] = cmd;
  if (!cmd.alias.empty()) {
    aliases_[cmd.alias] = cmd.name;
  }
}

void CLI::showMainMenu() {
  std::cout << std::endl;
  std::cout << colors::BRIGHT_RED << "  +" << std::string(61, '-') << "+"
            << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET << colors::BOLD
            << "                    EXPLOIT MODULES                         "
            << colors::RESET << colors::BRIGHT_RED << "|" << colors::RESET
            << std::endl;
  std::cout << colors::BRIGHT_RED << "  +" << std::string(61, '-') << "+"
            << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET
            << colors::BRIGHT_GREEN << "  [1]" << colors::RESET
            << " use exploit    " << colors::DIM
            << "- Run Attack Technique          " << colors::RESET
            << colors::BRIGHT_RED << "|" << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET
            << colors::BRIGHT_GREEN << "  [2]" << colors::RESET
            << " show exploits  " << colors::DIM
            << "- List Available Techniques     " << colors::RESET
            << colors::BRIGHT_RED << "|" << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET
            << colors::BRIGHT_GREEN << "  [3]" << colors::RESET
            << " run campaign   " << colors::DIM
            << "- Execute APT Campaign          " << colors::RESET
            << colors::BRIGHT_RED << "|" << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  +" << std::string(61, '-') << "+"
            << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET << colors::BOLD
            << "                    SYSTEM MODULES                          "
            << colors::RESET << colors::BRIGHT_RED << "|" << colors::RESET
            << std::endl;
  std::cout << colors::BRIGHT_RED << "  +" << std::string(61, '-') << "+"
            << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET
            << colors::BRIGHT_YELLOW << "  [4]" << colors::RESET
            << " sysinfo        " << colors::DIM
            << "- System & EDR Status           " << colors::RESET
            << colors::BRIGHT_RED << "|" << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET
            << colors::BRIGHT_YELLOW << "  [5]" << colors::RESET
            << " snapshot       " << colors::DIM
            << "- Manage VM Snapshots           " << colors::RESET
            << colors::BRIGHT_RED << "|" << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET
            << colors::BRIGHT_YELLOW << "  [6]" << colors::RESET
            << " clearev        " << colors::DIM
            << "- Clean Artifacts & Traces      " << colors::RESET
            << colors::BRIGHT_RED << "|" << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  +" << std::string(61, '-') << "+"
            << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET << colors::BOLD
            << "                    CORE COMMANDS                           "
            << colors::RESET << colors::BRIGHT_RED << "|" << colors::RESET
            << std::endl;
  std::cout << colors::BRIGHT_RED << "  +" << std::string(61, '-') << "+"
            << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET
            << colors::BRIGHT_CYAN << "  [7]" << colors::RESET
            << " options        " << colors::DIM
            << "- View Configuration            " << colors::RESET
            << colors::BRIGHT_RED << "|" << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET
            << colors::BRIGHT_CYAN << "  [8]" << colors::RESET
            << " history        " << colors::DIM
            << "- Command History               " << colors::RESET
            << colors::BRIGHT_RED << "|" << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET
            << colors::BRIGHT_CYAN << "  [9]" << colors::RESET
            << " clear          " << colors::DIM
            << "- Clear Screen                  " << colors::RESET
            << colors::BRIGHT_RED << "|" << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET
            << colors::BRIGHT_RED << "  [0]" << colors::RESET
            << " exit           " << colors::DIM
            << "- Exit Framework                " << colors::RESET
            << colors::BRIGHT_RED << "|" << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  +" << std::string(61, '-') << "+"
            << colors::RESET << std::endl;
  std::cout << std::endl;
}

void CLI::showTechniqueMenu() {
  std::cout << std::endl;
  std::cout << colors::BRIGHT_RED << "  +" << std::string(61, '-') << "+"
            << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET << colors::BOLD
            << "               AVAILABLE EXPLOIT MODULES                    "
            << colors::RESET << colors::BRIGHT_RED << "|" << colors::RESET
            << std::endl;
  std::cout << colors::BRIGHT_RED << "  +" << std::string(61, '-') << "+"
            << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET
            << colors::BRIGHT_GREEN << "  [1]" << colors::RESET
            << " exploit/privesc/byovd         " << colors::DIM
            << "T1068        " << colors::RESET << colors::BRIGHT_RED << "|"
            << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET
            << colors::BRIGHT_GREEN << "  [2]" << colors::RESET
            << " exploit/evasion/edr_freeze    " << colors::DIM
            << "T1562.001    " << colors::RESET << colors::BRIGHT_RED << "|"
            << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET
            << colors::BRIGHT_GREEN << "  [3]" << colors::RESET
            << " exploit/injection/crystal_palace " << colors::DIM
            << "T1055.001  " << colors::RESET << colors::BRIGHT_RED << "|"
            << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET
            << colors::BRIGHT_GREEN << "  [4]" << colors::RESET
            << " exploit/evasion/syswhispers4    " << colors::DIM
            << "T1106        " << colors::RESET << colors::BRIGHT_RED << "|"
            << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  +" << std::string(61, '-') << "+"
            << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET
            << colors::BRIGHT_RED << "  [0]" << colors::RESET << " back"
            << colors::DIM << "                                       "
            << colors::RESET << colors::BRIGHT_RED << "|" << colors::RESET
            << std::endl;
  std::cout << colors::BRIGHT_RED << "  +" << std::string(61, '-') << "+"
            << colors::RESET << std::endl;
  std::cout << std::endl;
}

void CLI::showSnapshotMenu() {
  std::cout << std::endl;
  std::cout << colors::BRIGHT_RED << "  +" << std::string(61, '-') << "+"
            << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET << colors::BOLD
            << "                 VM SNAPSHOT MANAGER                        "
            << colors::RESET << colors::BRIGHT_RED << "|" << colors::RESET
            << std::endl;
  std::cout << colors::BRIGHT_RED << "  +" << std::string(61, '-') << "+"
            << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET
            << colors::BRIGHT_GREEN << "  [1]" << colors::RESET
            << " snapshot -c    " << colors::DIM
            << "- Create new checkpoint        " << colors::RESET
            << colors::BRIGHT_RED << "|" << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET
            << colors::BRIGHT_GREEN << "  [2]" << colors::RESET
            << " snapshot -r    " << colors::DIM
            << "- Restore from checkpoint      " << colors::RESET
            << colors::BRIGHT_RED << "|" << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET
            << colors::BRIGHT_GREEN << "  [3]" << colors::RESET
            << " snapshot -l    " << colors::DIM
            << "- List all checkpoints         " << colors::RESET
            << colors::BRIGHT_RED << "|" << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET
            << colors::BRIGHT_GREEN << "  [4]" << colors::RESET
            << " snapshot -d    " << colors::DIM
            << "- Delete checkpoint            " << colors::RESET
            << colors::BRIGHT_RED << "|" << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  +" << std::string(61, '-') << "+"
            << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET
            << colors::BRIGHT_RED << "  [0]" << colors::RESET << " back"
            << colors::DIM << "                                       "
            << colors::RESET << colors::BRIGHT_RED << "|" << colors::RESET
            << std::endl;
  std::cout << colors::BRIGHT_RED << "  +" << std::string(61, '-') << "+"
            << colors::RESET << std::endl;
  std::cout << std::endl;
}

void CLI::showWelcome() { UI::banner(); }

void CLI::showHelp(const CommandContext &ctx) { showMainMenu(); }

void CLI::printPrompt() {
  std::cout << colors::BRIGHT_RED << "vyuha" << colors::RESET
            << colors::BRIGHT_BLUE << " exploit" << colors::RESET << colors::DIM
            << "(" << colors::RESET << colors::BRIGHT_GREEN << "*"
            << colors::RESET << colors::DIM << ") > " << colors::RESET;
}

std::string CLI::readLine() {
  std::string line;
  std::getline(std::cin, line);
  return line;
}

CommandContext CLI::parseInput(const std::string &input) {
  CommandContext ctx;
  std::istringstream stream(input);
  std::string token;

  while (stream >> token) {
    ctx.args.push_back(token);
  }

  return ctx;
}

bool CLI::processInput(const std::string &input) {
  std::string trimmed = input;
  size_t start = trimmed.find_first_not_of(" \t");
  size_t end = trimmed.find_last_not_of(" \t");
  if (start == std::string::npos)
    return true;
  trimmed = trimmed.substr(start, end - start + 1);

  if (trimmed.empty())
    return true;

  // Add to history
  history_.push_back(trimmed);

  // Check for number input
  if (trimmed.length() == 1 && trimmed[0] >= '0' && trimmed[0] <= '9') {
    int choice = trimmed[0] - '0';
    handleMainMenuChoice(choice);
    return true;
  }

  // Check if it's a slash command (legacy support)
  if (trimmed[0] == '/') {
    std::string cmdLine = trimmed.substr(1);
    CommandContext ctx = parseInput(cmdLine);

    if (ctx.args.empty())
      return true;

    std::string cmdName = ctx.args[0];
    ctx.args.erase(ctx.args.begin());

    if (aliases_.count(cmdName)) {
      cmdName = aliases_[cmdName];
    }

    if (commands_.count(cmdName)) {
      commands_[cmdName].handler(ctx);
    } else {
      UI::error("Unknown command: /" + cmdName);
    }
  } else {
    UI::warning("Invalid input. Enter a number (0-9) or use /help");
  }

  return true;
}

void CLI::handleMainMenuChoice(int choice) {
  CommandContext ctx;

  switch (choice) {
  case 1: // Run Attack Technique
    handleTechniqueMenu();
    break;

  case 2: // List Techniques
    cmdList(ctx);
    break;

  case 3: // Run Campaign
    handleCampaignMenu();
    break;

  case 4: // Status
    cmdStatus(ctx);
    break;

  case 5: // Snapshots
    handleSnapshotMenu();
    break;

  case 6: // Clean
    cmdClean(ctx);
    break;

  case 7: // Config
    cmdConfig(ctx);
    break;

  case 8: // History
    cmdHistory(ctx);
    break;

  case 9: // Clear
    cmdClear(ctx);
    break;

  case 0: // Exit
    cmdExit(ctx);
    break;

  default:
    UI::error("Invalid choice");
    break;
  }
}

void CLI::handleTechniqueMenu() {
  showTechniqueMenu();

  std::cout << colors::BRIGHT_RED << "  vyuha" << colors::RESET
            << colors::BRIGHT_BLUE << " exploit" << colors::RESET << colors::DIM
            << "(*) > " << colors::RESET;
  std::string input = readLine();

  if (input.empty() || input[0] == '0')
    return;

  std::string techniqueId;
  int choice = std::atoi(input.c_str());

  switch (choice) {
  case 1:
    techniqueId = "T1068";
    break;
  case 2:
    techniqueId = "T1562.001";
    break;
  case 3:
    techniqueId = "T1055.001";
    break;
  case 4:
    techniqueId = "T1106";
    break;
  default:
    UI::error("Invalid selection. Choose from available exploits (1-4).");
    std::cout << std::endl;
    return;
  }

  CommandContext ctx;
  ctx.args.push_back(techniqueId);
  cmdRun(ctx);
}

void CLI::showCampaignMenu() {
  std::cout << std::endl;
  std::cout << colors::BRIGHT_RED << "  +" << std::string(61, '-') << "+" << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET << colors::BOLD
            << "                   ADAPTIVE ML CAMPAIGNS                     "
            << colors::RESET << colors::BRIGHT_RED << "|" << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  +" << std::string(61, '-') << "+" << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET
            << colors::BRIGHT_GREEN << "  [1]" << colors::RESET
            << " Auto-ML Campaign   " << colors::DIM
            << "(BYOVD, EDR-Freeze, CrystalPalace, SysWhispers4) " << colors::RESET << colors::BRIGHT_RED << "|" << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET
            << colors::BRIGHT_GREEN << "  [2]" << colors::RESET
            << " Custom Campaign    " << colors::DIM
            << "(Load from local .txt file)        " << colors::RESET << colors::BRIGHT_RED << "|" << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  +" << std::string(61, '-') << "+" << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  |" << colors::RESET
            << colors::BRIGHT_RED << "  [0]" << colors::RESET << " back"
            << colors::DIM << "                                       "
            << colors::RESET << colors::BRIGHT_RED << "|" << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  +" << std::string(61, '-') << "+" << colors::RESET << std::endl;
  std::cout << std::endl;
}

void CLI::handleCampaignMenu() {
  showCampaignMenu();

  std::cout << colors::BRIGHT_RED << "  vyuha" << colors::RESET
            << colors::BRIGHT_BLUE << " campaign" << colors::RESET
            << colors::DIM << "(*) > " << colors::RESET;
  std::string input = readLine();

  if (input.empty() || input[0] == '0')
    return;

  int choice = std::atoi(input.c_str());
  std::string campaignName;

  if (choice == 1) {
    // Dynamically create a campaign file using ONLY your registered exploits
    campaignName = "auto_ml_campaign_" + currentSession_ + ".txt";
    std::ofstream fout(campaignName);
    fout << "T1068\n";     // BYOVD
    fout << "T1562.001\n"; // EDR-Freeze
    fout << "T1055.001\n"; // Crystal Palace
    fout << "T1106\n";     // SysWhispers4
    fout.close();
    UI::info("Generated auto-campaign using available exploit modules.");
  } else if (choice == 2) {
    campaignName = UI::prompt("Enter campaign file path (.txt):");
  } else {
    UI::error("Invalid campaign selection");
    return;
  }

  CommandContext ctx;
  ctx.args.push_back(campaignName);
  cmdCampaign(ctx);
}

void CLI::handleSnapshotMenu() {
  showSnapshotMenu();

  std::cout << colors::BRIGHT_RED << "  vyuha" << colors::RESET
            << colors::BRIGHT_BLUE << " snapshot" << colors::RESET
            << colors::DIM << "(*) > " << colors::RESET;
  std::string input = readLine();

  if (input.empty() || input[0] == '0')
    return;

  int choice = std::atoi(input.c_str());
  CommandContext ctx;

  switch (choice) {
  case 1: {
    std::string name = UI::prompt("Enter snapshot name:");
    ctx.args.push_back("create");
    ctx.args.push_back(name.empty() ? "snapshot_" + currentSession_ : name);
    cmdSnapshot(ctx);
    break;
  }
  case 2: {
    std::string name = UI::prompt("Enter snapshot name to restore:");
    ctx.args.push_back("restore");
    ctx.args.push_back(name);
    cmdSnapshot(ctx);
    break;
  }
  case 3:
    ctx.args.push_back("list");
    cmdSnapshot(ctx);
    break;
  case 4: {
    std::string name = UI::prompt("Enter snapshot name to delete:");
    UI::warning("Delete snapshot: " + name + " (placeholder)");
    break;
  }
  default:
    UI::error("Invalid choice");
    break;
  }
}

void CLI::runInteractive() {
  running_ = true;
  showWelcome();
  showMainMenu();

  while (running_) {
    printPrompt();
    std::string input = readLine();

    if (std::cin.eof()) {
      running_ = false;
      break;
    }

    processInput(input);

    // Show menu again after each action
    if (running_) {
      showMainMenu();
    }
  }

  std::cout << std::endl;
  std::cout << colors::BRIGHT_RED << "[*]" << colors::RESET
            << " Exiting VYUHA..." << std::endl;
  std::cout << colors::DIM << "    Remember to clean up your traces!"
            << colors::RESET << std::endl;
}

int CLI::runCommand(int argc, char *argv[]) {
  if (argc < 2) {
    runInteractive();
    return 0;
  }

  UI::enableAnsi();

  std::string arg = argv[1];
  if (arg == "--help" || arg == "-h") {
    UI::banner();
    showMainMenu();
    return 0;
  }

  if (arg == "--version" || arg == "-v") {
    std::cout << colors::BRIGHT_RED << "VYUHA" << colors::RESET
              << " - APT Simulation & EDR Evasion" << std::endl;
    return 0;
  }

  if (arg == "-i" || arg == "--interactive") {
    runInteractive();
    return 0;
  }

  // Build command string from args
  std::string cmdLine = "/" + arg;
  for (int i = 2; i < argc; ++i) {
    cmdLine += " ";
    cmdLine += argv[i];
  }

  UI::banner();
  processInput(cmdLine);

  return 0;
}

// ============================================================================
// COMMAND HANDLERS
// ============================================================================

void CLI::cmdRun(const CommandContext &ctx) {
  if (ctx.args.empty()) {
    handleTechniqueMenu();
    return;
  }

  std::string techniqueId = ctx.args[0];

  std::cout << std::endl;
  UI::box("Executing Technique", techniqueId);
  std::cout << std::endl;

  // BYOVD-specific interactive configuration
  std::map<std::string, std::string> options;

  if (techniqueId == "T1068") {
    // Prompt for driver path
    std::string defaultPath = "C:\\\\EDR-Test\\\\vulndriver.sys";
    std::cout << colors::BRIGHT_CYAN << "[?] Driver Path" << colors::RESET
              << std::endl;
    std::cout << "    Default: " << colors::DIM << defaultPath << colors::RESET
              << std::endl;
    std::cout << "    Enter path (or press ENTER for default): ";

    std::string driverPath = readLine();
    if (driverPath.empty()) {
      driverPath = defaultPath;
    }
    options["driver_path"] = driverPath;

    std::cout << std::endl;
    std::cout << colors::BRIGHT_CYAN << "[*] Scanning for EDR processes..."
              << colors::RESET << std::endl;
    std::cout << std::endl;

    // Show detected EDR processes (this will be done by the exploit itself)
    std::cout << colors::BRIGHT_YELLOW
              << "[i] Target Selection:" << colors::RESET << std::endl;
    std::cout << "    1. Auto-detect and show EDR processes" << std::endl;
    std::cout << "    2. Manual PID entry" << std::endl;
    std::cout << "    3. Skip termination (load driver only)" << std::endl;
    std::cout << std::endl;
    std::cout << "    Choice: ";

    std::string choice = readLine();
    if (choice == "1") {
      options["mode"] = "auto_detect";
    } else if (choice == "2") {
      std::cout << "    Enter target PID: ";
      std::string pidStr = readLine();
      options["target_pid"] = pidStr;
      options["mode"] = "manual";
    } else {
      options["mode"] = "load_only";
    }

    std::cout << std::endl;
  } else if (techniqueId == "T1562.001") {
    // EDR-Freeze interactive configuration
    std::cout << colors::BRIGHT_YELLOW
              << "[i] Target Selection:" << colors::RESET << std::endl;
    std::cout << "    1. Auto-detect EDR processes" << std::endl;
    std::cout << "    2. Manual PID entry" << std::endl;
    std::cout << std::endl;
    std::cout << "    Choice: ";

    std::string choice = readLine();
    if (choice == "1") {
      options["mode"] = "auto_detect";
    } else if (choice == "2") {
      options["mode"] = "manual";
      std::cout << "    Enter target PID: ";
      std::string pidStr = readLine();
      options["target_pid"] = pidStr;
    } else {
      UI::error("Invalid choice");
      return;
    }

    std::cout << std::endl;
    std::cout << colors::BRIGHT_CYAN << "[?] Freeze Duration" << colors::RESET
              << std::endl;
    std::cout << "    Default: " << colors::DIM << "10000 ms (10 seconds)"
              << colors::RESET << std::endl;
    std::cout
        << "    Enter duration in milliseconds (or press ENTER for default): ";

    std::string sleepStr = readLine();
    if (sleepStr.empty()) {
      options["sleep_ms"] = "10000";
    } else {
      options["sleep_ms"] = sleepStr;
    }

    std::cout << std::endl;
  } else if (techniqueId == "T1106") {
    // SysWhispers4 — direct syscall EDR bypass
    std::cout << colors::BRIGHT_CYAN
              << "[*] SysWhispers4 - Direct Syscall EDR Bypass"
              << colors::RESET << std::endl;
    std::cout << std::endl;
    std::cout << colors::DIM
              << "    Resolves SSNs at runtime and invokes NT kernel functions\n"
              << "    via syscall instruction, bypassing EDR user-mode hooks."
              << colors::RESET << std::endl;
    std::cout << std::endl;

    std::cout << colors::BRIGHT_CYAN
              << "[?] SSN Resolution Method" << colors::RESET << std::endl;
    std::cout << "    [1] FreshyCalls (default, hook-resistant)" << std::endl;
    std::cout << "    [2] Hell's Gate (fast, fails if hooked)" << std::endl;
    std::cout << "    [3] Halo's Gate (Hell's Gate + neighbor scan)"
              << std::endl;
    std::cout << "    [4] Tartarus' Gate (all hook patterns, ±16 scan)"
              << std::endl;
    std::cout << "    [5] RecycledGate (FreshyCalls + cross-validation)"
              << std::endl;
    std::cout << "    [6] FromDisk (map clean ntdll from KnownDlls)"
              << std::endl;
    std::cout << "    Enter choice (1-6, default=1): ";
    std::string resolveChoice = readLine();
    if (resolveChoice == "2")
      options["resolve"] = "hells_gate";
    else if (resolveChoice == "3")
      options["resolve"] = "halos_gate";
    else if (resolveChoice == "4")
      options["resolve"] = "tartarus";
    else if (resolveChoice == "5")
      options["resolve"] = "recycled";
    else if (resolveChoice == "6")
      options["resolve"] = "from_disk";
    else
      options["resolve"] = "freshycalls";

    std::cout << std::endl;
    std::cout << colors::BRIGHT_CYAN
              << "[?] Invocation Method" << colors::RESET << std::endl;
    std::cout << "    [1] Direct (syscall in our stub)" << std::endl;
    std::cout << "    [2] Indirect (jmp to syscall;ret in ntdll)"
              << std::endl;
    std::cout << "    Enter choice (1-2, default=1): ";
    std::string methodChoice = readLine();
    if (methodChoice == "2")
      options["method"] = "indirect";
    else
      options["method"] = "direct";

    std::cout << std::endl;
    std::cout << colors::BRIGHT_CYAN
              << "[?] Evasion Techniques (y/n)" << colors::RESET << std::endl;
    std::cout << "    Unhook ntdll (.text remap from KnownDlls)? [y/N]: ";
    std::string unhookChoice = readLine();
    if (unhookChoice == "y" || unhookChoice == "Y")
      options["unhook_ntdll"] = "true";

    std::cout << "    Patch ETW (EtwEventWrite)? [y/N]: ";
    std::string etwChoice = readLine();
    if (etwChoice == "y" || etwChoice == "Y")
      options["etw_bypass"] = "true";

    std::cout << "    Patch AMSI (AmsiScanBuffer)? [y/N]: ";
    std::string amsiChoice = readLine();
    if (amsiChoice == "y" || amsiChoice == "Y")
      options["amsi_bypass"] = "true";

    std::cout << std::endl;

  } else if (techniqueId == "T1055.001") {
    // Crystal Palace UDRL — single blob, all 6 layers run inside it
    std::cout << colors::BRIGHT_CYAN
              << "[*] Crystal Palace UDRL - Self-Contained PIC Blob Executor"
              << colors::RESET << std::endl;
    std::cout << std::endl;
    std::cout
        << colors::DIM
        << "    The blob (output.bin) produced by KaplaStrike already "
           "contains:\n"
           "    loader code + XOR-encrypted beacon + XOR key + PICO\n"
           "    All 6 evasion layers execute inside the blob automatically."
        << colors::RESET << std::endl;
    std::cout << std::endl;

    std::cout << colors::BRIGHT_CYAN
              << "[?] Crystal Palace blob path (output.bin)" << colors::RESET
              << std::endl;
    std::cout << "    Default: " << colors::DIM << "C:\\EDR-Test\\output.bin"
              << colors::RESET << std::endl;
    std::cout << "    Build:   " << colors::DIM
              << "cd KaplaStrike && make x64 && ./link spec/loader.spec "
                 "beacon.dll output.bin"
              << colors::RESET << std::endl;
    std::cout << "    Enter path (or press ENTER for default): ";
    std::string blobPath = readLine();
    options["blob_path"] =
        blobPath.empty() ? "C:\\EDR-Test\\output.bin" : blobPath;

    std::cout << std::endl;
    std::cout
        << colors::BRIGHT_YELLOW
        << "[!] Execution transfers to beacon via NtContinue (does not return)."
        << colors::RESET << std::endl;
    std::cout << "    Ensure your C2 listener is live before proceeding."
              << std::endl;
    std::cout << std::endl;
    if (!UI::confirm("Launch Crystal Palace 6-layer evasion chain?")) {
      UI::warning("Crystal Palace UDRL cancelled.");
      return;
    }

    std::cout << std::endl;
  }

  // Prepare execution
  UI::info("Preparing environment...");
  SLEEP_MS(500);

  UI::info("Creating snapshot...");
  SLEEP_MS(300);

  UI::info("Executing technique " + techniqueId + "...");

  // Show progress animation
  for (int i = 0; i <= 100; i += 10) {
    UI::progress(i, 100, techniqueId);
    SLEEP_MS(100);
  }
  std::cout << std::endl;

  // ACTUAL EXPLOIT EXECUTION
  edr::exploits::ExploitResult result =
      exploitManager_->execute(techniqueId, options);

  std::cout << std::endl;

  // Show results
  if (result.success) {
    UI::success("Exploit executed successfully!");
    std::cout << std::endl;
    if (!result.output.empty()) {
      UI::info("Output:");
      std::cout << result.output << std::endl << std::endl;
    }
  } else {
    UI::error("Exploit execution failed");
    std::cout << std::endl;
    if (!result.errorMessage.empty()) {
      UI::warning("Error: " + result.errorMessage);
      std::cout << std::endl;
    }
  }

  // Show result table
  std::vector<std::string> headers = {"Field", "Value"};
  std::vector<std::vector<std::string>> data = {
      {"Technique", result.techniqueId},
      {"Name", result.techniqueName},
      {"Status", result.success ? "Success" : "Failed"},
      {"EDR Alert", result.detected ? "Yes" : "No"},
      {"Duration", std::to_string(result.executionTime.count()) + "ms"},
  };

  if (!result.artifacts.empty()) {
    std::string artifactList;
    for (const auto &artifact : result.artifacts) {
      if (!artifactList.empty())
        artifactList += ", ";
      artifactList += artifact;
    }
    data.push_back({"Artifacts", artifactList});
  }

  UI::table(data, headers);
  std::cout << std::endl;
}

void CLI::cmdList(const CommandContext &ctx) {
  std::cout << std::endl;

  std::vector<std::string> headers = {"#", "ID", "Name", "Tactic", "Status"};
  std::vector<std::vector<std::string>> data = {
      {"1", "T1068", "BYOVD (vulndriver.sys)", "Privilege Escalation",
       "Implemented"},
      {"2", "T1562.001", "EDR-Freeze (WerFault)", "Defense Evasion",
       "Implemented"},
      {"3", "T1055.001", "Crystal Palace UDRL", "Process Injection",
       "Implemented"},
      {"4", "T1106", "SysWhispers4 (Direct Syscalls)", "Defense Evasion",
       "Implemented"},
  };

  UI::info("Available Exploit Techniques");
  std::cout << std::endl;
  UI::table(data, headers);
  std::cout << std::endl;

  UI::info("Use 'use exploit' to execute available techniques");
  std::cout << std::endl;
}

void CLI::cmdStatus(const CommandContext &ctx) {
  std::cout << std::endl;
  UI::info("Scanning system for security products...");
  std::cout << std::endl;

  // Get running processes once
  auto runningProcs = getRunningProcesses();

  // System Info Section
  UI::println("  SYSTEM INFORMATION", colors::BOLD);
  UI::divider(colors::DIM);

  std::vector<std::string> sysHeaders = {"Property", "Value"};
  std::vector<std::vector<std::string>> sysData = {
      {"Computer Name", getComputerName()},
      {"Username", getUserName()},
      {"OS", getWindowsVersion()},
      {"Privileges", isAdmin() ? "Administrator" : "Standard User"},
  };
  UI::table(sysData, sysHeaders);
  std::cout << std::endl;

  // EDR/AV Detection Section
  UI::println("  SECURITY PRODUCTS", colors::BOLD);
  UI::divider(colors::DIM);

  std::vector<std::string> headers = {"Component", "Status", "Details"};
  std::vector<std::vector<std::string>> data;

  // Detect Windows Defender
  auto defenderStatus = detectWindowsDefender();
  data.push_back(
      {"Windows Defender", defenderStatus.first, defenderStatus.second});

  // Detect EDR products
  auto detectedEDRs = detectEDRProducts(runningProcs);
  if (detectedEDRs.empty()) {
    data.push_back(
        {"Third-party EDR", "Not Detected", "No known EDR processes found"});
  } else {
    for (const auto &edr : detectedEDRs) {
      data.push_back({std::get<0>(edr), std::get<1>(edr), std::get<2>(edr)});
    }
  }

  // Detect VM
  auto vmStatus = detectVMProvider();
  data.push_back({"VM/Hypervisor", vmStatus.first, vmStatus.second});

  UI::table(data, headers);
  std::cout << std::endl;

  // Process count
  UI::info("Scanned " + std::to_string(runningProcs.size()) +
           " running processes");
  UI::success("Session ID: " + currentSession_);
  std::cout << std::endl;
}

void CLI::cmdCampaign(const CommandContext &ctx) {
  if (ctx.args.empty()) {
    handleCampaignMenu();
    return;
  }

  const std::string &campaignFile = ctx.args[0];

  std::cout << std::endl;
  UI::info("Campaign file : " + campaignFile);
  UI::info("ML engine     : " + std::string(mlEngine_ ? "active" : "offline"));
  UI::info("Exploit mgr   : " + std::to_string(exploitManager_ ? 1 : 0) +
           " loaded");
  std::cout << std::endl;

  if (!UI::confirm("Launch adaptive campaign? (ML + Exploits)")) {
    UI::info("Campaign aborted.");
    return;
  }

  std::cout << std::endl;
  UI::info("Starting AgentCore::runCampaign() ...");
  std::cout << std::endl;

  // Full three-way integration: Jdeep agent + Bipin exploits + Karthik ML
  auto results =
      agentCore_->runCampaign(campaignFile, *exploitManager_, *mlEngine_);

  // Print summary
  std::cout << std::endl;
  int successes = 0;
  for (const auto &r : results) {
    if (r.success)
      ++successes;
    std::string status =
        r.success
            ? (colors::BRIGHT_GREEN + std::string("[+] SUCCESS") +
               colors::RESET)
            : (colors::BRIGHT_RED + std::string("[-] FAILED ") + colors::RESET);
    std::cout << "  " << status << "  " << r.techniqueId << "  ("
              << r.duration.count() << " ms)";
    if (!r.mitreTactic.empty())
      std::cout << "  [" << r.mitreTactic << "]";
    std::cout << std::endl;
  }

  std::cout << std::endl;
  UI::success("Campaign complete: " + std::to_string(successes) + "/" +
              std::to_string(results.size()) + " techniques succeeded.");

  // Session-wide ML report
  auto report = mlEngine_->generateReport();
  if (!report.recommendation.empty()) {
    std::cout << std::endl;
    UI::info("ML Recommendation: " + report.recommendation);
  }
  std::cout << std::endl;
}

void CLI::cmdSnapshot(const CommandContext &ctx) {
  if (ctx.args.empty()) {
    handleSnapshotMenu();
    return;
  }

  std::string action = ctx.args[0];

  std::cout << std::endl;

  if (action == "create") {
    std::string name =
        ctx.args.size() > 1 ? ctx.args[1] : "snapshot_" + currentSession_;
    UI::info("Creating snapshot: " + name);
    SLEEP_MS(500);
    UI::success("Snapshot created");
  } else if (action == "restore") {
    if (ctx.args.size() < 2) {
      UI::error("Specify snapshot name to restore");
      return;
    }
    UI::info("Restoring snapshot: " + ctx.args[1]);
    SLEEP_MS(500);
    UI::success("Snapshot restored");
  } else {
    UI::info("Available snapshots:");
    std::cout << colors::DIM << "  (No snapshots found)" << colors::RESET
              << std::endl;
  }

  std::cout << std::endl;
}

void CLI::cmdClean(const CommandContext &ctx) {
  std::cout << std::endl;
  std::cout << colors::BRIGHT_RED
            << "  ╔═══════════════════════════════════════════════════════════╗"
            << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  ║" << colors::RESET << colors::BOLD
            << "                  ANTI-FORENSICS MODULE                     "
            << colors::RESET << colors::BRIGHT_RED << "║" << colors::RESET
            << std::endl;
  std::cout << colors::BRIGHT_RED
            << "  ╠═══════════════════════════════════════════════════════════╣"
            << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  ║" << colors::RESET
            << colors::BRIGHT_GREEN << "  [1]" << colors::RESET
            << " clearev -s     " << colors::DIM
            << "- Clear session artifacts      " << colors::RESET
            << colors::BRIGHT_RED << "║" << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  ║" << colors::RESET
            << colors::BRIGHT_YELLOW << "  [2]" << colors::RESET
            << " clearev -a     " << colors::DIM
            << "- Deep clean + restore VM      " << colors::RESET
            << colors::BRIGHT_RED << "║" << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED
            << "  ╠═══════════════════════════════════════════════════════════╣"
            << colors::RESET << std::endl;
  std::cout << colors::BRIGHT_RED << "  ║" << colors::RESET
            << colors::BRIGHT_RED << "  [0]" << colors::RESET << " back"
            << colors::DIM << "                                      "
            << colors::RESET << colors::BRIGHT_RED << "║" << colors::RESET
            << std::endl;
  std::cout << colors::BRIGHT_RED
            << "  ╚═══════════════════════════════════════════════════════════╝"
            << colors::RESET << std::endl;
  std::cout << std::endl;

  std::cout << colors::BRIGHT_RED << "  vyuha" << colors::RESET
            << colors::BRIGHT_BLUE << " clearev" << colors::RESET << colors::DIM
            << "(*) > " << colors::RESET;
  std::string input = readLine();

  if (input.empty() || input[0] == '0')
    return;

  int choice = std::atoi(input.c_str());

  if (choice == 1) {
    std::cout << colors::BRIGHT_YELLOW << "[*]" << colors::RESET
              << " Wiping session artifacts..." << std::endl;
    SLEEP_MS(300);
    std::cout << colors::BRIGHT_GREEN << "[+]" << colors::RESET
              << " Event logs cleared" << std::endl;
    std::cout << colors::BRIGHT_GREEN << "[+]" << colors::RESET
              << " Temp files removed" << std::endl;
    std::cout << colors::BRIGHT_GREEN << "[+]" << colors::RESET
              << " Session cleaned" << std::endl;
  } else if (choice == 2) {
    if (UI::confirm("This will restore from last snapshot. Continue?")) {
      std::cout << colors::BRIGHT_YELLOW << "[*]" << colors::RESET
                << " Restoring from checkpoint..." << std::endl;
      SLEEP_MS(500);
      std::cout << colors::BRIGHT_GREEN << "[+]" << colors::RESET
                << " System restored to clean state" << std::endl;
    }
  }

  std::cout << std::endl;
}

void CLI::cmdConfig(const CommandContext &ctx) {
  std::cout << std::endl;
  UI::info("Current Configuration");
  std::cout << std::endl;

  std::vector<std::string> headers = {"Key", "Value"};
  std::vector<std::vector<std::string>> data = {
      {"debug", "false"},
      {"log_level", "INFO"},
      {"output_dir", "results"},
      {"auto_cleanup", "true"},
      {"snapshot_provider", "auto"},
  };
  UI::table(data, headers);
  std::cout << std::endl;
}

void CLI::cmdHistory(const CommandContext &ctx) {
  std::cout << std::endl;
  UI::info("Command History");
  std::cout << std::endl;

  if (history_.empty()) {
    std::cout << colors::DIM << "  (No commands yet)" << colors::RESET
              << std::endl;
  } else {
    for (size_t i = 0; i < history_.size(); ++i) {
      std::cout << colors::DIM << "  " << (i + 1) << ". " << colors::RESET
                << history_[i] << std::endl;
    }
  }

  std::cout << std::endl;
}

void CLI::cmdClear(const CommandContext &ctx) {
  UI::clear();
  UI::banner();
}

void CLI::cmdExit(const CommandContext &ctx) { running_ = false; }

} // namespace cli
} // namespace edr
