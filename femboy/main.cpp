#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <map>
#include <algorithm>
#include <memory>
#include <execution>
#include <mutex>
#include <cstring>
#include <iomanip>
#include <filesystem>
#include <Windows.h>
#include <TlHelp32.h>
#include "database.hpp"

struct ModuleInfo {
    uintptr_t base;
    size_t size;
};

struct SectionInfo {
    uint32_t rva;
    uint32_t size;
};

struct PESections {
    SectionInfo text;
    SectionInfo rdata;
};

struct ScannedModule {
    std::string name;
    uintptr_t base;
    size_t size;
    std::vector<uint8_t> image;
    PESections sections;
};

std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

DWORD GetProcessIdByName(const std::wstring& processName) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (processName == pe.szExeFile) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &pe));
    }
    CloseHandle(snapshot);
    return pid;
}

std::map<std::string, ModuleInfo> GetProcessModules(DWORD pid) {
    std::map<std::string, ModuleInfo> modules;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return modules;
    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    if (Module32FirstW(snapshot, &me)) {
        do {
            std::wstring wname(me.szModule);
            std::string name = WStringToString(wname);
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);
            modules[name] = { reinterpret_cast<uintptr_t>(me.modBaseAddr), me.modBaseSize };
        } while (Module32NextW(snapshot, &me));
    }
    CloseHandle(snapshot);
    return modules;
}

std::vector<uint8_t> ReadModuleMemory(HANDLE process, uintptr_t base, size_t size) {
    std::vector<uint8_t> buffer(size, 0);
    uintptr_t current = base;
    while (current < base + size) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(current), &mbi, sizeof(mbi)) == 0) {
            break;
        }
        size_t region_size = mbi.RegionSize;
        if (current + region_size > base + size) {
            region_size = base + size - current;
        }
        bool is_readable = (mbi.State == MEM_COMMIT) &&
                           !(mbi.Protect & PAGE_NOACCESS) &&
                           !(mbi.Protect & PAGE_GUARD);
        if (is_readable) {
            SIZE_T bytes_read = 0;
            ReadProcessMemory(process, reinterpret_cast<LPCVOID>(current), &buffer[current - base], region_size, &bytes_read);
        }
        current += mbi.RegionSize;
    }
    return buffer;
}

PESections ParsePE(const std::vector<uint8_t>& image) {
    PESections sections{};
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) return sections;
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return sections;
    if (image.size() < dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64)) return sections;
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return sections;
    auto section_header = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        auto& sec = section_header[i];
        std::string name(reinterpret_cast<const char*>(sec.Name), 8);
        if (name.find(".text") != std::string::npos) {
            sections.text.rva = sec.VirtualAddress;
            sections.text.size = sec.Misc.VirtualSize;
        } else if (name.find(".rdata") != std::string::npos) {
            sections.rdata.rva = sec.VirtualAddress;
            sections.rdata.size = sec.Misc.VirtualSize;
        }
    }
    return sections;
}

struct ParsedPattern {
    std::vector<uint8_t> bytes;
    std::vector<bool> mask;
};

ParsedPattern ParsePattern(const std::string& needle) {
    ParsedPattern pattern;
    std::stringstream ss(needle);
    std::string token;
    while (ss >> token) {
        if (token == "?" || token == "??") {
            pattern.bytes.push_back(0);
            pattern.mask.push_back(false);
        } else {
            pattern.bytes.push_back(static_cast<uint8_t>(std::stoul(token, nullptr, 16)));
            pattern.mask.push_back(true);
        }
    }
    return pattern;
}

ptrdiff_t FindPattern(const uint8_t* data, size_t size, const ParsedPattern& pattern) {
    if (pattern.bytes.empty() || size < pattern.bytes.size()) return -1;
    size_t scan_limit = size - pattern.bytes.size();
    uint8_t first = pattern.bytes[0];
    bool first_wild = !pattern.mask[0];

    if (!first_wild) {
        const uint8_t* ptr = data;
        const uint8_t* limit = data + scan_limit;
        while (ptr <= limit) {
            ptr = static_cast<const uint8_t*>(std::memchr(ptr, first, limit - ptr + 1));
            if (!ptr) break;
            size_t i = ptr - data;
            bool found = true;
            for (size_t j = 1; j < pattern.bytes.size(); j++) {
                if (pattern.mask[j] && data[i + j] != pattern.bytes[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return i;
            ptr++;
        }
    } else {
        for (size_t i = 0; i <= scan_limit; i++) {
            bool found = true;
            for (size_t j = 0; j < pattern.bytes.size(); j++) {
                if (pattern.mask[j] && data[i + j] != pattern.bytes[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return i;
        }
    }
    return -1;
}

std::vector<bool> GetRelocatableMask(const std::vector<uint8_t>& bytes) {
    std::vector<bool> mask(bytes.size(), true);
    size_t i = 0;
    while (i < bytes.size()) {
        uint8_t b = bytes[i];
        if ((b == 0xE8 || b == 0xE9) && i + 5 <= bytes.size()) {
            for (size_t j = 0; j < 4; j++) {
                mask[i + 1 + j] = false;
            }
            i += 5;
            continue;
        }
        if (b == 0x0F && i + 6 <= bytes.size() && (bytes[i + 1] & 0xF0) == 0x80) {
            for (size_t j = 0; j < 4; j++) {
                mask[i + 2 + j] = false;
            }
            i += 6;
            continue;
        }
        if ((b & 0xF8) == 0x48 && i + 7 <= bytes.size()) {
            uint8_t op2 = bytes[i + 1];
            uint8_t modrm = bytes[i + 2];
            bool rip_rel_op = (op2 == 0x03 || op2 == 0x0B || op2 == 0x13 || op2 == 0x1B ||
                               op2 == 0x23 || op2 == 0x2B || op2 == 0x33 || op2 == 0x3B ||
                               op2 == 0x85 || op2 == 0x89 || op2 == 0x8B || op2 == 0x8D);
            if (rip_rel_op && (modrm & 0xC7) == 0x05) {
                for (size_t j = 0; j < 4; j++) {
                    mask[i + 3 + j] = false;
                }
                i += 7;
                continue;
            }
        }
        if ((b == 0x8B || b == 0x89 || b == 0x8D) && i + 6 <= bytes.size()) {
            uint8_t modrm = bytes[i + 1];
            if ((modrm & 0xC7) == 0x05) {
                for (size_t j = 0; j < 4; j++) {
                    mask[i + 2 + j] = false;
                }
                i += 6;
                continue;
            }
        }
        i++;
    }
    return mask;
}

size_t CountMatchesCapped(const uint8_t* hay, size_t hay_size, const std::vector<uint8_t>& bytes, const std::vector<bool>& mask, size_t cap) {
    size_t need = bytes.size();
    if (hay_size < need || need == 0) return 0;
    uint8_t first = bytes[0];
    bool first_wild = !mask[0];
    size_t end = hay_size - need;
    size_t count = 0;

    if (!first_wild) {
        const uint8_t* ptr = hay;
        const uint8_t* limit = hay + end;
        while (ptr <= limit) {
            ptr = static_cast<const uint8_t*>(std::memchr(ptr, first, limit - ptr + 1));
            if (!ptr) break;
            size_t i = ptr - hay;
            bool ok = true;
            for (size_t j = 1; j < need; j++) {
                if (mask[j] && hay[i + j] != bytes[j]) {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                count++;
                if (count >= cap) return count;
            }
            ptr++;
        }
    } else {
        for (size_t i = 0; i <= end; i++) {
            bool ok = true;
            for (size_t j = 0; j < need; j++) {
                if (mask[j] && hay[i + j] != bytes[j]) {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                count++;
                if (count >= cap) return count;
            }
        }
    }
    return count;
}

std::string FormatIda(const std::vector<uint8_t>& bytes, const std::vector<bool>& mask) {
    std::stringstream ss;
    for (size_t i = 0; i < bytes.size(); i++) {
        if (i > 0) ss << " ";
        if (mask[i]) {
            ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
        } else {
            ss << "?";
        }
    }
    return ss.str();
}

std::string SynthesizePattern(const uint8_t* image, size_t image_size, uint32_t text_rva, uint32_t text_size, uintptr_t rva) {
    size_t lo = static_cast<size_t>(rva);
    size_t text_lo = static_cast<size_t>(text_rva);
    size_t text_hi = text_lo + static_cast<size_t>(text_size);
    if (lo < text_lo || lo >= text_hi) return "";
    size_t cap = text_hi < image_size ? text_hi : image_size;

    std::vector<size_t> try_lengths = { 16, 20, 24, 28, 32, 40, 48 };
    std::string best_fallback = "";
    for (size_t len : try_lengths) {
        size_t hi = lo + len;
        if (hi > cap) hi = cap;
        if (hi <= lo) break;
        std::vector<uint8_t> bytes(image + lo, image + hi);
        if (bytes.empty()) break;
        auto mask = GetRelocatableMask(bytes);
        size_t count = CountMatchesCapped(image + text_lo, text_size, bytes, mask, 2);
        if (count == 1) {
            return FormatIda(bytes, mask);
        }
        best_fallback = FormatIda(bytes, mask);
    }
    return best_fallback;
}

std::string CleanModuleName(const std::string& mod) {
    std::string name = mod;
    size_t dot = name.find(".dll");
    if (dot != std::string::npos) name = name.substr(0, dot);
    std::replace(name.begin(), name.end(), '.', '_');
    return name;
}

int main() {
    std::wstring process_name = L"cs2.exe";
    DWORD pid = GetProcessIdByName(process_name);
    if (!pid) {
        std::cerr << "Process cs2.exe not found." << std::endl;
        return 1;
    }

    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!process) {
        std::cerr << "Failed to open process." << std::endl;
        return 1;
    }

    auto raw_modules = GetProcessModules(pid);
    std::map<std::string, ScannedModule> modules;
    for (auto& pattern : g_patterns) {
        std::string mod_name = pattern.module_name;
        std::transform(mod_name.begin(), mod_name.end(), mod_name.begin(), ::tolower);
        if (modules.find(mod_name) == modules.end()) {
            auto it = raw_modules.find(mod_name);
            if (it != raw_modules.end()) {
                ScannedModule sm{};
                sm.name = pattern.module_name;
                sm.base = it->second.base;
                sm.size = it->second.size;
                sm.image = ReadModuleMemory(process, sm.base, sm.size);
                sm.sections = ParsePE(sm.image);
                modules[mod_name] = sm;
            }
        }
    }

    std::map<std::string, std::map<std::string, std::string>> resolved_signatures;
    std::map<std::string, std::map<std::string, uintptr_t>> resolved_offsets;
    int found_count = 0;
    int total_count = 0;

    std::mutex mtx;
    std::for_each(std::execution::par, g_patterns.begin(), g_patterns.end(), [&](const Pattern& pattern) {
        std::string mod_name = pattern.module_name;
        std::transform(mod_name.begin(), mod_name.end(), mod_name.begin(), ::tolower);
        auto it = modules.find(mod_name);
        if (it == modules.end()) {
            std::lock_guard<std::mutex> lock(mtx);
            std::cout << "Dumping [" << pattern.module_name << "] " << pattern.name << " -> Module not loaded" << std::endl;
            return;
        }

        auto& sm = it->second;
        auto parsed = ParsePattern(pattern.needle);

        ptrdiff_t match_offset = -1;
        if (sm.sections.text.size > 0) {
            match_offset = FindPattern(sm.image.data() + sm.sections.text.rva, sm.sections.text.size, parsed);
            if (match_offset != -1) {
                match_offset += sm.sections.text.rva;
            }
        }

        if (match_offset == -1 && sm.sections.rdata.size > 0) {
            match_offset = FindPattern(sm.image.data() + sm.sections.rdata.rva, sm.sections.rdata.size, parsed);
            if (match_offset != -1) {
                match_offset += sm.sections.rdata.rva;
            }
        }

        if (match_offset == -1) {
            match_offset = FindPattern(sm.image.data(), sm.image.size(), parsed);
        }

        if (match_offset == -1) {
            std::lock_guard<std::mutex> lock(mtx);
            std::cout << "Dumping [" << pattern.module_name << "] " << pattern.name << " -> Pattern not found" << std::endl;
            return;
        }

        uintptr_t match_rva = static_cast<uintptr_t>(match_offset);
        uintptr_t match_va = sm.base + match_rva;
        uintptr_t resolved_rva = 0;

        if (pattern.resolve == ResolveKind::None) {
            resolved_rva = match_rva + pattern.extra_off;
        } else if (pattern.resolve == ResolveKind::Rel32 || pattern.resolve == ResolveKind::RipRel) {
            uintptr_t disp_addr = match_rva + pattern.rel_off;
            if (disp_addr + 4 <= sm.image.size()) {
                int32_t disp = 0;
                std::memcpy(&disp, &sm.image[disp_addr], 4);
                uintptr_t resolved_va = match_va + pattern.rel_off + 4 + disp + pattern.extra_off;
                resolved_rva = resolved_va - sm.base;
            }
        }

        std::string synth_pattern = "";
        if (sm.sections.text.size > 0) {
            synth_pattern = SynthesizePattern(sm.image.data(), sm.image.size(), sm.sections.text.rva, sm.sections.text.size, resolved_rva);
        }
        if (synth_pattern.empty()) {
            synth_pattern = pattern.needle;
        }

        {
            std::lock_guard<std::mutex> lock(mtx);
            resolved_signatures[sm.name][pattern.name] = synth_pattern;
            resolved_offsets[sm.name][pattern.name] = resolved_rva;

            std::cout << "Dumping [" << pattern.module_name << "] " << pattern.name << " -> " << synth_pattern << std::endl;
            found_count++;
        }
    });
    total_count = static_cast<int>(g_patterns.size());

    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    std::filesystem::path exe_dir = std::filesystem::path(path).parent_path();
    std::ofstream out_sig(exe_dir / "signatures.hpp");
    if (out_sig.is_open()) {
        out_sig << "#pragma once" << std::endl;
        out_sig << "#include <string_view>" << std::endl << std::endl;
        out_sig << "namespace signatures {" << std::endl;
        for (auto& mod_pair : resolved_signatures) {
            out_sig << "    namespace " << CleanModuleName(mod_pair.first) << " {" << std::endl;
            for (auto& sig_pair : mod_pair.second) {
                out_sig << "        inline constexpr std::string_view " << sig_pair.first << " = \"" 
                        << sig_pair.second << "\";" << std::endl;
            }
            out_sig << "    }" << std::endl;
        }
        out_sig << "}" << std::endl;
        out_sig.close();
    }

    std::ofstream out_off(exe_dir / "offsets.hpp");
    if (out_off.is_open()) {
        out_off << "#pragma once" << std::endl;
        out_off << "#include <cstddef>" << std::endl << std::endl;
        out_off << "namespace offsets {" << std::endl;
        for (auto& mod_pair : resolved_offsets) {
            out_off << "    namespace " << CleanModuleName(mod_pair.first) << " {" << std::endl;
            for (auto& off_pair : mod_pair.second) {
                out_off << "        inline constexpr std::ptrdiff_t " << off_pair.first << " = 0x" 
                        << std::hex << std::uppercase << off_pair.second << ";" << std::endl;
            }
            out_off << "    }" << std::endl;
        }
        out_off << "}" << std::endl;
        out_off.close();
    }

    std::cout << "Done! Found " << found_count << " of " << total_count << " signatures." << std::endl;
    CloseHandle(process);
    return 0;
}
