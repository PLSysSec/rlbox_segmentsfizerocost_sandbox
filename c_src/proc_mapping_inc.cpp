#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <sstream>
#include <stdint.h>
#include <string.h>
#include <vector>

#include <dlfcn.h>
#include <linux/limits.h>
#include <sys/mman.h>
#include <unistd.h>

#include "segmentsfi_sandbox_runtime.h"

struct RangeLine {
    bool found;
    uint64_t start;
    uint64_t end;
    std::string flags;
    std::string path;
};

static uint64_t parseHex(std::string val) {
    uint64_t x;
    std::stringstream ss;
    ss << std::hex << val;
    ss >> x;
    return x;
}

// A line looks like the following
// 7f906d9aa000-7f906db91000 r-xp 00000000 103:01 13272328                  /lib/x86_64-linux-gnu/libc-2.27.so
static RangeLine parseLine(std::string line) {
    RangeLine ret;

    std::istringstream iss(line);

    std::string range;
    iss >> range;

    std::string::size_type pos = range.find('-');
    if(range.npos == pos) {
        ret.found = false;
        return ret;
    } else {
        ret.start = parseHex(range.substr(0, pos));
        ret.end = parseHex(range.substr(pos + 1));
    }

    iss >> ret.flags;

    std::string dummy;
    iss >> dummy;
    iss >> dummy;
    iss >> dummy;

    iss >> ret.path;
    // std::cout << "Substring: " << ret.start << std::endl;
    // std::cout << "Substring: " << ret.end << std::endl;
    // std::cout << "Substring: " << ret.flags << std::endl;
    // std::cout << "Substring: " << ret.path << std::endl;
    ret.found = true;
    return ret;
}

 static std::vector<RangeLine> loadRanges() {
    char command[256];
    sprintf(command, "/proc/%d/maps", getpid());
    std::ifstream file(command);

    std::vector<RangeLine> ranges;
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line))
        {
            auto ret = parseLine(line);
            if (ret.found && ret.flags[0] == 'r') {
                ranges.emplace_back(ret);
            }
        }
        file.close();
    }

    return ranges;
}

struct Range {
    char* start;
    char* end;
};

struct LoadedLibInfo {
    std::vector<Range> library_ranges;
};

static std::map<std::string, LoadedLibInfo> libInfo;
static std::shared_mutex mutex_libInfo;

static void load_procmap_library_info() {
    std::vector<RangeLine> ranges = loadRanges();

    std::unique_lock lock(mutex_libInfo);
    libInfo.clear();
    for(auto& r : ranges){
        libInfo[r.path].library_ranges.emplace_back(Range{
            (char*) (uintptr_t) r.start,
            (char*) (uintptr_t) r.end
        });
    }

    for (auto& element : libInfo) {
        struct {
            bool operator()(Range& a, Range& b) const
            {
                if (a.start < b.start) {
                    return true;
                } else if (a.start > b.start) {
                    return false;
                }  else {
                    return a.end < b.end;
                }
            }
        } customCompare;

        std::sort(element.second.library_ranges.begin(), element.second.library_ranges.end(), customCompare);
    }
}

// static
std::unique_ptr<RemappedLib> RemappedLib::create_remapped_lib(const char* libName, bool isFullPath, int flag, char* target) {
    std::string fullPath;

    if (isFullPath) {
        fullPath = libName;
    } else {
        char buffer[PATH_MAX+1];
        if (!realpath(libName, buffer)) {
            printf("Could not execute realpath!\n");
            abort();
        }
        fullPath = buffer;
    }

    void* originalLib = dlopen(fullPath.c_str(), flag);
    if (originalLib == nullptr) {
        return nullptr;
    }

    // Update the metadata
    load_procmap_library_info();

    std::shared_lock lock(mutex_libInfo);
    auto it = libInfo.find(fullPath);
    if (it == libInfo.end()) {
        return nullptr;
    }

    auto& curr = it->second;
    std::vector<Range>& ranges = curr.library_ranges;
    char* start = ranges[0].start;
    char* end = ranges[ranges.size() - 1].end;
    size_t total_size = end - start + 1;
    uint32_t chosen_page_offset = 0;

    for(auto& r : ranges) {
        uint64_t offset = r.start - start + chosen_page_offset;
        uint64_t size = r.end - r.start;
        // printf("target + offset: %p\n", (void*)(target + offset));
        // printf("r.start: %p\n", (void*)(r.start));
        // printf("size: %lu\n", (uint64_t)(size));
        memcpy(target + offset, r.start, size);
    }

    auto ret = std::make_unique<RemappedLib>();
    ret->libBase = target;
    ret->offset = chosen_page_offset;
    ret->length = total_size;
    ret->originalLib = originalLib;
    ret->originalLibBase = start;
    return ret;
}

void* RemappedLib::symbol_lookup(const char *symbol) {
    if (originalLib == nullptr) {
        abort();
    }
    void* sym = dlsym(originalLib, symbol);
    if (!sym) {
        return sym;
    }
    auto address = ((char*) sym - (char*) originalLibBase) + (char*) libBase + offset;
    return address;
}

RemappedLib::~RemappedLib() {
    if (originalLib != nullptr) {
        dlclose(originalLib);
        originalLib = nullptr;
    }
}