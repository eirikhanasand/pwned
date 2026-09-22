// Single-source, bounded in-memory SHA-1 builder. Never removes source data.
// Compile with -O3 -std=c++17 -fopenmp; link libcrypto and zlib.
#include <openssl/sha.h>
#include <zlib.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#ifdef _OPENMP
#include <omp.h>
#endif

using Bytes = std::vector<unsigned char>;
constexpr uint64_t PREFIXES = 1 << 20, BLOCK_LIMIT = 64 << 20;
constexpr uint64_t HEADROOM = 4ULL << 30, BATCH = 64 << 20;
struct Record { unsigned char hash[20], line[5]; };
static_assert(sizeof(Record) == 25, "records must be packed");
static_assert(sizeof(size_t) >= 8, "64-bit host required");

static std::string hex(const unsigned char* data, size_t size) {
    const char* digits = "0123456789abcdef";
    std::string result(size * 2, '0');
    for (size_t i = 0; i < size; ++i) { result[2*i] = digits[data[i] >> 4]; result[2*i+1] = digits[data[i] & 15]; }
    return result;
}
static std::string quote(const std::string& value) {
    std::string result = "\"";
    for (unsigned char c : value) {
        if (c == '\\' || c == '"') { result += '\\'; result += c; }
        else if (c < 32 || c >= 127) throw std::runtime_error("catalog name must be printable ASCII");
        else result += c;
    }
    return result + '"';
}
static uint64_t number(const char* text) {
    std::string s(text); size_t used = 0;
    if (s.empty() || s.find_first_not_of("0123456789") != std::string::npos) throw std::runtime_error("invalid integer");
    uint64_t result = std::stoull(s, &used);
    if (used != s.size()) throw std::runtime_error("invalid integer");
    return result;
}
static void append(Bytes& out, uint64_t value, unsigned width) {
    for (unsigned i = 0; i < width; ++i) out.push_back(value >> (i * 8));
}
static uint64_t get(const unsigned char* data, unsigned width) {
    uint64_t value = 0;
    for (unsigned i = 0; i < width; ++i) value |= uint64_t(data[i]) << (i * 8);
    return value;
}
static void varint(Bytes& out, uint64_t value) {
    while (value >= 128) { out.push_back((value & 127) | 128); value >>= 7; }
    out.push_back(value);
}
static uint64_t lineOf(const Record& r) {
    uint64_t value = 0;
    for (unsigned char c : r.line) value = (value << 8) | c;
    return value;
}
static void setLine(Record& r, uint64_t value) {
    for (int i = 4; i >= 0; --i) { r.line[i] = value & 255; value >>= 8; }
}
static uint32_t prefixOf(const Record& r) { return (uint32_t(r.hash[0]) << 12) | (r.hash[1] << 4) | (r.hash[2] >> 4); }
static bool less(const Record& a, const Record& b) { return memcmp(&a, &b, sizeof(Record)) < 0; }
static bool sameSnapshot(const struct stat& a, const struct stat& b) {
#ifdef __APPLE__
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_size == b.st_size &&
        a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec &&
        a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec;
#else
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_size == b.st_size &&
        a.st_mtim.tv_sec == b.st_mtim.tv_sec && a.st_mtim.tv_nsec == b.st_mtim.tv_nsec &&
        a.st_ctim.tv_sec == b.st_ctim.tv_sec && a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
#endif
}

struct Builder {
    std::string source, output, partial, statusPath, catalog, expectedSha;
    uint64_t expectedLines, expectedLF, expectedBytes, memory, reserve, allocated;
    unsigned threads;
    int sourceFd = -1, outFd = -1, lockFd = -1, directoryFd = -1;
    struct stat before{};
    Record* records = nullptr;
    uint64_t hashedLines = 0, hashedLF = 0, readBytes = 0, writtenBytes = 0, unique = 0, verifiedLines = 0;
    std::chrono::steady_clock::time_point started = std::chrono::steady_clock::now(), lastStatus = started;
    std::string phase = "starting", sourceSha;
    bool waiting = false, ownsLock = false;

    Builder(char** argv) : source(argv[1]), output(argv[2]), partial(output + ".partial"), statusPath(output + ".status.json"),
        catalog("[" + quote(argv[3]) + "]"), expectedSha(argv[7]), expectedLines(number(argv[4])),
        expectedLF(number(argv[5])), expectedBytes(number(argv[6])), memory(number(argv[8])),
        reserve(number(argv[9])), threads(number(argv[10])) {
        if (expectedLines >= (1ULL << 40) || memory < HEADROOM || expectedLines > (memory - HEADROOM) / sizeof(Record))
            throw std::runtime_error("packed records exceed memory budget or 40-bit line capacity");
        if (!threads || number(argv[10]) > 64 || expectedSha.size() != 64 || expectedSha.find_first_not_of("0123456789abcdef") != std::string::npos)
            throw std::runtime_error("invalid threads or SHA-256");
        allocated = expectedLines * sizeof(Record);
    }
    ~Builder() {
        if (records) munmap(records, allocated);
        if (sourceFd >= 0) close(sourceFd);
        if (outFd >= 0) close(outFd);
        if (lockFd >= 0) close(lockFd);
        if (directoryFd >= 0) close(directoryFd);
    }
    virtual void unchanged() {
        struct stat current{}, named{};
        if (fstat(sourceFd, &current) || lstat(source.c_str(), &named) || !sameSnapshot(before, current) || !sameSnapshot(before, named))
            throw std::runtime_error("source snapshot changed; original retained, release not published");
    }
    virtual std::pair<uint64_t, uint64_t> location(uint64_t line) const { return {0, line}; }
    virtual void noteFileHash(uint64_t) {}
    uint64_t freeSpace() {
#ifdef PWNED_TESTING
        if (const char* path = getenv("PWNED_TEST_SPACE_FILE")) {
            std::ifstream input(path); uint64_t value;
            if (!(input >> value)) throw std::runtime_error("invalid simulated space");
            return value > writtenBytes ? value - writtenBytes : 0;
        }
#endif
        struct statvfs s{};
        if (fstatvfs(directoryFd, &s)) throw std::runtime_error("cannot inspect disk space");
        return uint64_t(s.f_bavail) * s.f_frsize;
    }
    void status(bool force = false, const std::string& extra = "") {
        auto now = std::chrono::steady_clock::now();
        if (!force && now - lastStatus < std::chrono::seconds(10)) return;
        lastStatus = now;
        std::string data = "{\"state\":" + quote(waiting ? "waiting_for_disk" : phase) +
            ",\"phase\":" + quote(phase) + ",\"sourceBytes\":" + std::to_string(expectedBytes) +
            ",\"readBytes\":" + std::to_string(readBytes) + ",\"expectedLines\":" + std::to_string(expectedLines) +
            ",\"hashedLines\":" + std::to_string(hashedLines) + ",\"hashedNewlines\":" + std::to_string(hashedLF) +
            ",\"uniqueHashes\":" + std::to_string(unique) + ",\"verifiedLines\":" + std::to_string(verifiedLines) +
            ",\"writtenBytes\":" + std::to_string(writtenBytes) + ",\"recordMemoryBytes\":" + std::to_string(allocated) +
            ",\"memoryLimitBytes\":" + std::to_string(memory) + ",\"diskReserveBytes\":" + std::to_string(reserve) +
            ",\"elapsedSeconds\":" + std::to_string(std::chrono::duration<double>(now - started).count()) + extra + "}\n";
        std::cout << data << std::flush;
        if (!ownsLock) return;  // A rejected concurrent run must not alter status.
        // Status is best effort on a completely full volume; stdout remains usable.
        std::string temp = statusPath + ".new";
        int fd = open(temp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
        if (fd >= 0) {
            size_t offset = 0;
            while (offset < data.size()) {
                ssize_t n = write(fd, data.data() + offset, data.size() - offset);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) break;
                offset += n;
            }
            bool ok = offset == data.size() && fsync(fd) == 0;
            close(fd);
            if (ok) { if (rename(temp.c_str(), statusPath.c_str()) == 0) fsync(directoryFd); }
        }
    }
    void waitSpace(uint64_t needed, bool forceWait = false) {
        for (;;) {
            auto free = freeSpace();
            if (!forceWait && free >= reserve && free - reserve >= needed) break;
            waiting = true;
            status(true, ",\"freeDiskBytes\":" + std::to_string(free) + ",\"nextWriteBytes\":" + std::to_string(needed));
            std::this_thread::sleep_for(std::chrono::seconds(5));
            forceWait = false;
        }
        if (waiting) { unchanged(); waiting = false; status(true); }
    }
    void writeAt(const unsigned char* data, uint64_t size, uint64_t offset, bool growing = true) {
        while (size) {
            size_t chunk = std::min<uint64_t>(size, 8 << 20);
            waitSpace(growing ? chunk : 0);
            ssize_t n = pwrite(outFd, data, chunk, offset);
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && (errno == ENOSPC || errno == EDQUOT)) { waitSpace(chunk, true); continue; }
            if (n <= 0) throw std::runtime_error("output write failed; original retained");
            data += n; size -= n; offset += n;
            writtenBytes = std::max(writtenBytes, offset);
        }
    }
    void syncOutput() {
        while (fsync(outFd)) {
            if (errno == EINTR) continue;
            if (errno == ENOSPC || errno == EDQUOT) { waitSpace(8 << 20, true); continue; }
            throw std::runtime_error("output sync failed; original retained");
        }
    }
    void readAt(unsigned char* data, uint64_t size, uint64_t offset) {
        while (size) {
            ssize_t n = pread(outFd, data, std::min<uint64_t>(size, 8 << 20), offset);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) throw std::runtime_error("saved index is truncated or unreadable");
            data += n; size -= n; offset += n;
        }
    }
    void setup() {
        std::string directory = output.substr(0, output.find_last_of('/'));
        if (output.find_last_of('/') == std::string::npos) directory = ".";
        directoryFd = open(directory.c_str(), O_RDONLY | O_DIRECTORY);
        if (directoryFd < 0) throw std::runtime_error("output directory must already exist");
        lockFd = open((output + ".lock").c_str(), O_CREAT | O_RDWR | O_NOFOLLOW, 0600);
        if (lockFd < 0 || flock(lockFd, LOCK_EX | LOCK_NB)) throw std::runtime_error("another builder owns this output");
        ownsLock = true;
        struct stat existing{};
        if (lstat(output.c_str(), &existing) == 0 || lstat(partial.c_str(), &existing) == 0)
            throw std::runtime_error("output or partial file already exists; inspect it before restarting");
        sourceFd = open(source.c_str(), O_RDONLY | O_NOFOLLOW);
        if (sourceFd < 0 || fstat(sourceFd, &before) || !S_ISREG(before.st_mode) || uint64_t(before.st_size) != expectedBytes)
            throw std::runtime_error("source is not the expected regular file");
        if (allocated) {
            void* mapping = mmap(nullptr, allocated, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (mapping == MAP_FAILED) throw std::runtime_error("cannot allocate packed records");
            records = static_cast<Record*>(mapping);
#ifdef MADV_DONTDUMP
            madvise(records, allocated, MADV_DONTDUMP);
#endif
        }
        status(true);
    }
    void hashInput() {
        phase = "hashing"; status(true);
        Bytes buffer; buffer.reserve(BATCH + BLOCK_LIMIT);
        SHA256_CTX sourceDigest; SHA256_Init(&sourceDigest);
        bool eof = false;
        while (!eof || !buffer.empty()) {
            if (!eof) {
                size_t old = buffer.size(); buffer.resize(old + BATCH);
                ssize_t n;
                do { n = read(sourceFd, buffer.data() + old, BATCH); } while (n < 0 && errno == EINTR);
                if (n < 0) throw std::runtime_error("source read failed");
                buffer.resize(old + n);
                if (n) {
                    SHA256_Update(&sourceDigest, buffer.data() + old, n); readBytes += n;
                    if (readBytes > expectedBytes) throw std::runtime_error("source grew beyond expected size");
                }
                else eof = true;
            }
            size_t usable = buffer.size();
            if (!eof) while (usable && buffer[usable - 1] != '\n') --usable;
            if (!usable) {
                if (buffer.size() > BLOCK_LIMIT) throw std::runtime_error("source line exceeds 64 MiB bound");
                continue;
            }
            std::vector<uint64_t> boundaries(threads + 1, usable), counts(threads), lfs(threads), starts(threads);
            std::vector<unsigned> oversized(threads);
            boundaries[0] = 0;
            for (unsigned t = 1; t < threads; ++t) {
                size_t p = usable * t / threads;
                while (p && p < usable && buffer[p - 1] != '\n') ++p;
                boundaries[t] = p;
            }
#pragma omp parallel for num_threads(threads) schedule(static)
            for (unsigned t = 0; t < threads; ++t) {
                uint64_t p = boundaries[t], end = boundaries[t+1];
                while (p < end) {
                    auto next = static_cast<unsigned char*>(memchr(buffer.data() + p, '\n', end - p));
                    uint64_t stop = next ? next - buffer.data() : end;
                    if (stop - p > BLOCK_LIMIT) oversized[t] = 1;
                    ++counts[t]; if (next) ++lfs[t];
                    p = next ? next - buffer.data() + 1 : end;
                }
            }
            uint64_t total = 0;
            if (std::any_of(oversized.begin(), oversized.end(), [](unsigned value) { return value != 0; }))
                throw std::runtime_error("source line exceeds 64 MiB bound");
            for (unsigned t = 0; t < threads; ++t) { starts[t] = hashedLines + total; total += counts[t]; hashedLF += lfs[t]; }
            if (hashedLines > expectedLines || total > expectedLines - hashedLines) throw std::runtime_error("source line count exceeds expected count");
#pragma omp parallel for num_threads(threads) schedule(static)
            for (unsigned t = 0; t < threads; ++t) {
                uint64_t p = boundaries[t], end = boundaries[t+1], index = starts[t];
                while (p < end) {
                    auto next = static_cast<unsigned char*>(memchr(buffer.data() + p, '\n', end - p));
                    uint64_t stop = next ? next - buffer.data() : end;
                    uint64_t length = stop - p;
                    if (length && buffer[stop-1] == '\r') --length;
                    SHA_CTX digest; SHA1_Init(&digest); SHA1_Update(&digest, buffer.data() + p, length); SHA1_Final(records[index].hash, &digest);
                    setLine(records[index], index + 1); ++index;
                    p = next ? stop + 1 : end;
                }
            }
            hashedLines += total;
            buffer.erase(buffer.begin(), buffer.begin() + usable);
            status();
        }
        unsigned char digest[32]; SHA256_Final(digest, &sourceDigest); sourceSha = hex(digest, 32);
        unchanged();
        if (hashedLines != expectedLines || hashedLF != expectedLF || readBytes != expectedBytes || sourceSha != expectedSha)
            throw std::runtime_error("source checksum or pre-deduplication count mismatch");
        status(true, ",\"sourceSha256\":" + quote(sourceSha) + ",\"preDeduplicationCountsVerified\":true");
    }
    std::array<uint64_t, 257> partition(uint64_t start, uint64_t end, unsigned byte) {
        std::array<uint64_t, 257> bounds{};
        for (uint64_t i = start; i < end; ++i) ++bounds[records[i].hash[byte] + 1];
        bounds[0] = start;
        for (unsigned b = 1; b <= 256; ++b) bounds[b] += bounds[b-1];
        auto cursor = bounds;
        for (unsigned b = 0; b < 256; ++b) {
            while (cursor[b] < bounds[b+1]) {
                unsigned target = records[cursor[b]].hash[byte];
                if (target == b) ++cursor[b];
                else std::swap(records[cursor[b]], records[cursor[target]++]);
            }
        }
        return bounds;
    }
    void sortRecords() {
        phase = "partitioning"; status(true);
        auto outer = partition(0, expectedLines, 0);
        phase = "sorting"; status(true);
        // Two-byte radix partitioning avoids a second full-size array; each
        // thread sorts small disjoint buckets with the native in-place sort.
        uint64_t finished = 0;
#pragma omp parallel for num_threads(threads) schedule(dynamic)
        for (unsigned b = 0; b < 256; ++b) {
            auto inner = partition(outer[b], outer[b+1], 1);
            for (unsigned c = 0; c < 256; ++c)
                if (inner[c+1] > inner[c]) std::sort(records + inner[c], records + inner[c+1], less);
#pragma omp critical
            { finished += outer[b+1] - outer[b]; status(false, ",\"sortedLines\":" + std::to_string(finished)); }
        }
        // Verify ordering AND the complete original line permutation, not just
        // counts, before any deduplication can hide a missing record.
        phase = "checking_sort"; status(true);
        Bytes seen((expectedLines + 7) / 8, 0);
        for (uint64_t i = 0; i < expectedLines; ++i) {
            uint64_t line = lineOf(records[i]);
            if (!line || line > expectedLines || (i && !less(records[i-1], records[i]))) throw std::runtime_error("sort order or line number invalid");
            uint64_t bit = line - 1;
            if (seen[bit >> 3] & (1 << (bit & 7))) throw std::runtime_error("sort duplicated a source line");
            seen[bit >> 3] |= 1 << (bit & 7);
            if ((i & ((1 << 24) - 1)) == 0) status(false, ",\"checkedLines\":" + std::to_string(i));
        }
        unchanged();
    }
    Bytes rawBlock(uint64_t first, uint64_t end, uint32_t& count) {
        Bytes hashes, posts, offsets; count = 0;
        append(offsets, 0, 4);
        for (uint64_t i = first; i < end;) {
            uint64_t stop = i + 1;
            while (stop < end && memcmp(records[i].hash, records[stop].hash, 20) == 0) ++stop;
            hashes.insert(hashes.end(), records[i].hash + 2, records[i].hash + 20);
            uint64_t fileCount = 0, lastFile = UINT64_MAX;
            for (uint64_t j = i; j < stop; ++j) {
                auto file = location(lineOf(records[j])).first;
                if (file != lastFile) { ++fileCount; lastFile = file; }
            }
            varint(posts, fileCount);
            uint64_t previousFile = 0;
            for (uint64_t j = i; j < stop;) {
                auto firstLocation = location(lineOf(records[j]));
                if (phase == "writing") noteFileHash(firstLocation.first);
                uint64_t fileEnd = j + 1, runs = 1;
                while (fileEnd < stop && location(lineOf(records[fileEnd])).first == firstLocation.first) {
                    if (lineOf(records[fileEnd]) != lineOf(records[fileEnd-1]) + 1) ++runs;
                    ++fileEnd;
                }
                varint(posts, firstLocation.first - previousFile); varint(posts, runs);
                previousFile = firstLocation.first;
                uint64_t previous = 0;
                while (j < fileEnd) {
                    uint64_t last = j + 1;
                    while (last < fileEnd && lineOf(records[last]) == lineOf(records[last-1]) + 1) ++last;
                    uint64_t line = location(lineOf(records[j])).second;
                    varint(posts, line - previous); varint(posts, last - j);
                    if (posts.size() > BLOCK_LIMIT) throw std::runtime_error("single-hash provenance exceeds block bound");
                    previous = line + last - j - 1; j = last;
                }
            }
            ++count;
            if (8ULL + hashes.size() + offsets.size() + 4 + posts.size() > BLOCK_LIMIT)
                throw std::runtime_error("prefix block exceeds 64 MiB bound; original retained");
            append(offsets, posts.size(), 4); i = stop;
        }
        Bytes raw; raw.reserve(4 + hashes.size() + offsets.size() + posts.size());
        append(raw, count, 4); raw.insert(raw.end(), hashes.begin(), hashes.end());
        raw.insert(raw.end(), offsets.begin(), offsets.end()); raw.insert(raw.end(), posts.begin(), posts.end());
        return raw;
    }
    void publish() {
        phase = "writing"; status(true);
        waitSpace(24 + catalog.size() + (PREFIXES + 1) * 8);
        outFd = open(partial.c_str(), O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        if (outFd < 0) throw std::runtime_error("cannot exclusively create partial index");
        Bytes header({'P','W','N','I','D','X','0','1'}); append(header, catalog.size(), 8); append(header, 0, 8);
        header.insert(header.end(), catalog.begin(), catalog.end());
        uint64_t directoryStart = header.size(); header.resize(header.size() + (PREFIXES + 1) * 8, 0);
        writeAt(header.data(), header.size(), 0);
        std::vector<uint64_t> directory(PREFIXES + 1);
        uint64_t i = 0, offset = header.size(), lastSynced = offset;
        for (uint32_t prefix = 0; prefix < PREFIXES; ++prefix) {
            directory[prefix] = offset;
            uint64_t end = i;
            while (end < expectedLines && prefixOf(records[end]) == prefix) ++end;
            if (end != i) {
                uint32_t count;
                Bytes raw = rawBlock(i, end, count);
                uLongf length = compressBound(raw.size()); Bytes encoded(4 + length);
                for (unsigned b = 0; b < 4; ++b) encoded[b] = raw.size() >> (b * 8);
                if (compress2(encoded.data() + 4, &length, raw.data(), raw.size(), 1) != Z_OK) throw std::runtime_error("compression failed");
                encoded.resize(4 + length);
                writeAt(encoded.data(), encoded.size(), offset); offset += encoded.size(); unique += count;
                if (offset - lastSynced >= (512 << 20)) { syncOutput(); lastSynced = offset; }
            }
            i = end; status(false, ",\"emittedLines\":" + std::to_string(i));
        }
        directory[PREFIXES] = offset;
        if (i != expectedLines) throw std::runtime_error("output occurrence count mismatch");
        header.clear(); header.insert(header.end(), {'P','W','N','I','D','X','0','1'}); append(header, catalog.size(), 8); append(header, unique, 8);
        header.insert(header.end(), catalog.begin(), catalog.end());
        for (auto position : directory) append(header, position, 8);
        if (header.size() != directoryStart + (PREFIXES + 1) * 8) throw std::runtime_error("invalid header size");
        writeAt(header.data(), header.size(), 0, false); syncOutput();
        phase = "verifying_saved_index"; status(true);
        struct stat saved{};
        if (fstat(outFd, &saved) || uint64_t(saved.st_size) != offset) throw std::runtime_error("saved index size mismatch");
        Bytes savedHeader(header.size()); readAt(savedHeader.data(), savedHeader.size(), 0);
        if (savedHeader != header) throw std::runtime_error("saved header mismatch");
        SHA256_CTX checksum; SHA256_Init(&checksum); SHA256_Update(&checksum, header.data(), header.size());
        i = 0; uint64_t verifiedUnique = 0;
        for (uint32_t prefix = 0; prefix < PREFIXES; ++prefix) {
            uint64_t end = i;
            while (end < expectedLines && prefixOf(records[end]) == prefix) ++end;
            if (end != i) {
                uint32_t count; Bytes expected = rawBlock(i, end, count);
                Bytes encoded(directory[prefix+1] - directory[prefix]); readAt(encoded.data(), encoded.size(), directory[prefix]);
                SHA256_Update(&checksum, encoded.data(), encoded.size());
                if (encoded.size() < 5 || get(encoded.data(), 4) != expected.size()) throw std::runtime_error("saved block header mismatch");
                Bytes decoded(expected.size()); uLongf size = decoded.size();
                if (uncompress(decoded.data(), &size, encoded.data()+4, encoded.size()-4) != Z_OK || size != expected.size() || decoded != expected)
                    throw std::runtime_error("saved hash or original-line provenance mismatch");
                verifiedUnique += count;
            }
            i = end; verifiedLines = i; status();
        }
        if (verifiedLines != expectedLines || verifiedUnique != unique) throw std::runtime_error("saved counts mismatch");
        unchanged(); unsigned char digest[32]; SHA256_Final(digest, &checksum);
        // A hard link publishes without overwriting an existing release.
        while (link(partial.c_str(), output.c_str())) {
            if (errno == ENOSPC || errno == EDQUOT) { waitSpace(4096, true); continue; }
            throw std::runtime_error("cannot publish verified index without overwriting");
        }
        if (fsync(directoryFd)) throw std::runtime_error("cannot sync published index directory");
        if (unlink(partial.c_str()) || fsync(directoryFd)) throw std::runtime_error("cannot finalize published index name");
        phase = "complete";
        status(true, ",\"sourceSha256\":" + quote(sourceSha) + ",\"indexSha256\":" + quote(hex(digest, 32)) +
            ",\"preDeduplicationCountsVerified\":true,\"savedProvenanceVerified\":true,\"originalDeleted\":false");
    }
};

int main(int argc, char** argv) {
#ifdef PWNED_TESTING
    if (argc == 2 && std::string(argv[1]) == "--test-lines") {
        for (uint64_t n : {1ULL, (1ULL << 32), (1ULL << 35), (1ULL << 40) - 1}) {
            Record r{}; setLine(r, n); if (lineOf(r) != n) return 1;
        }
        return 0;
    }
#endif
    if (argc != 11) {
        std::cerr << "usage: builder SOURCE OUTPUT CATALOG_NAME LINES LF_COUNT BYTES SHA256 MEMORY_BYTES RESERVE_BYTES THREADS\n"; return 2;
    }
    try {
        Builder builder(argv);
        try { builder.setup(); builder.hashInput(); builder.sortRecords(); builder.publish(); }
        catch (const std::exception& error) { builder.phase = "failed"; builder.waiting = false; builder.status(true, ",\"error\":" + quote(error.what())); throw; }
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
