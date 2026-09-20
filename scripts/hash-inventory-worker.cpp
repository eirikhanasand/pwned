// One SHA-1 per original logical line; never emits source records.
#include <openssl/sha.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <unistd.h>
#include <algorithm>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <numeric>
#include <omp.h>

struct File {
    int fd;
    struct stat before{};
    const unsigned char* data = nullptr;
    explicit File(const char* path) {
        fd = open(path, O_RDONLY | O_NOFOLLOW);
        if (fd < 0 || fstat(fd, &before) || !S_ISREG(before.st_mode)) throw std::runtime_error("cannot open regular input");
        if (before.st_size) {
            auto p = mmap(nullptr, before.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
            if (p == MAP_FAILED) throw std::runtime_error("cannot map input");
            data = static_cast<unsigned char*>(p);
            madvise(const_cast<unsigned char*>(data), before.st_size, MADV_SEQUENTIAL);
        }
    }
    void unchanged() {
        struct stat after{};
        if (fstat(fd, &after) || before.st_size != after.st_size ||
            before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
            before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec)
            throw std::runtime_error("input changed during processing");
    }
    ~File() { if (data) munmap(const_cast<unsigned char*>(data), before.st_size); close(fd); }
};

std::string hex(const unsigned char* data, size_t n) {
    static const char digits[] = "0123456789ABCDEF";
    std::string value(n * 2, '0');
    for (size_t i = 0; i < n; ++i) { value[i*2] = digits[data[i] >> 4]; value[i*2+1] = digits[data[i] & 15]; }
    return value;
}

struct Summary { uint64_t bytes = 0, lines = 0, newlines = 0; bool terminated = false; std::string digest; };

Summary inspect(File& file) {
    Summary result;
    result.bytes = file.before.st_size;
    SHA256_CTX context;
    SHA256_Init(&context);
    const size_t block = 8 * 1024 * 1024;
    for (size_t offset = 0; offset < result.bytes; offset += block) {
        size_t length = std::min<uint64_t>(block, result.bytes - offset);
        SHA256_Update(&context, file.data + offset, length);
        const unsigned char* p = file.data + offset;
        const unsigned char* end = p + length;
        while (p < end) {
            auto found = static_cast<const unsigned char*>(memchr(p, '\n', end - p));
            if (!found) break;
            ++result.newlines;
            p = found + 1;
        }
    }
    result.terminated = result.bytes && file.data[result.bytes - 1] == '\n';
    result.lines = result.newlines + (result.bytes && !result.terminated ? 1 : 0);
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_Final(digest, &context);
    result.digest = hex(digest, sizeof digest);
    file.unchanged();
    return result;
}

void print(const Summary& s) {
    std::cout << "{\"bytes\":" << s.bytes << ",\"lines\":" << s.lines
        << ",\"newlines\":" << s.newlines << ",\"terminated\":" << (s.terminated ? "true" : "false")
        << ",\"sha256\":\"" << s.digest << "\"}" << std::endl;
}

void space(int fd, uint64_t reserve, uint64_t needed) {
    struct statvfs usage{};
    if (fstatvfs(fd, &usage) || static_cast<uint64_t>(usage.f_bavail) * usage.f_frsize < reserve + needed)
        throw std::runtime_error("disk reserve reached");
}

void writeAll(int fd, const unsigned char* data, size_t length) {
    while (length) {
        ssize_t n = write(fd, data, length);
        if (n <= 0) throw std::runtime_error("output write failed");
        data += n;
        length -= n;
    }
}

// Fixed-width input makes sorting row indexes inexpensive. Keep an original-line
// -> unique-hash-line map so deduplication does not discard occurrence provenance.
void deduplicate(File& input, const Summary& source, char** argv) {
    const uint64_t reserve = std::stoull(argv[5]), memory = std::stoull(argv[6]);
    if (source.bytes != source.lines * 41 - (source.lines && !source.terminated ? 1 : 0))
        throw std::runtime_error("invalid hash record width");
    // Include mapped inputs/outputs plus both index arrays and generous overhead.
    if (source.lines > (memory > 67108864 ? (memory - 67108864) / 106 : 0))
        throw std::runtime_error("deduplication memory budget reached");
    for (uint64_t i = 0; i < source.lines; ++i) {
        for (size_t j = 0; j < 40; ++j) {
            unsigned char c = input.data[i * 41 + j];
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')))
                throw std::runtime_error("invalid uppercase SHA-1 record");
        }
        if ((i + 1 < source.lines || source.terminated) && input.data[i * 41 + 40] != '\n')
            throw std::runtime_error("invalid hash separator");
    }
    std::vector<uint64_t> indexes(source.lines), mapping(source.lines);
    std::iota(indexes.begin(), indexes.end(), 0);
    std::sort(indexes.begin(), indexes.end(), [&](uint64_t a, uint64_t b) {
        int order = memcmp(input.data + a * 41, input.data + b * 41, 40);
        return order ? order < 0 : a < b;
    });
    uint64_t unique = 0, previous = 0;
    for (uint64_t index : indexes) {
        if (!unique || memcmp(input.data + index * 41, input.data + previous * 41, 40)) ++unique;
        mapping[index] = unique;
        previous = index;
    }
    int out = open(argv[3], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (out < 0) throw std::runtime_error("deduplicated output exists or cannot be created");
    space(out, reserve, unique * 41 + source.lines * 8);
    int map = open(argv[4], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (map < 0) throw std::runtime_error("line map exists or cannot be created");
    std::vector<unsigned char> buffer;
    buffer.reserve(8 * 1024 * 1024 + 41);
    auto flush = [&](int fd) {
        space(fd, reserve, buffer.size());
        writeAll(fd, buffer.data(), buffer.size());
        buffer.clear();
    };
    uint64_t emitted = 0;
    for (uint64_t index : indexes) {
        if (mapping[index] == emitted) continue;
        emitted = mapping[index];
        buffer.insert(buffer.end(), input.data + index * 41, input.data + index * 41 + 40);
        buffer.push_back('\n');
        if (buffer.size() >= 8 * 1024 * 1024) flush(out);
    }
    flush(out);
    for (uint64_t line : mapping) {
        for (unsigned shift = 0; shift < 64; shift += 8) buffer.push_back((line >> shift) & 255);
        if (buffer.size() >= 8 * 1024 * 1024) flush(map);
    }
    flush(map);
    if (fsync(out) || fsync(map) || close(out) || close(map)) throw std::runtime_error("deduplication flush failed");
    File saved(argv[3]), savedMap(argv[4]);
    Summary output = inspect(saved), provenance = inspect(savedMap);
    if (output.lines != unique || output.bytes != unique * 41 || provenance.bytes != source.lines * 8)
        throw std::runtime_error("deduplicated counts failed verification");
    for (uint64_t i = 0; i < unique; ++i) {
        if (saved.data[i * 41 + 40] != '\n' || (i && memcmp(saved.data + (i - 1) * 41, saved.data + i * 41, 40) >= 0))
            throw std::runtime_error("saved hashes are not sorted and unique");
    }
    for (uint64_t i = 0; i < source.lines; ++i) {
        uint64_t line = 0;
        for (unsigned j = 0; j < 8; ++j) line |= uint64_t(savedMap.data[i * 8 + j]) << (j * 8);
        if (!line || line > unique || line != mapping[i] || memcmp(input.data + i * 41, saved.data + (line - 1) * 41, 40))
            throw std::runtime_error("saved original-line mapping failed verification");
    }
    input.unchanged(); saved.unchanged(); savedMap.unchanged();
    std::cout << "{\"input\":"; print(source);
    std::cout << ",\"output\":"; print(output);
    std::cout << ",\"lineMap\":"; print(provenance);
    std::cout << "}" << std::endl;
}

int main(int argc, char** argv) {
    try {
        if (argc < 3) throw std::runtime_error("usage: worker scan INPUT | worker convert INPUT OUTPUT RESERVE THREADS");
        File input(argv[2]);
        Summary source = inspect(input);
        if (std::string(argv[1]) == "scan") { print(source); return 0; }
        if (std::string(argv[1]) == "deduplicate" && argc == 7) { deduplicate(input, source, argv); return 0; }
        if (std::string(argv[1]) != "convert" || argc != 6) throw std::runtime_error("invalid arguments");
        int threads = std::stoi(argv[5]);
        if (threads < 1 || threads > 96) throw std::runtime_error("invalid thread count");
        omp_set_num_threads(threads);
        uint64_t reserve = std::stoull(argv[4]);
        uint64_t expected = source.lines * 41 - (source.lines && !source.terminated ? 1 : 0);
        int out = open(argv[3], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        if (out < 0) throw std::runtime_error("output already exists or cannot be created");
        space(out, reserve, expected);
        SHA256_CTX outputHash;
        SHA256_Init(&outputHash);
        struct Row { uint64_t start, length; };
        // Large batches stay in RAM. mmap retains source pages in the bounded
        // container's cache without allocating a second plaintext copy.
        const size_t batchRows = 4 * 1024 * 1024;
        std::vector<Row> rows;
        rows.reserve(std::min<uint64_t>(batchRows, source.lines));
        uint64_t position = 0, completed = 0;
        while (position < source.bytes) {
            rows.clear();
            while (position < source.bytes && rows.size() < batchRows) {
                auto next = static_cast<const unsigned char*>(memchr(input.data + position, '\n', source.bytes - position));
                uint64_t end = next ? static_cast<uint64_t>(next - input.data) : source.bytes;
                uint64_t length = end - position;
                if (length && input.data[end - 1] == '\r') --length;
                rows.push_back({position, length});
                position = next ? end + 1 : end;
            }
            std::vector<unsigned char> output(rows.size() * 41);
            #pragma omp parallel for schedule(static) if(rows.size() > 100000)
            for (size_t i = 0; i < rows.size(); ++i) {
                unsigned char digest[SHA_DIGEST_LENGTH];
                SHA_CTX context;
                SHA1_Init(&context);
                SHA1_Update(&context, input.data + rows[i].start, rows[i].length);
                SHA1_Final(digest, &context);
                static const char digits[] = "0123456789ABCDEF";
                for (size_t j = 0; j < sizeof digest; ++j) {
                    output[i*41+j*2] = digits[digest[j] >> 4];
                    output[i*41+j*2+1] = digits[digest[j] & 15];
                }
                output[i*41+40] = '\n';
            }
            completed += rows.size();
            if (completed == source.lines && !source.terminated) output.pop_back();
            space(out, reserve, output.size());
            SHA256_Update(&outputHash, output.data(), output.size());
            size_t written = 0;
            while (written < output.size()) {
                ssize_t n = write(out, output.data() + written, output.size() - written);
                if (n <= 0) throw std::runtime_error("output write failed");
                written += n;
            }
        }
        input.unchanged();
        if (fsync(out) || close(out)) throw std::runtime_error("output flush failed");
        unsigned char writtenDigest[SHA256_DIGEST_LENGTH];
        SHA256_Final(writtenDigest, &outputHash);
        File saved(argv[3]);
        Summary verified = inspect(saved);
        if (verified.bytes != expected || verified.lines != source.lines || verified.newlines != source.newlines ||
            verified.digest != hex(writtenDigest, sizeof writtenDigest)) throw std::runtime_error("saved output verification failed");
        // Independently reread the persisted file before reporting success.
        std::cout << "{\"source\":"; print(source);
        std::cout << ",\"output\":"; print(verified);
        std::cout << "}" << std::endl;
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << std::endl;
        return 1;
    }
}
