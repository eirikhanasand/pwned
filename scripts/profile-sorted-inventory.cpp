// Read-only sizing pass. Reports metadata only, never password records.
#include <openssl/sha.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>

static unsigned varbytes(uint64_t value) {
    unsigned bytes = 1;
    while (value >= 128) { value >>= 7; ++bytes; }
    return bytes;
}

int main(int argc, char** argv) {
    int fd = -1;
    unsigned char* data = nullptr;
    uint64_t bytes = 0;
    try {
        if (argc != 2) throw std::runtime_error("usage: profile-sorted-inventory INPUT");
        fd = open(argv[1], O_RDONLY | O_NOFOLLOW);
        struct stat before{};
        if (fd < 0 || fstat(fd, &before) || !S_ISREG(before.st_mode))
            throw std::runtime_error("cannot open regular source");
        bytes = before.st_size;
        if (bytes) {
            void* mapping = mmap(nullptr, bytes, PROT_READ, MAP_PRIVATE, fd, 0);
            if (mapping == MAP_FAILED) throw std::runtime_error("cannot map source");
            data = static_cast<unsigned char*>(mapping);
            madvise(data, bytes, MADV_SEQUENTIAL);
        }
        auto started = std::chrono::steady_clock::now(), reported = started;
        uint64_t position = 0, hashed = 0, lines = 0, newlines = 0, runs = 0;
        uint64_t previous = 0, previousLength = 0, runLength = 0, runStart = 0;
        uint64_t runMetadataBytes = 0, orderingViolations = 0;
        SHA256_CTX digest;
        SHA256_Init(&digest);
        auto finishRun = [&]() {
            if (runLength) runMetadataBytes += varbytes(runStart) + varbytes(runLength);
        };
        auto report = [&](bool complete, const std::string& checksum) {
            const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
            std::cout << "{\"state\":\"" << (complete ? "complete" : "running")
                << "\",\"bytes\":" << bytes << ",\"processedBytes\":" << position
                << ",\"lines\":" << lines << ",\"newlines\":" << newlines
                << ",\"adjacentRuns\":" << runs << ",\"orderingViolations\":" << orderingViolations
                << ",\"runPositionAndLengthVarintBytes\":" << runMetadataBytes
                << ",\"binaryHashBytesForRuns\":" << runs * 20
                << ",\"sortRecordsAt40Bytes\":" << runs * 40
                << ",\"elapsedSeconds\":" << seconds;
            if (complete) std::cout << ",\"sha256\":\"" << checksum << "\",\"terminated\":"
                << ((bytes && data[bytes - 1] == '\n') ? "true" : "false");
            std::cout << "}" << std::endl;
        };
        report(false, "");
        while (position < bytes) {
            const auto endPointer = static_cast<unsigned char*>(memchr(data + position, '\n', bytes - position));
            const uint64_t end = endPointer ? static_cast<uint64_t>(endPointer - data) : bytes;
            uint64_t length = end - position;
            if (length && data[end - 1] == '\r') --length;
            int order = lines ? memcmp(data + previous, data + position, std::min(previousLength, length)) : 0;
            if (!order && lines) order = (previousLength > length) - (previousLength < length);
            if (lines && order > 0) ++orderingViolations;
            ++lines;
            if (lines == 1 || order != 0) {
                finishRun(); ++runs; runStart = lines; runLength = 1;
            } else ++runLength;
            previous = position; previousLength = length;
            position = endPointer ? end + 1 : end;
            if (endPointer) ++newlines;
            if (position - hashed >= 8 * 1024 * 1024 || position == bytes) {
                SHA256_Update(&digest, data + hashed, position - hashed);
                hashed = position;
                auto now = std::chrono::steady_clock::now();
                if (now - reported >= std::chrono::seconds(10)) {
                    report(false, ""); reported = now;
                }
            }
        }
        finishRun();
        struct stat after{}, named{};
        if (fstat(fd, &after) || lstat(argv[1], &named) || before.st_dev != named.st_dev ||
            before.st_ino != named.st_ino || before.st_size != after.st_size ||
#ifdef __APPLE__
            before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec || before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec ||
            before.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec || before.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec
#else
            before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
            before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec
#endif
        ) throw std::runtime_error("source changed during profiling");
        unsigned char result[SHA256_DIGEST_LENGTH];
        SHA256_Final(result, &digest);
        const char* digits = "0123456789abcdef";
        std::string checksum;
        for (unsigned char byte : result) { checksum += digits[byte >> 4]; checksum += digits[byte & 15]; }
        report(true, checksum);
        if (data) munmap(data, bytes);
        close(fd);
        return 0;
    } catch (const std::exception& error) {
        if (data) munmap(data, bytes);
        if (fd >= 0) close(fd);
        std::cerr << error.what() << std::endl;
        return 1;
    }
}
