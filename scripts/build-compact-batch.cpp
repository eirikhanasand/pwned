// Reuse the bounded native builder, with a catalog and disjoint line intervals.
// The manifest is generated from independently scanned source checksums/counts.
// This executable NEVER deletes inputs. RAM publication/deletion is coordinated
// separately after every saved block has been verified by Builder::publish.
#define main single_source_main
#include "build-compact-inventory.cpp"
#undef main
#include <sstream>

struct Source {
    std::string path, name, sha;
    uint64_t lines, lf, bytes, first;
    struct stat snapshot{};
};

struct Batch : Builder {
    std::vector<Source> inputs;
    std::vector<uint64_t> starts;
    std::vector<uint64_t> fileUnique;
    std::string manifest;
    struct stat manifestSnapshot{};
    bool readingSource = false;

    Batch(char** argv) : Builder(argv), manifest(argv[1]) {
        std::ifstream stream(manifest);
        if (!stream || lstat(manifest.c_str(), &manifestSnapshot) || !S_ISREG(manifestSnapshot.st_mode))
            throw std::runtime_error("missing regular manifest");
        std::string row; uint64_t total = 0;
        catalog = "[";
        while (std::getline(stream, row)) {
            std::istringstream fields(row); std::vector<std::string> values; std::string value;
            while (std::getline(fields, value, '\t')) values.push_back(value);
            if (values.size() != 6) throw std::runtime_error("invalid manifest row");
            Source s{values[0], values[1], values[5], number(values[2].c_str()), number(values[3].c_str()), number(values[4].c_str()), total + 1, {}};
            if (s.sha.size() != 64 || s.sha.find_first_not_of("0123456789abcdef") != std::string::npos || s.lf > s.lines || s.lines - s.lf > 1)
                throw std::runtime_error("invalid source profile");
            if (lstat(s.path.c_str(), &s.snapshot) || !S_ISREG(s.snapshot.st_mode) || uint64_t(s.snapshot.st_size) != s.bytes)
                throw std::runtime_error("source is not expected regular file");
            for (const auto& previous : inputs)
                if (previous.name == s.name || previous.path == s.path) throw std::runtime_error("duplicate manifest source");
            if (!inputs.empty()) catalog += ',';
            catalog += quote(s.name);
            inputs.push_back(s); starts.push_back(total + 1); total += s.lines;
            if (total > expectedLines) throw std::runtime_error("manifest exceeds planned line count");
        }
        catalog += ']';
        if (inputs.empty() || total != expectedLines || catalog.size() > 1024 * 1024)
            throw std::runtime_error("invalid manifest totals/catalog");
        fileUnique.resize(inputs.size());
    }
    void noteFileHash(uint64_t id) override { ++fileUnique.at(id); }
    void counts() {
        std::cout << "{\"state\":\"batch_complete\",\"fileUniqueHashes\":[";
        for (size_t i = 0; i < fileUnique.size(); ++i) {
            if (i) std::cout << ',';
            std::cout << fileUnique[i];
        }
        std::cout << "]}\n" << std::flush;
    }
    std::pair<uint64_t, uint64_t> location(uint64_t line) const override {
        // Empty sources can share starts; upper_bound selects the nonempty span.
        auto found = std::upper_bound(starts.begin(), starts.end(), line);
        uint64_t id = found - starts.begin() - 1;
        return {id, line - starts[id] + 1};
    }
    void unchanged() override {
        struct stat current{};
        if (lstat(manifest.c_str(), &current) || !sameSnapshot(manifestSnapshot, current))
            throw std::runtime_error("manifest changed");
        if (readingSource) { Builder::unchanged(); return; }
        for (const auto& s : inputs)
            if (lstat(s.path.c_str(), &current) || !sameSnapshot(s.snapshot, current))
                throw std::runtime_error("batch source changed");
    }
    void hashAll() {
        Record* base = records;
        const auto totalLines = expectedLines;
        const int manifestFd = sourceFd;
        uint64_t totalLF = 0, totalBytes = 0, done = 0;
        try {
            for (size_t id = 0; id < inputs.size(); ++id) {
                const auto& s = inputs[id];
                source = s.path; before = s.snapshot; expectedSha = s.sha;
                expectedLines = s.lines; expectedLF = s.lf; expectedBytes = s.bytes;
                records = base ? base + done : nullptr;
                hashedLines = hashedLF = readBytes = 0;
                sourceFd = open(source.c_str(), O_RDONLY | O_NOFOLLOW);
                if (sourceFd < 0) throw std::runtime_error("cannot open batch source");
                readingSource = true;
                Builder::hashInput(); // Includes independent source checksum/count comparison.
                readingSource = false;
                close(sourceFd); sourceFd = manifestFd;
#pragma omp parallel for num_threads(threads) schedule(static)
                for (uint64_t i = 0; i < s.lines; ++i) setLine(records[i], lineOf(records[i]) + done);
                done += s.lines; totalLF += s.lf; totalBytes += s.bytes;
                status(true, ",\"completedFiles\":" + std::to_string(id + 1) + ",\"totalFiles\":" + std::to_string(inputs.size()) + ",\"batchHashedLines\":" + std::to_string(done));
            }
        } catch (...) {
            if (sourceFd != manifestFd && sourceFd >= 0) close(sourceFd);
            sourceFd = manifestFd; records = base; readingSource = false;
            throw;
        }
        records = base; expectedLines = hashedLines = totalLines;
        expectedLF = hashedLF = totalLF; expectedBytes = readBytes = totalBytes;
        source = manifest; sourceSha.clear(); unchanged();
    }
};

int main(int argc, char** argv) {
    // Same arguments as Builder; BYTES/SHA256 describe the manifest for setup.
    if (argc != 11) { std::cerr << "usage: batch MANIFEST OUTPUT UNUSED TOTAL_LINES TOTAL_LF MANIFEST_BYTES MANIFEST_SHA256 MEMORY RESERVE THREADS\n"; return 2; }
    try {
        Batch b(argv);
        try { b.setup(); b.hashAll(); b.sortRecords(); b.publish(); b.counts(); }
        catch (const std::exception& e) { b.phase = "failed"; b.waiting = false; b.status(true, ",\"error\":" + quote(e.what())); throw; }
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
