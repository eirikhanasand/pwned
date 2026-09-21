// Linux-only handoff: reuse a stopped builder's read-only memory, never rehash.
#define main original_builder_main
#include "build-compact-inventory.cpp"
#undef main
#include <sys/socket.h>
#include <sys/un.h>
#include <sstream>

struct Resume : Builder {
    int memFd = -1, handoffFd = -1;
    uint64_t base, donorStart, cursor = 0, cacheStart = 0, cacheCount = 0;
    uint64_t reusedBytes = 0, reusedLines = 0, discardedTail = 0;
    std::vector<Record> cache, bucket;
    std::string socketPath;

    Resume(char** argv) : Builder(argv), base(number(argv[12])), donorStart(number(argv[13])), socketPath(argv[11]) {
        statusPath = output + ".handoff.status.json";
        cache.resize((8 << 20) / sizeof(Record));
    }
    ~Resume() {
        records = nullptr; // Borrowed bucket, NOT the donor's allocation.
        if (memFd >= 0) close(memFd);
        if (handoffFd >= 0) close(handoffFd);
    }
    void unchanged() override {
        std::ifstream input("/proc/1/stat"); std::string stat;
        std::getline(input, stat);
        auto end = stat.rfind(')');
        if (end == std::string::npos) throw std::runtime_error("donor is missing");
        std::istringstream fields(stat.substr(end + 2));
        std::string field; fields >> field;
        if (field != "T") throw std::runtime_error("donor must stay stopped (not exited/restarted/resumed)");
        for (unsigned n = 4; n <= 22; ++n) fields >> field;
        if (!fields || number(field.c_str()) != donorStart) throw std::runtime_error("donor identity changed");
    }
    void receiveMemory() {
        unchanged();
        if (socketPath.size() >= sizeof(sockaddr_un::sun_path)) throw std::runtime_error("socket path too long");
        int server = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (server < 0) throw std::runtime_error("cannot open handoff socket");
        sockaddr_un address{}; address.sun_family = AF_UNIX;
        memcpy(address.sun_path, socketPath.c_str(), socketPath.size() + 1);
        if (bind(server, reinterpret_cast<sockaddr*>(&address), sizeof(address)) || chmod(socketPath.c_str(), 0600) || listen(server, 1))
            throw std::runtime_error("cannot exclusively bind handoff socket");
        phase = "awaiting_memory"; status(true);
        int peer = accept4(server, nullptr, nullptr, SOCK_CLOEXEC);
        if (peer < 0) throw std::runtime_error("cannot accept memory descriptor");
        ucred credentials{}; socklen_t size = sizeof(credentials);
        if (getsockopt(peer, SOL_SOCKET, SO_PEERCRED, &credentials, &size) || credentials.uid != 0)
            throw std::runtime_error("memory descriptor must come from root helper");
        char byte = 0, control[CMSG_SPACE(sizeof(int))]{};
        iovec vector{&byte, 1}; msghdr message{};
        message.msg_iov = &vector; message.msg_iovlen = 1;
        message.msg_control = control; message.msg_controllen = sizeof(control);
        if (recvmsg(peer, &message, MSG_CMSG_CLOEXEC) != 1 || byte != 'M' || (message.msg_flags & MSG_CTRUNC))
            throw std::runtime_error("invalid memory handoff");
        auto c = CMSG_FIRSTHDR(&message);
        if (!c || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS || c->cmsg_len != CMSG_LEN(sizeof(int)))
            throw std::runtime_error("missing memory descriptor");
        memcpy(&memFd, CMSG_DATA(c), sizeof(int));
        if ((fcntl(memFd, F_GETFL) & O_ACCMODE) != O_RDONLY) throw std::runtime_error("memory descriptor is not read-only");
        close(peer); close(server); unlink(socketPath.c_str());
    }
    void setupResume() {
        directoryFd = open(output.substr(0, output.find_last_of('/')).c_str(), O_RDONLY | O_DIRECTORY);
        if (directoryFd < 0) throw std::runtime_error("missing output directory");
        handoffFd = open((output + ".handoff.lock").c_str(), O_CREAT | O_RDWR | O_NOFOLLOW, 0600);
        if (handoffFd < 0 || flock(handoffFd, LOCK_EX | LOCK_NB)) throw std::runtime_error("another handoff is active");
        ownsLock = true;
        struct stat st{};
        if (lstat(output.c_str(), &st) == 0) throw std::runtime_error("final output already exists");
        outFd = open(partial.c_str(), O_RDWR | O_NOFOLLOW);
        if (outFd < 0 || fstat(outFd, &st) || !S_ISREG(st.st_mode)) throw std::runtime_error("missing regular partial index");
        receiveMemory();
        hashedLines = expectedLines; hashedLF = expectedLF; readBytes = expectedBytes; sourceSha = expectedSha;
    }
    const Record& at(uint64_t position) {
        if (position >= expectedLines) throw std::runtime_error("record outside verified inventory");
        if (!cacheCount || position < cacheStart || position >= cacheStart + cacheCount) {
            cacheStart = position; cacheCount = std::min<uint64_t>(cache.size(), expectedLines - position);
            unsigned char* dest = reinterpret_cast<unsigned char*>(cache.data());
            uint64_t offset = base + position * sizeof(Record), remaining = cacheCount * sizeof(Record);
            while (remaining) {
                ssize_t n = pread(memFd, dest, remaining, offset);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) throw std::runtime_error("donor memory unavailable; retain partial and donor");
                dest += n; offset += n; remaining -= n;
            }
        }
        return cache[position - cacheStart];
    }
    Bytes block(uint32_t prefix, uint32_t& count) {
        bucket.clear();
        while (cursor < expectedLines) {
            Record record = at(cursor);
            auto p = prefixOf(record);
            if (p < prefix) throw std::runtime_error("donor prefix ordering invalid");
            if (p != prefix) break;
            if (!lineOf(record) || lineOf(record) > expectedLines || (!bucket.empty() && !less(bucket.back(), record)))
                throw std::runtime_error("donor hash/line ordering invalid");
            if (bucket.size() >= BLOCK_LIMIT / sizeof(Record)) throw std::runtime_error("donor bucket exceeds bounded handoff memory");
            bucket.push_back(record); ++cursor;
        }
        count = 0;
        if (bucket.empty()) return {};
        records = bucket.data();
        return rawBlock(0, bucket.size(), count);
    }
    // Read one self-delimiting zlib stream without requiring the unfinished directory.
    bool existingBlock(uint64_t offset, uint64_t fileSize, Bytes& decoded, uint64_t& next) {
        if (fileSize - offset < 4) return false;
        unsigned char length[4]; readAt(length, 4, offset);
        uint64_t rawSize = get(length, 4);
        if (rawSize < 8 || rawSize > BLOCK_LIMIT) throw std::runtime_error("invalid existing block length");
        // One spare byte distinguishes an oversized stream from a split trailer.
        decoded.resize(rawSize + 1);
        z_stream z{};
        if (inflateInit(&z) != Z_OK) throw std::runtime_error("inflate init failed");
        Bytes input(64 << 10); uint64_t pos = offset + 4; int result = Z_OK;
        z.next_out = decoded.data(); z.avail_out = decoded.size();
        while (result == Z_OK && pos < fileSize) {
            size_t n = std::min<uint64_t>(input.size(), fileSize - pos); readAt(input.data(), n, pos);
            z.next_in = input.data(); z.avail_in = n; pos += n;
            result = inflate(&z, Z_NO_FLUSH);
            if (z.total_out > rawSize) { inflateEnd(&z); throw std::runtime_error("existing block expands beyond declared size"); }
        }
        next = pos - z.avail_in;
        bool complete = result == Z_STREAM_END && z.total_out == rawSize;
        inflateEnd(&z);
        if (!complete && result != Z_OK) throw std::runtime_error("corrupt existing zlib block");
        decoded.resize(rawSize);
        return complete;
    }
    std::string progress() {
        return ",\"emittedLines\":" + std::to_string(cursor) + ",\"reusedBytes\":" + std::to_string(reusedBytes) +
            ",\"reusedLines\":" + std::to_string(reusedLines) + ",\"discardedIncompleteTailBytes\":" + std::to_string(discardedTail) +
            ",\"sourceFinalSnapshotCheckSkipped\":true,\"rehashPerformed\":false,\"resortPerformed\":false";
    }
    void run() {
        unchanged();
        struct stat st{}; if (fstat(outFd, &st)) throw std::runtime_error("cannot stat partial");
        uint64_t originalSize = st.st_size;
        Bytes header({'P','W','N','I','D','X','0','1'}); append(header, catalog.size(), 8); append(header, 0, 8);
        header.insert(header.end(), catalog.begin(), catalog.end());
        uint64_t directoryStart = header.size(); header.resize(header.size() + (PREFIXES + 1) * 8, 0);
        if (originalSize < header.size()) throw std::runtime_error("partial header incomplete");
        Bytes savedHeader(header.size()); readAt(savedHeader.data(), savedHeader.size(), 0);
        // A resumed run can have a completed directory; compare immutable header/catalog.
        if (memcmp(header.data(), savedHeader.data(), 16) || memcmp(header.data()+24, savedHeader.data()+24, catalog.size()))
            throw std::runtime_error("partial catalog/header mismatch");
        std::vector<uint64_t> directory(PREFIXES + 1);
        uint64_t offset = header.size(), lastSynced = offset;
        bool recovering = true;
        phase = "checking_existing_blocks"; writtenBytes = originalSize; status(true, progress());
        for (uint32_t prefix = 0; prefix < PREFIXES; ++prefix) {
            directory[prefix] = offset;
            uint64_t first = cursor; uint32_t count;
            Bytes raw = block(prefix, count);
            if (!raw.empty()) {
                bool reuse = false;
                if (recovering && offset < originalSize) {
                    Bytes decoded; uint64_t next;
                    if (existingBlock(offset, originalSize, decoded, next)) {
                        if (decoded != raw) throw std::runtime_error("existing block does not match donor hashes/provenance");
                        offset = next; reuse = true; reusedBytes = offset; reusedLines = cursor;
                    }
                }
                if (!reuse) {
                    if (recovering) {
                        unchanged(); discardedTail = originalSize - offset;
                        if (ftruncate(outFd, offset)) throw std::runtime_error("cannot remove incomplete trailing write");
                        syncOutput(); writtenBytes = offset; recovering = false;
                        phase = "writing"; status(true, progress());
                    }
                    uLongf size = compressBound(raw.size()); Bytes encoded(4 + size);
                    for (unsigned b = 0; b < 4; ++b) encoded[b] = raw.size() >> (b * 8);
                    if (compress2(encoded.data()+4, &size, raw.data(), raw.size(), 1) != Z_OK) throw std::runtime_error("compression failed");
                    encoded.resize(4 + size); writeAt(encoded.data(), encoded.size(), offset); offset += encoded.size();
                    if (offset - lastSynced >= (512 << 20)) { syncOutput(); unchanged(); lastSynced = offset; }
                }
                unique += count;
            }
            if (cursor < first) throw std::runtime_error("record cursor overflow");
            status(false, progress());
        }
        if (cursor != expectedLines || (recovering && offset != originalSize)) throw std::runtime_error("existing output/occurrence count mismatch");
        directory[PREFIXES] = offset;
        for (unsigned b = 0; b < 8; ++b) header[16+b] = unique >> (b*8);
        for (uint64_t p = 0; p <= PREFIXES; ++p) for (unsigned b = 0; b < 8; ++b) header[directoryStart+p*8+b] = directory[p] >> (b*8);
        writeAt(header.data(), header.size(), 0, false); syncOutput();
        phase = "verifying_saved_index"; status(true, progress());
        readAt(savedHeader.data(), savedHeader.size(), 0);
        if (savedHeader != header || fstat(outFd, &st) || uint64_t(st.st_size) != offset) throw std::runtime_error("saved header/size mismatch");
        SHA256_CTX checksum; SHA256_Init(&checksum); SHA256_Update(&checksum, header.data(), header.size());
        cursor = 0; cacheCount = 0; uint64_t verifiedUnique = 0;
        for (uint32_t prefix = 0; prefix < PREFIXES; ++prefix) {
            uint32_t count; Bytes raw = block(prefix, count);
            if (!raw.empty()) {
                Bytes encoded(directory[prefix+1]-directory[prefix]); readAt(encoded.data(), encoded.size(), directory[prefix]);
                SHA256_Update(&checksum, encoded.data(), encoded.size());
                Bytes decoded(raw.size()); uLongf size = decoded.size();
                if (encoded.size()<5 || get(encoded.data(),4)!=raw.size() || uncompress(decoded.data(), &size, encoded.data()+4, encoded.size()-4)!=Z_OK || size!=raw.size() || decoded!=raw)
                    throw std::runtime_error("saved hash/provenance verification failed");
                verifiedUnique += count;
            }
            verifiedLines = cursor; status(false, progress());
        }
        if (verifiedLines != expectedLines || verifiedUnique != unique) throw std::runtime_error("final verified counts mismatch");
        unchanged(); unsigned char digest[32]; SHA256_Final(digest, &checksum);
        if (link(partial.c_str(), output.c_str()) || fsync(directoryFd)) throw std::runtime_error("cannot publish verified index");
        if (unlink(partial.c_str()) || fsync(directoryFd)) throw std::runtime_error("cannot finalize index");
        phase = "complete";
        status(true, progress() + ",\"sourceSha256\":" + quote(sourceSha) + ",\"indexSha256\":" + quote(hex(digest,32)) +
            ",\"preDeduplicationCountsVerified\":true,\"savedProvenanceVerified\":true");
    }
};

int main(int argc, char** argv) {
    if (argc != 14) { std::cerr << "usage: resume SOURCE OUTPUT CATALOG LINES LF BYTES SHA256 MEMORY RESERVE THREADS SOCKET DECIMAL_MEMORY_BASE DONOR_START_TICKS\n"; return 2; }
    try {
        Resume worker(argv);
        try { worker.setupResume(); worker.run(); }
        catch (const std::exception& e) { worker.phase="failed"; worker.waiting=false; worker.status(true, ",\"error\":"+quote(e.what())); throw; }
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
