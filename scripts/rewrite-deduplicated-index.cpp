// Rewrite stored provenance; inputs stay read-only until a verified replacement exists.
#define main original_builder_main
#include "build-compact-inventory.cpp"
#undef main
#include <map>
#include <set>
#include <memory>
#include <sstream>

static void require(bool ok, const char *message) {
    if (!ok)
        throw std::runtime_error(message);
}
static Bytes readBytes(int fd, uint64_t at, uint64_t length) {
    Bytes bytes(length);
    size_t done = 0;
    while (done < length) {
        auto n = pread(fd, bytes.data() + done, length - done, at + done);
        if (n < 0 && errno == EINTR)
            continue;
        require(n > 0, "truncated read");
        done += n;
    }
    return bytes;
}
static void writeBytes(int fd, uint64_t at, const Bytes &bytes) {
    size_t done = 0;
    while (done < bytes.size()) {
        auto n = pwrite(fd, bytes.data() + done, bytes.size() - done, at + done);
        if (n < 0 && errno == EINTR)
            continue;
        require(n > 0, "write failed; partial retained");
        done += n;
    }
}
static Bytes inflateBlock(const Bytes &encoded) {
    require(encoded.size() > 4, "short compressed block");
    uint64_t size = get(encoded.data(), 4);
    require(size >= 8 && size <= BLOCK_LIMIT, "invalid raw size");
    Bytes raw(size + 1);
    z_stream z{};
    require(inflateInit(&z) == Z_OK, "inflate init failed");
    z.next_in = const_cast<Bytef *>(encoded.data() + 4);
    z.avail_in = encoded.size() - 4;
    z.next_out = raw.data();
    z.avail_out = raw.size();
    int result = inflate(&z, Z_FINISH);
    bool valid = result == Z_STREAM_END && z.total_out == size && z.avail_in == 0;
    inflateEnd(&z);
    require(valid, "invalid compressed block");
    raw.resize(size);
    return raw;
}
static uint64_t integer(const Bytes &data, size_t &position, size_t end) {
    uint64_t value = 0;
    for (unsigned shift = 0; shift < 64; shift += 7) {
        require(position < end, "truncated provenance");
        auto b = data[position++];
        require(shift < 63 || b < 2, "integer overflow");
        value |= uint64_t(b & 127) << shift;
        if (!(b & 128))
            return value;
    }
    throw std::runtime_error("invalid integer");
}
struct Input {
    int fd = -1;
    uint64_t base = 0, unique = 0;
    std::vector<std::string> names;
    std::vector<uint64_t> directory;
    struct stat snapshot{};
    Bytes header;
    std::string expectedSha;
    SHA256_CTX checksum{};
    ~Input() {
        if (fd >= 0)
            close(fd);
    }
    void unchanged() {
        struct stat now{};
        require(!fstat(fd, &now) && sameSnapshot(snapshot, now), "source changed");
    }
};
struct Totals {
    uint64_t hashes = 0, occurrences = 0, duplicateLines = 0, sortedCopies = 0;
    std::vector<uint64_t> files, inputHashes;
    Totals(size_t n, size_t inputs) : files(n), inputHashes(inputs) {}
    bool operator==(const Totals &b) const {
        return hashes == b.hashes && occurrences == b.occurrences && duplicateLines == b.duplicateLines &&
               sortedCopies == b.sortedCopies && files == b.files && inputHashes == b.inputHashes;
    }
    void add(const Totals &b) {
        hashes += b.hashes;
        occurrences += b.occurrences;
        duplicateLines += b.duplicateLines;
        sortedCopies += b.sortedCopies;
        for (size_t i = 0; i < files.size(); ++i)
            files[i] += b.files[i];
        for (size_t i = 0; i < inputHashes.size(); ++i)
            inputHashes[i] += b.inputHashes[i];
    }
};
struct Result {
    Bytes raw, encoded;
    std::vector<Bytes> sourceBlocks;
    Totals totals;
    Result(size_t n, size_t inputs) : totals(n, inputs) {}
};
struct Cursor {
    Bytes raw;
    uint64_t count = 0, entry = 0, offsets = 0, postings = 0;
    Input *input;
    Cursor(Input *in, Bytes bytes, uint32_t prefix) : raw(std::move(bytes)), input(in) {
        if (raw.empty())
            return;
        count = get(raw.data(), 4);
        offsets = 4 + count * 18;
        postings = offsets + (count + 1) * 4;
        require(count && postings <= raw.size(), "invalid hash directory");
        require(get(raw.data() + offsets, 4) == 0 &&
                    postings + get(raw.data() + offsets + count * 4, 4) == raw.size(),
                "invalid posting bounds");
        for (uint64_t i = 0; i < count; ++i) {
            auto h = raw.data() + 4 + i * 18;
            require((h[0] >> 4) == (prefix & 15) && (!i || memcmp(h - 18, h, 18) < 0),
                    "unordered or misplaced hash");
        }
    }
    const unsigned char *hash() const {
        return raw.data() + 4 + entry * 18;
    }
    std::vector<std::pair<uint64_t, uint64_t>> locations(Totals &totals) {
        size_t position = postings + get(raw.data() + offsets + entry * 4, 4),
               end = postings + get(raw.data() + offsets + (entry + 1) * 4, 4);
        require(position >= postings && position < end && end <= raw.size(), "invalid posting offset");
        auto groups = integer(raw, position, end);
        require(groups && groups <= input->names.size(), "invalid groups");
        uint64_t id = 0;
        std::vector<std::pair<uint64_t, uint64_t>> found;
        for (uint64_t g = 0; g < groups; ++g) {
            auto delta = integer(raw, position, end);
            require(!g || delta, "duplicate source group");
            id += delta;
            require(id < input->names.size(), "invalid file id");
            auto runs = integer(raw, position, end);
            require(runs && runs <= (end - position) / 2, "invalid run count");
            uint64_t line = 0, first = 0, count = 0;
            for (uint64_t r = 0; r < runs; ++r) {
                auto step = integer(raw, position, end), length = integer(raw, position, end);
                require(step && length && step < (1ULL << 53) && length < (1ULL << 53) &&
                            line + step + length < (1ULL << 53),
                        "invalid line run");
                if (!r)
                    first = step;
                line += step + length - 1;
                count += length;
            }
            totals.occurrences += count;
            totals.duplicateLines += count - 1;
            found.push_back({input->base + id, first});
        }
        require(position == end, "trailing provenance");
        ++entry;
        return found;
    }
};
struct Rewrite {
    std::vector<std::unique_ptr<Input>> inputs;
    std::vector<std::string> names;
    std::vector<int64_t> originals, remap;
    uint64_t reserve;
    int threads;
    std::string output;
    int fd = -1, lock = -1;
    ~Rewrite() {
        if (fd >= 0)
            close(fd);
        if (lock >= 0)
            close(lock);
    }
    Rewrite(const std::string &manifest, const std::string &out, uint64_t floor, int workers)
        : reserve(floor), threads(workers), output(out) {
        std::ifstream in(manifest);
        require(bool(in), "missing manifest");
        std::string s;
        std::getline(in, s);
        auto count = number(s.c_str());
        require(count && count <= 16, "invalid input count");
        std::set<std::string> all;
        for (uint64_t i = 0; i < count; ++i) {
            auto p = std::make_unique<Input>();
            std::string path;
            std::getline(in, path);
            std::getline(in, p->expectedSha);
            std::getline(in, s);
            auto files = number(s.c_str());
            require(files && files < 100000, "invalid catalog size");
            std::string catalog = "[";
            p->base = names.size();
            for (uint64_t j = 0; j < files; ++j) {
                std::getline(in, s);
                require(bool(in) && all.insert(s).second, "duplicate or missing filename");
                if (j)
                    catalog += ',';
                catalog += quote(s);
                p->names.push_back(s);
                names.push_back(s);
            }
            catalog += ']';
            p->fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW);
            require(p->fd >= 0 && !fstat(p->fd, &p->snapshot) && S_ISREG(p->snapshot.st_mode),
                    "missing regular source");
            auto h = readBytes(p->fd, 0, 24);
            require(!memcmp(h.data(), "PWNIDX01", 8) && get(h.data() + 8, 8) == catalog.size(),
                    "source header mismatch");
            p->unique = get(h.data() + 16, 8);
            p->header = readBytes(p->fd, 0, 24 + catalog.size() + (PREFIXES + 1) * 8);
            require(std::string(p->header.begin() + 24, p->header.begin() + 24 + catalog.size()) == catalog,
                    "source catalog mismatch");
            for (uint64_t k = 0; k <= PREFIXES; ++k)
                p->directory.push_back(get(p->header.data() + 24 + catalog.size() + k * 8, 8));
            require(p->directory.front() == p->header.size() &&
                        p->directory.back() == uint64_t(p->snapshot.st_size) &&
                        std::is_sorted(p->directory.begin(), p->directory.end()),
                    "source directory invalid");
            SHA256_Init(&p->checksum);
            SHA256_Update(&p->checksum, p->header.data(), p->header.size());
            inputs.push_back(std::move(p));
        }
        originals.assign(names.size(), -1);
        remap.assign(names.size(), -1);
        std::map<std::string, uint64_t> ids;
        for (size_t i = 0; i < names.size(); ++i)
            ids[names[i]] = i;
        for (size_t i = 0; i < names.size(); ++i) {
            const auto &name = names[i];
            if (name.size() >= 11 && name.substr(name.size() - 11) == "_sorted.txt") {
                auto f = ids.find(name.substr(0, name.size() - 11) + ".txt");
                if (f != ids.end())
                    originals[i] = f->second;
            }
        }
        lock = open((output + ".lock").c_str(), O_CREAT | O_RDWR | O_NOFOLLOW, 0600);
        require(lock >= 0 && !flock(lock, LOCK_EX | LOCK_NB), "migration already active");
        require(access(output.c_str(), F_OK) != 0 && access((output + ".partial").c_str(), F_OK) != 0,
                "output already exists");
    }
    Result block(uint32_t prefix, bool census) {
        Result result(names.size(), inputs.size());
        std::vector<Cursor> cursors;
        uint64_t expanded = 0;
        for (size_t i = 0; i < inputs.size(); ++i) {
            auto &input = inputs[i];
            auto length = input->directory[prefix + 1] - input->directory[prefix];
            Bytes encoded, raw;
            if (length) {
                require(length > 4 && length <= BLOCK_LIMIT + 65536, "compressed source too large");
                encoded = readBytes(input->fd, input->directory[prefix], length);
                raw = inflateBlock(encoded);
                expanded += raw.size();
                require(expanded <= BLOCK_LIMIT, "prefix expansion too large");
            }
            cursors.emplace_back(input.get(), std::move(raw), prefix);
            result.totals.inputHashes[i] = cursors.back().count;
            if (census)
                result.sourceBlocks.push_back(std::move(encoded));
        }
        Bytes hashes, postings;
        std::vector<uint64_t> offsets{0};
        for (;;) {
            int least = -1;
            for (size_t i = 0; i < cursors.size(); ++i)
                if (cursors[i].entry < cursors[i].count &&
                    (least < 0 || memcmp(cursors[i].hash(), cursors[least].hash(), 18) < 0))
                    least = i;
            if (least < 0)
                break;
            std::array<unsigned char, 18> hash;
            memcpy(hash.data(), cursors[least].hash(), 18);
            std::vector<std::pair<uint64_t, uint64_t>> locations;
            for (auto &cursor : cursors)
                if (cursor.entry < cursor.count && !memcmp(hash.data(), cursor.hash(), 18)) {
                    auto found = cursor.locations(result.totals);
                    locations.insert(locations.end(), found.begin(), found.end());
                }
            std::vector<std::pair<uint64_t, uint64_t>> retained;
            // Input catalogs occupy disjoint increasing file-id ranges, so the
            // merged locations stay ordered and cross-index originals are visible.
            for (auto loc : locations) {
                auto original = originals[loc.first];
                auto match = std::lower_bound(locations.begin(), locations.end(),
                                              std::make_pair(uint64_t(original), uint64_t(0)));
                if (original >= 0 && match != locations.end() && match->first == uint64_t(original)) {
                    ++result.totals.sortedCopies;
                    continue;
                }
                ++result.totals.files[loc.first];
                retained.push_back(loc);
            }
            require(!retained.empty(), "hash would be lost");
            ++result.totals.hashes;
            if (!census) {
                hashes.insert(hashes.end(), hash.begin(), hash.end());
                varint(postings, retained.size());
                uint64_t previous = 0;
                for (auto loc : retained) {
                    require(remap[loc.first] >= 0, "unplanned retained file");
                    uint64_t id = remap[loc.first];
                    varint(postings, id - previous);
                    varint(postings, 1);
                    varint(postings, loc.second);
                    varint(postings, 1);
                    previous = id;
                }
                offsets.push_back(postings.size());
                require(4 + hashes.size() + offsets.size() * 4 + postings.size() <= BLOCK_LIMIT,
                        "output prefix too large");
            }
        }
        if (!census && result.totals.hashes) {
            append(result.raw, result.totals.hashes, 4);
            result.raw.insert(result.raw.end(), hashes.begin(), hashes.end());
            for (auto n : offsets)
                append(result.raw, n, 4);
            result.raw.insert(result.raw.end(), postings.begin(), postings.end());
        }
        return result;
    }
    void checkSpace(uint64_t bytes) {
        struct statvfs st{};
        auto parent = output.substr(0, output.find_last_of('/'));
        require(!statvfs(parent.c_str(), &st), "cannot check free disk");
        uint64_t free = uint64_t(st.f_bavail) * st.f_frsize;
        require(free >= reserve && free - reserve >= bytes,
                "disk reserve reached; partial and sources retained");
    }
    void progress(const char *phase, uint64_t prefix) {
        std::cout << "{\"phase\":" << quote(phase) << ",\"prefixes\":" << prefix
                  << ",\"totalPrefixes\":" << PREFIXES << "}\n"
                  << std::flush;
    }
    void run() {
        Totals census(names.size(), inputs.size());
        std::vector<uint64_t> directory(PREFIXES + 1);
        Bytes header;
        uint64_t offset = 0;
        SHA256_CTX checksum;
        SHA256_Init(&checksum);
        // Census first so unused files can be removed without leaving holes in
        // stored file ids. The final pass compares every saved block to its inputs.
        for (int phase = 0; phase < 3; ++phase) {
            Totals total(names.size(), inputs.size());
            const char *label = phase == 0   ? "scanning_sources"
                                : phase == 1 ? "writing_replacement"
                                             : "verifying_saved_replacement";
            for (uint32_t batch = 0; batch < PREFIXES; batch += 32) {
                uint32_t size = std::min<uint64_t>(32, PREFIXES - batch);
                std::vector<std::unique_ptr<Result>> results(size);
                std::vector<std::string> errors(size);
#pragma omp parallel for num_threads(threads) schedule(dynamic)
                for (uint32_t i = 0; i < size; ++i) {
                    try {
                        auto r = std::make_unique<Result>(block(batch + i, phase == 0));
                        if (phase == 1 && !r->raw.empty()) {
                            uLongf length = compressBound(r->raw.size());
                            r->encoded.resize(4 + length);
                            for (unsigned k = 0; k < 4; ++k)
                                r->encoded[k] = r->raw.size() >> (8 * k);
                            require(compress2(r->encoded.data() + 4, &length, r->raw.data(), r->raw.size(),
                                              1) == Z_OK,
                                    "compression failed");
                            r->encoded.resize(4 + length);
                        }
                        results[i] = std::move(r);
                    } catch (const std::exception &e) {
                        errors[i] = e.what();
                    }
                }
                for (uint32_t i = 0; i < size; ++i) {
                    require(errors[i].empty(), errors[i].c_str());
                    auto &r = *results[i];
                    total.add(r.totals);
                    uint32_t prefix = batch + i;
                    if (phase == 0) {
                        for (size_t n = 0; n < inputs.size(); ++n)
                            SHA256_Update(&inputs[n]->checksum, r.sourceBlocks[n].data(),
                                          r.sourceBlocks[n].size());
                    } else if (phase == 1) {
                        directory[prefix] = offset;
                        checkSpace(r.encoded.size());
                        writeBytes(fd, offset, r.encoded);
                        offset += r.encoded.size();
                    } else {
                        auto saved =
                            readBytes(fd, directory[prefix], directory[prefix + 1] - directory[prefix]);
                        require((r.raw.empty() && saved.empty()) ||
                                    (!saved.empty() && inflateBlock(saved) == r.raw),
                                "saved replacement differs from sources");
                        SHA256_Update(&checksum, saved.data(), saved.size());
                    }
                }
                if (batch % 4096 == 0)
                    progress(label, batch + size);
                if (phase == 1 && batch % 16384 == 0)
                    require(!fsync(fd), "partial sync failed");
            }
            for (auto &input : inputs)
                input->unchanged();
            for (size_t i = 0; i < inputs.size(); ++i)
                require(total.inputHashes[i] == inputs[i]->unique, "input unique count mismatch");
            if (phase == 0) {
                census = total;
                uint64_t next = 0;
                std::string catalog = "[";
                for (size_t i = 0; i < names.size(); ++i)
                    if (census.files[i]) {
                        if (next)
                            catalog += ',';
                        catalog += quote(names[i]);
                        remap[i] = next++;
                    }
                catalog += ']';
                for (auto &input : inputs) {
                    unsigned char digest[32];
                    SHA256_Final(digest, &input->checksum);
                    require(hex(digest, 32) == input->expectedSha, "source SHA-256 mismatch");
                }
                header.insert(header.end(), {'P', 'W', 'N', 'I', 'D', 'X', '0', '1'});
                append(header, catalog.size(), 8);
                append(header, census.hashes, 8);
                header.insert(header.end(), catalog.begin(), catalog.end());
                header.resize(header.size() + (PREFIXES + 1) * 8);
                checkSpace(header.size());
                fd = open((output + ".partial").c_str(), O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW, 0600);
                require(fd >= 0, "cannot create exclusive partial");
                writeBytes(fd, 0, header);
                offset = header.size();
            } else {
                require(total == census, "migration counts changed");
                if (phase == 1) {
                    directory[PREFIXES] = offset;
                    size_t start = header.size() - (PREFIXES + 1) * 8;
                    for (size_t p = 0; p < directory.size(); ++p)
                        for (unsigned b = 0; b < 8; ++b)
                            header[start + p * 8 + b] = directory[p] >> (8 * b);
                    writeBytes(fd, 0, header);
                    require(!fsync(fd), "replacement sync failed");
                    require(readBytes(fd, 0, header.size()) == header, "saved header mismatch");
                    SHA256_Update(&checksum, header.data(), header.size());
                }
            }
        }
        unsigned char digest[32];
        SHA256_Final(digest, &checksum);
        require(!link((output + ".partial").c_str(), output.c_str()), "cannot publish replacement");
        auto parent = output.substr(0, output.find_last_of('/'));
        int dir = open(parent.c_str(), O_RDONLY | O_DIRECTORY);
        require(dir >= 0 && !fsync(dir), "publication sync failed");
        require(!unlink((output + ".partial").c_str()) && !fsync(dir), "publication finalization failed");
        close(dir);
        uint64_t retained = 0, files = 0;
        for (auto n : census.files) {
            retained += n;
            files += bool(n);
        }
        std::cout << "{\"phase\":\"complete\",\"uniqueHashes\":" << census.hashes
                  << ",\"originalOccurrences\":" << census.occurrences
                  << ",\"retainedOccurrences\":" << retained
                  << ",\"duplicateLinesRemoved\":" << census.duplicateLines
                  << ",\"sortedMatchesRemoved\":" << census.sortedCopies
                  << ",\"filesBefore\":" << names.size() << ",\"filesAfter\":" << files
                  << ",\"bytes\":" << offset << ",\"sha256\":" << quote(hex(digest, 32))
                  << ",\"savedRecordsVerified\":true,\"inputsDeleted\":false}\n"
                  << std::flush;
    }
};
int main(int argc, char **argv) {
    if (argc != 5) {
        std::cerr << "usage: rewrite MANIFEST OUTPUT RESERVE_BYTES THREADS\n";
        return 2;
    }
    try {
        int threads = number(argv[4]);
        require(threads >= 1 && threads <= 32, "invalid thread count");
        Rewrite r(argv[1], argv[2], number(argv[3]), threads);
        r.run();
        return 0;
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
