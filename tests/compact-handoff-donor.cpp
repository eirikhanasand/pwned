#define main original_builder_main
#include "../scripts/build-compact-inventory.cpp"
#undef main
int main(int argc, char** argv) {
    if (argc != 11) return 2;
    try {
        Builder worker(argv); worker.setup(); worker.hashInput();
        if (getenv("PWNED_FIXTURE_DENSE")) {
            for (uint64_t i=0; i<std::min<uint64_t>(60000, worker.expectedLines); ++i) {
                worker.records[i].hash[0]=0; worker.records[i].hash[1]=0; worker.records[i].hash[2]&=15;
            }
        }
        worker.sortRecords();
        std::ofstream metadata(std::string(argv[2])+".donor.json");
        metadata << "{\"base\":" << reinterpret_cast<uint64_t>(worker.records) << "}"; metadata.close();
        worker.publish(); return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
