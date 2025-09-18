#include <SQLiteCpp/Database.h>
#include <iden3math/bigint.h>
#include <iden3math/ec/babyjub.h>
#include <iden3math/fp1.h>
#include <iden3math/hash/blake.h>
#include <iden3math/hash/pedersen.h>
#include <iden3math/prime.h>
#include <iden3math/serialize.h>
#include <chrono>
#include <iostream>
#include <mutex>
#include <thread>

#define BUCKET_MS 100

using namespace iden3math;

bool job(const std::shared_ptr<SQLite::Database>& db, int64_t start_unix_timestamp, int64_t end_unix_timestamp, bool* done, int64_t* progress) {
    SQLite::Statement sql(*db, "INSERT INTO t_precomputed(timestamp_ms, commitment) VALUES (?, ?)");
    // Generate and write database
    const auto fp1  = Fp1(prime::bn254());
    const auto salt = hash::blake256("iden3math");
    for (int64_t seed = start_unix_timestamp; seed <= end_unix_timestamp; seed += BUCKET_MS) {
        // Compute private note
        auto p1 = hash::blake256(fp1.add(BigInt(salt, LE), BigInt(seed)).bytes(LE));
        auto p2 = hash::blake256(fp1.add(BigInt(salt, LE), BigInt(p1, LE)).bytes(LE));
        ByteVec2D ds = { p1, p2 };
        auto note = serialize::concat(ds);
        note.pop_back();
        note.pop_back();
        if (note.size() != 62) {
            throw std::runtime_error("Incorrect note size " + std::to_string(note.size()));
        }
        // Pedersen hash
        ByteVec1D digest;
        hash::pedersen(note, digest);
        if (digest.size() != 32) {
            throw std::runtime_error("Incorrect digest size " + std::to_string(digest.size()));
        }
        // Decompress ec point
        std::optional<ec::Point> point = ec::babyjub::decompress(digest, LE);
        if (std::nullopt == point) {
            throw std::runtime_error("Failed to decompress point");
        }
        auto commitment = point->x.bytes(BE);
        serialize::pad(commitment, 0x00, 32 - commitment.size(), false);
        // Insert
        sql.bind(1, seed);
        sql.bind(2, commitment.data(), static_cast<int32_t>(commitment.size()));
        sql.exec();
        sql.reset();
        sql.clearBindings();
        // Update progress
        ++*progress;
    }
    *done = true;
    return true;
}

/*
 * precompute <threads> <start_unix_timestamp> <end_unix_timestamp>
 * 1759276800000 = Oct 1, 2025 (milliseconds)
 * 1790812800000 = Oct 1, 2026 (milliseconds)
 */
int main(int argc, char* argv[]) {
    // Parse precompute ranges
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << "<threads> <start_unix_timestamp> <end_unix_timestamp>" << std::endl;
        return 1;
    }
    int64_t num_of_workers = strtoll(argv[1], nullptr, 10);
    int64_t start_unix_timestamp = strtoll(argv[2], nullptr, 10);
    int64_t end_unix_timestamp = strtoll(argv[3], nullptr, 10);
    if (start_unix_timestamp < 0) {
        std::cerr << "Starting unix timestamp is negative" << std::endl;
        return 1;
    }
    if (end_unix_timestamp < 0) {
        std::cerr << "Ending unix timestamp is negative" << std::endl;
        return 1;
    }
    if (start_unix_timestamp >= end_unix_timestamp) {
        std::cerr << "End timestamp should greater than the start timestamp" << std::endl;
        return 1;
    }
    start_unix_timestamp -= start_unix_timestamp % BUCKET_MS;
    end_unix_timestamp += BUCKET_MS - end_unix_timestamp % BUCKET_MS;
    auto num_of_notes = (end_unix_timestamp - start_unix_timestamp) / BUCKET_MS + 1;
    if (num_of_notes < num_of_workers) {
        num_of_notes = num_of_workers;
    } else {
        num_of_notes += num_of_workers - (num_of_notes % num_of_workers);
    }
    end_unix_timestamp = start_unix_timestamp + (num_of_notes - 1) * BUCKET_MS;

    // Print parameters
    std::cout << "workers=" << num_of_workers
              << ", start=" << start_unix_timestamp
              << ", end=" << end_unix_timestamp
              << ", notes=" << num_of_notes
              << std::endl;

    // Open database file
    std::string db_file = "precomputed_" + std::to_string(start_unix_timestamp) + "_" + std::to_string(end_unix_timestamp) + ".sqlite";
    std::shared_ptr<SQLite::Database> db;
    try {
        db = std::make_shared<SQLite::Database>(db_file, SQLite::OPEN_CREATE | SQLite::OPEN_READWRITE);
        db->exec("PRAGMA journal_mode=WAL;"
                 "PRAGMA synchronous=OFF;"      // Or 'NORMAL' for better safety but slower
                 "PRAGMA cache_size=8388608;"   // 8 GB page cache
                 "PRAGMA mmap_size=8388608;"    // 8 GB memory-mapped I/O
                 "PRAGMA temp_store=MEMORY;"
                 "PRAGMA optimize;"
                 "CREATE TABLE IF NOT EXISTS t_precomputed (timestamp_ms INTEGER, commitment BLOB NOT NULL) WITHOUT ROWID");
    } catch (const std::exception& e) {
        std::cerr << "Failed to open " << db_file << ", " << e.what() << std::endl;
        return 1;
    }

    // Start workers
    std::vector<std::shared_ptr<std::thread>> workers;
    bool* worker_done     = new bool[num_of_workers];
    auto* worker_size     = new int64_t[num_of_workers];
    auto* worker_progress = new int64_t[num_of_workers];
    for (int64_t i = 0; i < num_of_workers; ++i) {
        // Calculate worker start-end range
        int64_t worker_start = start_unix_timestamp + i * (num_of_notes / num_of_workers) * BUCKET_MS;
        int64_t worker_end;
        if (i == num_of_workers - 1) {
            worker_end = end_unix_timestamp;
        } else {
            worker_end = start_unix_timestamp + (i + 1) * (num_of_notes / num_of_workers) * BUCKET_MS - BUCKET_MS;
        }
        std::cout << "Worker " << i << " range: " << worker_start << ", " << worker_end << std::endl;
        // Start worker
        worker_done[i] = false;
        worker_size[i] = (worker_end - worker_start) / BUCKET_MS + 1;
        worker_progress[i] = 0;
        auto worker = std::make_shared<std::thread>([=] {
            job(db, worker_start, worker_end, &worker_done[i], &worker_progress[i]);
        });
        worker->detach();
        workers.push_back(worker);
    }

    // Print placeholder lines and move cursor up
    std::cout << "======== Progress ========" << std::endl;
    int64_t flush_lines = num_of_workers + 1;
    for (int i = 0; i < flush_lines; ++i) {
        std::cout << "Worker " << i << " Progress: 0.00%" << std::endl;
    }
    std::cout << "\x1b[" << flush_lines << "F" << std::flush;

    // Monitor progress
    constexpr auto log_interval = std::chrono::seconds(1);
    auto log_tp = std::chrono::steady_clock::now();
    bool all_done;
    int64_t overall_count_prev_log = 0;
    do {
        int64_t overall_count = 0;
        // Update log timestamp
        auto now = std::chrono::steady_clock::now();
        auto elapsed = now - log_tp;
        bool need_log = elapsed >= log_interval;
        if (need_log) {
            log_tp = now;
        }
        all_done = true;
        // Check worker status and print progress
        for (int64_t i = 0; i < num_of_workers; ++i) {
            if (!worker_done[i]) {
                all_done = false;
            }
            overall_count += worker_progress[i];
            auto progress = static_cast<double>(worker_progress[i]) / static_cast<double>(worker_size[i]) * 100.0;
            if (need_log) {
                std::cout << "\x1b[2K\r"  // Clear the entire line and move cursor to the beginning
                          << "Worker " << i << " progress: " << std::fixed << std::setprecision(4) << progress << "%" << std::endl;
            }
        }
        // Print ETA
        if (need_log) {
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
            auto eta_ms = static_cast<double>(num_of_notes - overall_count) / static_cast<double>(overall_count - overall_count_prev_log) * elapsed_ms;
            auto eta = std::chrono::system_clock::now() + std::chrono::milliseconds(static_cast<int64_t>(eta_ms));
            std::chrono::zoned_time zt{std::chrono::current_zone(), eta};
            std::cout << "\x1b[2K\r"
                      << "ETA: " << std::format("{:%F %T %Z}", zt) << std::endl;
            overall_count_prev_log = overall_count;
        }
        // Move cursor up if log
        if (!all_done and need_log) {
            std::cout << "\x1b[" << flush_lines << "F" << std::flush;
        }
        // Sleep to avoid busy loop
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    } while (!all_done);

    delete[] worker_done;
    delete[] worker_size;
    delete[] worker_progress;
    return 0;
}
