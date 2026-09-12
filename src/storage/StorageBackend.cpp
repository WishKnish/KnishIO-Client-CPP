#include "storage/StorageBackend.h"
#include "storage/SecretStorageException.h"
#include "third_party/nlohmann/json.hpp"
#include <fstream>
#include <random>
#include <sstream>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace knishio {
namespace storage {

using json = nlohmann::json;

// ============================================================================
// MemoryStorageBackend
// ============================================================================

std::optional<std::string> MemoryStorageBackend::getItem(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = store_.find(key);
    if (it != store_.end()) {
        return it->second;
    }
    return std::nullopt;
}

void MemoryStorageBackend::setItem(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    store_[key] = value;
}

bool MemoryStorageBackend::removeItem(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    return store_.erase(key) > 0;
}

std::vector<std::string> MemoryStorageBackend::keys() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    result.reserve(store_.size());
    for (const auto& [k, _] : store_) {
        result.push_back(k);
    }
    return result;
}

void MemoryStorageBackend::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    store_.clear();
}

// ============================================================================
// FileStorageBackend
// ============================================================================

FileStorageBackend::FileStorageBackend(std::filesystem::path path)
    : path_(std::move(path)) {
    load();
}

void FileStorageBackend::load() {
    std::lock_guard<std::mutex> lock(mutex_);
    store_.clear();

    if (!std::filesystem::exists(path_)) {
        return;
    }

    std::ifstream file(path_);
    if (!file.is_open()) {
        throw SecretStorageException("file storage: failed to open " + path_.string());
    }

    try {
        json j = json::parse(file);
        if (j.is_object()) {
            for (auto it = j.begin(); it != j.end(); ++it) {
                if (it.value().is_string()) {
                    store_[it.key()] = it.value().get<std::string>();
                }
            }
        }
    } catch (const std::exception& e) {
        throw SecretStorageException("file storage: corrupted store at " + path_.string() + ": " + e.what());
    }
}

void FileStorageBackend::persist() {
    auto parent = path_.parent_path();
    if (!parent.empty() && !std::filesystem::exists(parent)) {
        std::error_code ec;
        if (!std::filesystem::create_directories(parent, ec) && ec) {
            throw SecretStorageException("file storage: failed to create directory " + parent.string() + ": " + ec.message());
        }
    }

    // Generate random temporary filename in same directory
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;
    std::stringstream ss;
    ss << path_.string() << ".tmp." << std::hex << dist(gen);
    std::filesystem::path tmpPath = ss.str();

    {
        std::ofstream file(tmpPath, std::ios::trunc);
        if (!file.is_open()) {
            throw SecretStorageException("file storage: failed to open temp file " + tmpPath.string());
        }

        json j = store_;
        file << j.dump(2);
        file.flush();
        if (!file.good()) {
            std::filesystem::remove(tmpPath);
            throw SecretStorageException("file storage: failed to write to " + tmpPath.string());
        }
    }

    // Apply restrictive permissions (0600: read/write by owner only)
#ifndef _WIN32
    chmod(tmpPath.c_str(), S_IRUSR | S_IWUSR);
#endif
    std::error_code permEc;
    std::filesystem::permissions(tmpPath,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, permEc);

    // Atomically rename temporary file to destination path
    std::error_code renameEc;
    std::filesystem::rename(tmpPath, path_, renameEc);
    if (renameEc) {
        std::filesystem::remove(tmpPath);
        throw SecretStorageException("file storage: failed to rename " + tmpPath.string() + " to " + path_.string() + ": " + renameEc.message());
    }
}

std::optional<std::string> FileStorageBackend::getItem(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = store_.find(key);
    if (it != store_.end()) {
        return it->second;
    }
    return std::nullopt;
}

void FileStorageBackend::setItem(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    store_[key] = value;
    persist();
}

bool FileStorageBackend::removeItem(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = store_.find(key);
    if (it == store_.end()) {
        return false;
    }
    store_.erase(it);
    persist();
    return true;
}

std::vector<std::string> FileStorageBackend::keys() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    result.reserve(store_.size());
    for (const auto& [k, _] : store_) {
        result.push_back(k);
    }
    return result;
}

} // namespace storage
} // namespace knishio
