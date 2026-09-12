#pragma once

#include <string>
#include <vector>
#include <optional>
#include <map>
#include <memory>
#include <mutex>
#include <filesystem>

namespace knishio {
namespace storage {

/**
 * Interface for pluggable key-value persistence backends
 */
class StorageBackend {
public:
    virtual ~StorageBackend() = default;

    /**
     * Retrieve item by key
     */
    virtual std::optional<std::string> getItem(const std::string& key) = 0;

    /**
     * Store item by key
     */
    virtual void setItem(const std::string& key, const std::string& value) = 0;

    /**
     * Remove item by key, returning true if it was present
     */
    virtual bool removeItem(const std::string& key) = 0;

    /**
     * List all keys in the store
     */
    virtual std::vector<std::string> keys() = 0;
};

/**
 * Thread-safe in-memory storage backend
 */
class MemoryStorageBackend : public StorageBackend {
public:
    MemoryStorageBackend() = default;
    ~MemoryStorageBackend() override = default;

    std::optional<std::string> getItem(const std::string& key) override;
    void setItem(const std::string& key, const std::string& value) override;
    bool removeItem(const std::string& key) override;
    std::vector<std::string> keys() override;

    void clear();

private:
    std::map<std::string, std::string> store_;
    mutable std::mutex mutex_;
};

/**
 * File-backed persistent storage backend with atomic updates and 0600 permissions
 */
class FileStorageBackend : public StorageBackend {
public:
    explicit FileStorageBackend(std::filesystem::path path);
    ~FileStorageBackend() override = default;

    std::optional<std::string> getItem(const std::string& key) override;
    void setItem(const std::string& key, const std::string& value) override;
    bool removeItem(const std::string& key) override;
    std::vector<std::string> keys() override;

    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

private:
    void load();
    void persist();

    std::filesystem::path path_;
    std::map<std::string, std::string> store_;
    mutable std::mutex mutex_;
};

} // namespace storage
} // namespace knishio

namespace KnishIO {
namespace storage {
    using knishio::storage::StorageBackend;
    using knishio::storage::MemoryStorageBackend;
    using knishio::storage::FileStorageBackend;
} // namespace storage
} // namespace KnishIO
