#include "../aes_encryption_plugin.h"
#include <chrono>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include "base/factory.h"
#include "dram_controller/plugins/encryption/aes_config.h"
#include "frontend/frontend.h"
#include "dram_controller/plugins/encryption/aes_encryption_plugin.h"
#include "dram_controller/controller.h"
#include "frontend/impl/memory_trace/loadstore_trace.cpp"
#include "memory_system/memory_system.h"
namespace Ramulator {

    class AESEncryptionPlugin;
    class IControllerPlugin;

    class AESEncryptionPlugin : public IControllerPlugin, public Implementation, public IAESEncryptionPlugin {
        RAMULATOR_REGISTER_IMPLEMENTATION(IControllerPlugin, AESEncryptionPlugin, "AESEncryption", "AESEncryption")

        private:
            IControllerPlugin* m_controller = nullptr;
            uint8_t m_default_data[64] = {0};
            IFrontEnd* m_frontend = nullptr;
            IMemorySystem* m_memory_system;

        public:
            void init() override {
                std::cout << "Initializing AES Encryption Plugin..." << std::endl;

                m_encryption_enabled = false;
                m_decrypt_on_read = true;
                m_encrypt_on_write = true;

                for (int i = 0; i < sizeof(m_default_data); ++i) {
                    m_default_data[i] = i;
                }

                parseConfig();

                if (!loadKeyFromConfig()) {
                    std::vector<uint8_t> test_key = {
                        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                        0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
                     };
                    if (setEncryptionKey(test_key)) {
                            std::cout << "Using default test key (128-bit)" << std::endl;
                            m_encryption_enabled = true;
                    }
                }

                if (m_aes_engine.isInitialized()) {
                    std::cout << "AES Engine initialized successfully ("
                            << m_aes_engine.getKeySize()*8 << "-bit)" << std::endl;
                } else {
                    std::cerr << "Warning: AES Engine not initialized - plugin disabled" << std::endl;
                }
            }

            void setup(IFrontEnd* frontend, IMemorySystem* memory_system) override {
                m_frontend = frontend;
                m_memory_system = memory_system;

                if (auto lst = dynamic_cast<LoadStoreTrace*>(frontend)) {
                    std::cout << "Linked to LoadStoreTrace frontend\n";
                } else {
                    std::cerr << "Warning: AES plugin expects LoadStoreTrace frontend\n";
                }
            }

            void update(bool request_found, ReqBuffer::iterator& req_it) override {
                    if (!m_encryption_enabled || !request_found) return;
                    Request& req = *req_it;
                    process_request(req);
            }

            void process_request(Request& req) {
                std::cout << "Processing " << (req.type_id == Request::Type::Read ? "Read" : "Write")
                          << " @ 0x" << std::hex << req.addr << std::dec << std::endl;
                if (!m_encryption_enabled) {
                    std::cout << "  [SKIP] Encryption plugin disabled." << std::endl;
                    return;
                }

                if (req.type_id == Request::Type::Read && !m_decrypt_on_read) {
                    std::cout << "  [SKIP] Decryption on read disabled." << std::endl;
                    return;
                }

                if (!req.data_ptr || req.size == 0) {
                    req.size = 64;
                    req.data_ptr = new uint8_t[req.size];
                    for (size_t i = 0; i < req.size; i++) {
                        static_cast<uint8_t*>(req.data_ptr)[i] = (req.addr + i) % 256;
                    }
                }

                try {
                    if (req.type_id == Request::Type::Read && m_decrypt_on_read) {
                        std::cout << "[process_request] Decrypting data of size " << req.size << std::endl;
                        m_aes_engine.handleRead(req.addr);
                        if (decryptData(static_cast<uint8_t*>(req.data_ptr), req.size)) {
                            std::cout << "Successful decrypt" << std::endl;
                        }
                    } else if (req.type_id == Request::Type::Write && m_encrypt_on_write) {
                        std::cout << "[process_request] Encrypting data of size " << req.size << std::endl;
                        m_aes_engine.handleWrite(req.addr);
                        if (encryptData(static_cast<uint8_t*>(req.data_ptr), req.size)) {
                            std::cout << "Successful encrypt" << std::endl;
                        } else {
                            std::cerr << "[process_request] Encryption failed!" << std::endl;
                        }
                    }
                } catch (const std::exception& e) {
                    std::cerr << "AES Error: " << e.what() << std::endl;
                }

                //buffer deallocation
                if (req.data_ptr != m_default_data) {
                    delete[] static_cast<uint8_t*>(req.data_ptr);
                }
            }

            void finalize() {
                if (m_encryption_enabled) {
                    dumpStatistics();
                }
            }

            bool setEncryptionKey(const std::vector<uint8_t>& key) {
                if (!AESConfig::validateKey(key)) {
                    return false;
                }

                bool success = m_aes_engine.initialize(key);
                if (success) {
                    m_encryption_enabled = true;
                }
                return success;
            }

            bool setEncryptionKey(const uint8_t* key, int key_size) {
                std::vector<uint8_t> key_vec(key, key + key_size);
                return setEncryptionKey(key_vec);
            }

            void enableEncryption(bool enable) {
                m_encryption_enabled = enable && m_aes_engine.isInitialized();
            }

            void enableDecryptionOnRead(bool enable) {
                m_decrypt_on_read = enable;
            }

            void enableEncryptionOnWrite(bool enable) {
                m_encrypt_on_write = enable;
            }
        
            bool encryptData(uint8_t* data, size_t size) {
                if (!m_aes_engine.isInitialized()) {
                    std::cerr << "[encryptData] AES engine not initialized!" << std::endl;
                    return false;
                }
                if (!data) {
                    std::cerr << "[encryptData] Data pointer is null!" << std::endl;
                    return false;
                }
                if (size == 0) {
                    std::cerr << "[encryptData] Size is zero!" << std::endl;
                    return false;
                }

                const size_t blocks = size / AES_BLOCK_SIZE;
                const size_t remaining = size % AES_BLOCK_SIZE;
                std::cout << "[encryptData] Encrypting " << blocks << " blocks, remaining bytes: " << remaining << std::endl;

                const auto start = std::chrono::high_resolution_clock::now();

                for (size_t i = 0; i < blocks; i++) {
                    uint8_t* block_ptr = data + (i * AES_BLOCK_SIZE);
                    uint8_t encrypted_block[AES_BLOCK_SIZE];

                    if (!m_aes_engine.encrypt(block_ptr, encrypted_block)) {
                        std::cerr << "[encryptData] Failed to encrypt block " << i << std::endl;
                        return false;
                    }

                    std::memcpy(block_ptr, encrypted_block, AES_BLOCK_SIZE);
                }

                if (remaining > 0) {
                    uint8_t padded_block[AES_BLOCK_SIZE] = {0};
                    std::memcpy(padded_block, data + (blocks * AES_BLOCK_SIZE), remaining);

                    uint8_t encrypted_block[AES_BLOCK_SIZE];
                    if (!m_aes_engine.encrypt(padded_block, encrypted_block)) {
                        std::cerr << "[encryptData] Failed to encrypt last partial block" << std::endl;
                        return false;
                    }

                    std::memcpy(data + (blocks * AES_BLOCK_SIZE), encrypted_block, remaining);
                }

                const auto end = std::chrono::high_resolution_clock::now();
                const auto nanoTime = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
                const double tCk_ns = 1.833;
                uint64_t dram_cycles = static_cast<uint64_t>(nanoTime / tCk_ns);
                m_encryption_cycles = dram_cycles;
                m_encrypt_operations += blocks;
                return true;
            }

            bool decryptData(uint8_t* data, size_t size) {
                if (!m_aes_engine.isInitialized() || !data || size == 0) {
                    return false;
                }

                size_t blocks = size / AES_BLOCK_SIZE;
                size_t remaining = size % AES_BLOCK_SIZE;

                auto start = std::chrono::high_resolution_clock::now();

                for (size_t i = 0; i < blocks; i++) {
                    uint8_t* block_ptr = data + (i * AES_BLOCK_SIZE);
                    uint8_t decrypted_block[AES_BLOCK_SIZE];

                    if (!m_aes_engine.decrypt(block_ptr, decrypted_block)) {
                        return false;
                    }

                    std::memcpy(block_ptr, decrypted_block, AES_BLOCK_SIZE);
                }

                if (remaining > 0) {
                    uint8_t padded_block[AES_BLOCK_SIZE] = {0};
                    std::memcpy(padded_block, data + (blocks * AES_BLOCK_SIZE), remaining);

                    uint8_t decrypted_block[AES_BLOCK_SIZE];
                    if (!m_aes_engine.decrypt(padded_block, decrypted_block)) {
                        return false;
                    }

                    std::memcpy(data + (blocks * AES_BLOCK_SIZE), decrypted_block, remaining);
                }

                auto end = std::chrono::high_resolution_clock::now();
                auto nanoTime = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
                double tCk_ns = 1.833;
                uint64_t dram_cycles = static_cast<uint64_t>(nanoTime / tCk_ns);
                m_decryption_cycles = dram_cycles;
                m_decrypt_operations += blocks;
                return true;
            }

            bool isEncryptionRequired(const Request& req) {
                    return true;
            }

            bool isDecryptionRequired(const Request& req) {
                    return true;
            }

            void parseConfig() {
                const char* enable_env = std::getenv("AES_PLUGIN_ENABLE");
                if (enable_env && std::string(enable_env) == "1") {
                    m_encryption_enabled = true;
                }
            }

            bool loadKeyFromConfig() {
                std::cout << "Attempting to load AES key..." << std::endl;

                if (const char* key_env = std::getenv("AES_PLUGIN_KEY")) {
                    std::cout << "Trying environment variable key" << std::endl;
                    std::string key_str(key_env);
                    key_str.erase(std::remove_if(key_str.begin(), key_str.end(), ::isspace), key_str.end());

                    if (key_str.length() == 32 || key_str.length() == 48 || key_str.length() == 64) {
                        std::vector<uint8_t> key;
                        for (size_t i = 0; i < key_str.length(); i += 2) {
                            try {
                                std::string byte_str = key_str.substr(i, 2);
                                uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
                                key.push_back(byte);
                            } catch (...) {
                                std::cerr << "Invalid hex byte in key" << std::endl;
                                return false;
                            }
                        }
                        if (setEncryptionKey(key)) {
                            m_encryption_enabled = true;
                            return true;
                        }
                    }
                }

                if (const char* key_file_env = std::getenv("AES_PLUGIN_KEY_FILE")) {
                    std::cout << "Trying config file: " << key_file_env << std::endl;
                    AESConfig::EncryptionSettings settings;
                    if (AESConfig::loadFromFile(key_file_env, settings)) {
                        if (setEncryptionKey(settings.key)) {
                            m_encryption_enabled = true;
                            return true;
                        }
                    }
                }

                std::cerr << "No valid AES key configuration found" << std::endl;
                return false;
            }

            double getAverageEncryptionCycles() const {
                return m_encrypt_operations > 0 ? static_cast<double>(m_encryption_cycles) / m_encrypt_operations : 0.0;
            }

            double getAverageDecryptionCycles() const {
                return m_decrypt_operations > 0 ? static_cast<double>(m_decryption_cycles) / m_decrypt_operations : 0.0;
            }

            void dumpStatistics() const {
                std::cout << "Encryption Plugin Statistics" << std::endl;
                std::cout << "Encryption Operations: " << m_encrypt_operations << std::endl;
                std::cout << "Decryption Operations: " << m_decrypt_operations << std::endl;
                std::cout << "Total Bytes Encrypted: " << m_total_bytes_encrypted << std::endl;
                std::cout << "Total Bytes Decrypted: " << m_total_bytes_decrypted << std::endl;
                std::cout << "Average Encryption Cycles: " << getAverageEncryptionCycles() << std::endl;
                std::cout << "Average Decryption Cycles: " << getAverageDecryptionCycles() << std::endl;
                std::cout << "Key Size: " << m_aes_engine.getKeySize() * 8 << " bits" << std::endl;
                std::cout << "Rounds: " << m_aes_engine.getRounds() << std::endl;
            }

    };

}

