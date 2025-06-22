#include "../aes_encryption_plugin.h"
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <fstream>

#include "dram_controller/plugins/encryption/aes_config.h"
#include "frontend/frontend.h"

namespace Ramulator {
    void Ramulator::AESEncryptionPlugin::init() {
        m_encryption_enabled = false;
        m_decrypt_on_read = true;
        m_encrypt_on_write = true;
        m_encrypt_operations = 0;
        m_decrypt_operations = 0;
        m_total_bytes_encrypted = 0;
        m_total_bytes_decrypted = 0;
        m_encryption_cycles = 0;
        m_decryption_cycles = 0;

        parseConfig();
        loadKeyFromConfig();
    }

    void Ramulator::AESEncryptionPlugin::setup(IFrontEnd* frontend, IMemorySystem* memory_system) {

    }

    void Ramulator::AESEncryptionPlugin::update(bool request_found, ReqBuffer::iterator& req_it) {
        if (!m_encryption_enabled || !request_found) {
            return;
        }

        auto& req = *req_it;
        auto start_time = std::chrono::high_resolution_clock::now();

        try {
            if (req.type_id == Request::Type::Read && m_decrypt_on_read && isDecryptionRequired(req)) {
                if (req.data_ptr && req.size > 0) {
                    bool success = decryptData(static_cast<uint8_t*>(req.data_ptr), req.size);
                    if (success) {
                        auto end_time = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time);
                        updateStats(false, req.size, duration.count());
                    }
                }
            }

            if (req.type_id == Request::Type::Write && m_encrypt_on_write && isEncryptionRequired(req)) {
                if (req.data_ptr && req.size > 0) {
                    bool success = encryptData(static_cast<uint8_t*>(req.data_ptr), req.size);
                    if (success) {
                        auto end_time = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time);
                        updateStats(true, req.size, duration.count());
                    }
                }
            }
        } catch (const AESException& e) {
            std::cerr << "AES Plugin Error: " << e.what() << std::endl;
        }
    }

    void Ramulator::AESEncryptionPlugin::finalize() {
        if (m_encryption_enabled) {
            dumpStatistics();
        }
    }

    bool Ramulator::AESEncryptionPlugin::setEncryptionKey(const std::vector<uint8_t>& key) {
        if (!AESConfig::validateKey(key)) {
            return false;
        }

        bool success = m_aes_engine.initialize(key);
        if (success) {
            m_encryption_enabled = true;
        }
        return success;
    }

    bool Ramulator::AESEncryptionPlugin::setEncryptionKey(const uint8_t* key, int key_size) {
        std::vector<uint8_t> key_vec(key, key + key_size);
        return setEncryptionKey(key_vec);
    }

    void Ramulator::AESEncryptionPlugin::enableEncryption(bool enable) {
        m_encryption_enabled = enable && m_aes_engine.isInitialized();
    }

    void Ramulator::AESEncryptionPlugin::enableDecryptionOnRead(bool enable) {
        m_decrypt_on_read = enable;
    }

    void Ramulator::AESEncryptionPlugin::enableEncryptionOnWrite(bool enable) {
        m_encrypt_on_write = enable;
    }

    bool Ramulator::AESEncryptionPlugin::encryptData(uint8_t* data, size_t size) {
        if (!m_aes_engine.isInitialized() || !data || size == 0) {
            return false;
        }

        size_t blocks = size / AES_BLOCK_SIZE;
        size_t remaining = size % AES_BLOCK_SIZE;

        for (size_t i = 0; i < blocks; i++) {
            uint8_t* block_ptr = data + (i * AES_BLOCK_SIZE);
            uint8_t encrypted_block[AES_BLOCK_SIZE];

            if (!m_aes_engine.encrypt(block_ptr, encrypted_block)) {
                return false;
            }

            std::memcpy(block_ptr, encrypted_block, AES_BLOCK_SIZE);
        }

        if (remaining > 0) {
            uint8_t padded_block[AES_BLOCK_SIZE] = {0};
            std::memcpy(padded_block, data + (blocks * AES_BLOCK_SIZE), remaining);

            uint8_t encrypted_block[AES_BLOCK_SIZE];
            if (!m_aes_engine.encrypt(padded_block, encrypted_block)) {
                return false;
            }

            std::memcpy(data + (blocks * AES_BLOCK_SIZE), encrypted_block, remaining);
        }

        return true;
    }

    bool Ramulator::AESEncryptionPlugin::decryptData(uint8_t* data, size_t size) {
        if (!m_aes_engine.isInitialized() || !data || size == 0) {
            return false;
        }

        size_t blocks = size / AES_BLOCK_SIZE;
        size_t remaining = size % AES_BLOCK_SIZE;

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

        return true;
    }

    bool Ramulator::AESEncryptionPlugin::isEncryptionRequired(const Request& req) {
        return true;
    }

    bool Ramulator::AESEncryptionPlugin::isDecryptionRequired(const Request& req) {
        return true;
    }

    void Ramulator::AESEncryptionPlugin::updateStats(bool is_encrypt, size_t bytes, uint64_t cycles) {
        if (is_encrypt) {
            m_encrypt_operations++;
            m_total_bytes_encrypted += bytes;
            m_encryption_cycles += cycles;
        } else {
            m_decrypt_operations++;
            m_total_bytes_decrypted += bytes;
            m_decryption_cycles += cycles;
        }
    }

    void Ramulator::AESEncryptionPlugin::parseConfig() {
        const char* enable_env = std::getenv("AES_PLUGIN_ENABLE");
        if (enable_env && std::string(enable_env) == "1") {
            m_encryption_enabled = true;
        }
    }

    bool Ramulator::AESEncryptionPlugin::loadKeyFromConfig() {
        const char* key_env = std::getenv("AES_PLUGIN_KEY");
        if (key_env) {
            std::string key_str(key_env);
            if (key_str.length() == 64) { // 256-bit key in hex
                std::vector<uint8_t> key;
                key.reserve(32);

                for (size_t i = 0; i < key_str.length(); i += 2) {
                    std::string byte_str = key_str.substr(i, 2);
                    uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
                    key.push_back(byte);
                }

                return setEncryptionKey(key);
            }
        }

        const char* key_file_env = std::getenv("AES_PLUGIN_KEY_FILE");
        if (key_file_env) {
            AESConfig::EncryptionSettings settings;
            if (AESConfig::loadFromFile(key_file_env, settings)) {
                return setEncryptionKey(settings.key);
            }
        }

        return false;
    }

    double Ramulator::AESEncryptionPlugin::getAverageEncryptionCycles() const {
        return m_encrypt_operations > 0 ? static_cast<double>(m_encryption_cycles) / m_encrypt_operations : 0.0;
    }

    double Ramulator::AESEncryptionPlugin::getAverageDecryptionCycles() const {
        return m_decrypt_operations > 0 ? static_cast<double>(m_decryption_cycles) / m_decrypt_operations : 0.0;
    }

    void Ramulator::AESEncryptionPlugin::dumpStatistics() const {
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

    //Run this in a test binary or interactive mode before simulation
    // bool AESEncryptionPlugin::selfTest() {
    //     std::vector<uint8_t> test_key = {
    //         0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    //         0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    //     };
    //
    //     std::vector<uint8_t> test_plain = {
    //         0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
    //         0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    //     };
    //
    //     std::vector<uint8_t> expected_cipher = {
    //         0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
    //         0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
    //     };
    //
    //     AESEngine test_engine;
    //     if (!test_engine.initialize(test_key)) {
    //         return false;
    //     }
    //
    //     std::vector<uint8_t> encrypted, decrypted;
    //     if (!test_engine.encryptBlock(test_plain, encrypted)) {
    //         return false;
    //     }
    //
    //     if (encrypted != expected_cipher) {
    //         return false;
    //     }
    //
    //     if (!test_engine.decryptBlock(encrypted, decrypted)) {
    //         return false;
    //     }
    //
    //     return decrypted == test_plain;
    // }

}
#endif

