#ifndef RAMULATOR_AES_ENCRYPTION_PLUGIN_H
#define RAMULATOR_AES_ENCRYPTION_PLUGIN_H

#include "base/base.h"
#include "dram_controller/plugin.h"
#include "aes_engine.h"

namespace Ramulator {
    class AESEncryptionPlugin : public IControllerPlugin {
        RAMULATOR_REGISTER_IMPLEMENTATION(IControllerPlugin, AESEncryptionPlugin,"AESEncryption", "AES encryption/decryption plugin for memory controller");
    private:
        AESEngine m_aes_engine;

        bool m_encryption_enabled;
        bool m_decrypt_on_read;
        bool m_encrypt_on_write;

        uint64_t m_encrypt_operations;
        uint64_t m_decrypt_operations;
        uint64_t m_total_bytes_encrypted;
        uint64_t m_total_bytes_decrypted;

        //performance tracking
        uint64_t m_encryption_cycles;
        uint64_t m_decryption_cycles;

        void parseConfig();
        bool loadKeyFromConfig();
        bool encryptData(uint8_t* data, size_t size);
        bool decryptData(uint8_t* data, size_t size);

        bool isEncryptionRequired(const Request& req);
        bool isDecryptionRequired(const Request& req);
        void updateStats(bool is_encrypt, size_t bytes, uint64_t cycles);

    public:
        AESEncryptionPlugin() = default;
        ~AESEncryptionPlugin() = default;

        void init() override;
        void setup(IFrontEnd* frontend, IMemorySystem* memory_system) override;
        void update(bool request_found, ReqBuffer::iterator& req_it) override;
        void finalize() override;

        bool setEncryptionKey(const std::vector<uint8_t>& key);
        bool setEncryptionKey(const uint8_t* key, int key_size);
        void enableEncryption(bool enable = true);
        void enableDecryptionOnRead(bool enable = true);
        void enableEncryptionOnWrite(bool enable = true);

        uint64_t getEncryptionOperations() const {
            return m_encrypt_operations;
        };

        uint64_t getDecryptionOperations() const {
            return m_decrypt_operations;
        }

        uint64_t getTotalBytesEncrypted() const {
            return m_total_bytes_encrypted;
        }

        uint64_t getTotalBytesDecrypted() const {
            return m_total_bytes_decrypted;
        }

        double getAverageEncryptionCycles() const {
            return m_encryption_cycles;
        }

        double getAverageDecryptionCycles() const {
            return m_decryption_cycles;
        }

        void dumpStatistics() const;
        bool selfTest();
    };
}
#endif