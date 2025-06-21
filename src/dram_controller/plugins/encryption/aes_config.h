#ifndef RAMULATOR_AES_CONFIG_H
#define RAMULATOR_AES_CONFIG_H

#pragma once
#include <vector>
#include <string>

namespace Ramulator {
    class AESConfig {
    public:
           struct EncryptionSettings{
                std::vector<uint8_t> key;
                bool encrypt_writes = true;
                bool decrypt_reads = true;
                bool enable_stats = true;
                std::string key_file_path;
           };

           static bool loadFromFile(const std::string& config_file, EncryptionSettings& encryption_settings);
           static bool validateKey(const std::vector<uint8_t>& key);
           static std::vector<uint8_t> generateRandomKey(int key_size = AES_KEY_SIZE_256);
    };
}
#endif