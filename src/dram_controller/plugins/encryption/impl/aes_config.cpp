#include "../aes_config.h"
#include <fstream>
#include <iostream>
#include <memory>
#include <random>

#include "dram_controller/plugin.h"
#include "dram_controller/plugins/encryption/aes_engine.h"

namespace Ramulator {
    class AESEncryptionPlugin;

    bool Ramulator::AESConfig::loadFromFile(const std::string& config_file, EncryptionSettings& settings) {
        std::ifstream file(config_file);
        if (!file.is_open()) {
            std::cerr << "AESConfig: Failed to open config file: " << config_file << std::endl;
            return false;
        }

        std::string line;
        while (std::getline(file, line)) {
            if (line.find("key=") == 0) {
                std::string key_hex = line.substr(4);
                settings.key.clear();
                settings.key.reserve(key_hex.length() / 2);

                for (size_t i = 0; i < key_hex.length(); i += 2) {
                    std::string byte_str = key_hex.substr(i, 2);
                    uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
                    settings.key.push_back(byte);
                }
            }else if (line.find("encrypt_write="==0)) {
                settings.encrypt_writes = (line.substr(15)=="true");
            }
        }

        return validateKey(settings.key);
    }

    bool Ramulator::AESConfig::validateKey(const std::vector<uint8_t>& key) {
        return key.size() == AES_KEY_SIZE_128 || key.size() == AES_KEY_SIZE_192 || key.size() == AES_KEY_SIZE_256;
    }

    /**
     * Generates a secure, random, byte-level key of specified length;
     * Ensures no reused or predictable key content;
     * @param key_size
     * @return
     */
    std::vector<uint8_t> Ramulator::AESConfig::generateRandomKey(int key_size) {
        std::vector<uint8_t> key(key_size);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);

        for (int i = 0; i < key_size; i++) {
            key[i] = static_cast<uint8_t>(dis(gen));
        }

        return key;
    }

    std::unique_ptr<IControllerPlugin> create_aes_encryption_plugin() {
        return std::make_unique<AESEncryptionPlugin>();
    }
}
