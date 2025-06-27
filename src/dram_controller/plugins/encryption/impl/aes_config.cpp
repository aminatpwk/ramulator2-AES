#include "../aes_config.h"
#include <fstream>
#include <iostream>
#include <memory>
#include <random>
#include "dram_controller/plugins/encryption/impl/aes_encryption_plugin.cpp"
#include "dram_controller/plugin.h"
#include "dram_controller/plugins/encryption/aes_engine.h"
#include "base/factory.h"
namespace Ramulator {

    bool AESConfig::loadFromFile(const std::string& config_file, EncryptionSettings& settings) {
        std::ifstream file(config_file);
        if (!file.is_open()) {
            std::cerr << "Failed to open: " << config_file << std::endl;
            return false;
        }

        std::string line;
        while (std::getline(file, line)) {
            line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());

            if (line.find("key=") == 0) {
                std::string key_hex = line.substr(4);
                if (key_hex.empty()) {
                    std::cerr << "Empty key in config" << std::endl;
                    continue;
                }

                try {
                    settings.key.clear();
                    for (size_t i = 0; i < key_hex.length(); i += 2) {
                        std::string byte_str = key_hex.substr(i, 2);
                        uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
                        settings.key.push_back(byte);
                    }
                } catch (...) {
                    std::cerr << "Invalid hex in key: " << key_hex << std::endl;
                    return false;
                }
            }
            else if (line.find("encrypt_write=") == 0) {
                settings.encrypt_writes = (line.substr(14) == "true");
            }
            else if (line.find("decrypt_read=") == 0) {
                settings.decrypt_reads = (line.substr(13) == "true");
            }
        }

        if (settings.key.empty()) {
            std::cerr << "No valid key found in config" << std::endl;
            return false;
        }

        return true;
    }

    bool AESConfig::validateKey(const std::vector<uint8_t>& key) {
        return key.size() == AES_KEY_SIZE_128 || key.size() == AES_KEY_SIZE_192 || key.size() == AES_KEY_SIZE_256;
    }

    /**
     * Generates a secure, random, byte-level key of specified length;
     * Ensures no reused or predictable key content;
     * @param key_size
     * @return
     */
    std::vector<uint8_t> AESConfig::generateRandomKey(int key_size) {
        std::vector<uint8_t> key(key_size);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);

        for (int i = 0; i < key_size; i++) {
            key[i] = static_cast<uint8_t>(dis(gen));
        }

        return key;
    }

    std::unique_ptr<IControllerPlugin> create_aes_encryption_plugin(const YAML::Node& config, Implementation* parent) {
        using namespace Ramulator;
        Implementation* impl = Factory::create_implementation("ControllerPlugin", "AESEncryption", config, parent);
        auto* plugin = dynamic_cast<IControllerPlugin*>(impl);

        if (!plugin) {
            throw std::runtime_error("Failed to create AESEncryptionPlugin");
        }

        return std::unique_ptr<IControllerPlugin>(plugin);
    }

}
