#ifndef RAMULATOR_AES_ENGINE_H
#define RAMULATOR_AES_ENGINE_H

#pragma once
#include <vector>
#include <cstdint>
#include "base/type.h"

namespace Ramulator {
    constexpr int AES_BLOCK_SIZE = 16;
    constexpr int AES_KEY_SIZE_128 = 16;
    constexpr int AES_KEY_SIZE_192 = 24;
    constexpr int AES_KEY_SIZE_256 = 32;

    struct AESParameters {
        int Nk;
        int Nr;
        int Nb = 4;
    };

    class AESEngine {
    private:
        static const uint8_t S_BOX[256];
        static const uint8_t INV_S_BOX[256];
        static const uint8_t RCON[11];

        AESParameters m_params;
        std::vector<uint32_t> m_expanded_keys;
        bool m_initialized;

        void subBytes(uint8_t state[4][4]);
        void shiftRow(uint8_t state[4][4]);
        void invSubBytes(uint8_t state[4][4]);
        void invShiftRow(uint8_t state[4][4]);
        void mixColumn(uint8_t state[4][4]);
        void invMixColumn(uint8_t state[4][4]);
        void addRoundKey(uint8_t state[4][4], const uint32_t* round_key);

        uint32_t subWord(uint32_t word);
        uint32_t rotateWord(uint32_t word);
        void keyExpansion(const uint8_t* key, int key_size);

        uint8_t gf_mul(uint8_t a, uint8_t b);

        void bytesToState(const uint8_t* input, uint8_t state[4][4]);
        void stateToBytes(const uint8_t state[4][4], uint8_t* output);
        uint32_t bytesToWord(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3);

    public:
        AESEngine();
        ~AESEngine() = default;

        bool initialize(const uint8_t* key, int key_size);
        bool initialize(const std::vector<uint8_t>& key);

        bool encrypt(const uint8_t* input, uint8_t* output);
        bool decrypt(const uint8_t* input, uint8_t* output);

        bool encryptBlock(const std::vector<uint8_t>& input, std::vector<uint8_t>& output);
        bool decryptBlock(const std::vector<uint8_t>& input, std::vector<uint8_t>& output);

        bool isInitialized() const {
            return m_initialized;
        }

        int getKeySize() const;

        int getRounds() const {
            return m_params.Nr;
        }

        void handleWrite(Addr_t addr);
        void handleRead(Addr_t addr);

    };
}
#endif