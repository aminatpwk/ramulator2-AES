#ifndef RAMULATOR_AES_PLUGIN_H
#define RAMULATOR_AES_PLUGIN_H

#include "dram_controller/plugins/encryption/aes_engine.h"
#include "dram_controller/plugins/encryption/aes_encryption_plugin.h"
#include "dram_controller/plugins/encryption/aes_config.h"

namespace Ramulator {
    std::unique_ptr<IControllerPlugin> create_aes_engine_plugin();
}
#endif