#ifndef RAMULATOR_AES_PLUGIN_H
#define RAMULATOR_AES_PLUGIN_H

#pragma once
#include <memory>
#include "aes_encryption_plugin.h"

namespace Ramulator {
    class IControllerPlugin;
    std::unique_ptr<IControllerPlugin> create_aes_engine_plugin();
}
#endif