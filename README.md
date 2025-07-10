# AES Encryption Plugin for Ramulator 2.0

## Introduction

The AES Encryption Plugin is an extension to [Ramulator 2.0](https://github.com/CMU-SAFARI/ramulator2), a modern, modular, and extensible cycle-accurate DRAM simulator. This plugin integrates the Advanced Encryption Standard (AES) into the memory controller of Ramulator 2.0 to enhance the security of DRAM-based memory systems against hardware attacks such as Rowhammer and Cold Boot. The plugin includes a custom scheduler designed to optimize performance by reducing encryption overhead, achieving a significant reduction in encryption cycles (~40% optimisation).

The plugin leverages Ramulator 2.0’s modular architecture, extending its memory controller interface to incorporate AES encryption and a performance-optimized scheduler. It is implemented in C++ and tested on Ubuntu/WSL using the Ramulator 2.0 simulation environment.


## Features

- **AES Encryption Integration**: Implements AES encryption at the memory controller level to protect data against hardware-based attacks like Rowhammer and Cold Boot.
- **Custom Scheduler**: Includes a performance-optimized scheduler that reduces encryption overhead by ~40% (from ~750 to ~450 cycles per operation).
- **Modular Design**: Built using Ramulator 2.0’s extensible interface and implementation framework, allowing seamless integration and easy modification.
- **YAML Configuration**: Configurable via a human-readable YAML file (`example_config_aes.yaml`) for specifying encryption parameters and scheduler settings.
- **Tested Workloads**: Evaluated using memory traces (e.g., `aestest.trace`) to demonstrate performance improvements in simulated environments.

## Dependencies

The AES Encryption Plugin requires the following dependencies, which are automatically handled by Ramulator 2.0’s build system (CMake):

- **Ramulator 2.0**: The base simulator, available at [CMU-SAFARI/ramulator2](https://github.com/CMU-SAFARI/ramulator2).
- **C++20 Compiler**: Tested with `g++-12` and `clang++-15`.
- **External Libraries**: `argparse`, `spdlog`, `yaml-cpp` (automatically downloaded by CMake).

## Getting Started

### Prerequisites

Ensure you have a C++20-capable compiler (`g++-12` or `clang++-15`) and CMake installed. The plugin is designed to work on Ubuntu/WSL or compatible Linux environments.

### Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/aminatpwk/ramulator2-AES
   cd ramulator2-AES
   ```

3. **Build Ramulator 2.0 with the Plugin**:
   ```bash
   mkdir build
   cd build
   cmake ..
   make -j
   cp ./ramulator2 ../ramulator2
   cd ..
   ```

   This will produce the `ramulator2` executable and the `libramulator.so` dynamic library, both including the AES Encryption Plugin.

### Running the Plugin

The plugin can be used in standalone mode with Ramulator 2.0’s memory-trace parser frontend. To run a simulation with the AES Encryption Plugin:

1. **Prepare the Configuration File**:
   - Use the provided `example_config_aes.yaml` file to configure the plugin. A sample configuration snippet:
     ```yaml
     MemorySystem:
       DRAM:
         standard: DDR4
         timing:
           nRCD: 15
       Controller:
         impl: AESEncryption
         scheduler: FRFCFS
     ```

2. **Run the Simulation**:
   ```bash
   ./ramulator2 -f ./example_config_aes.yaml
   ```

### Directory Structure

```
ramulator2/
├── ext/                     # External libraries (argparse, spdlog, yaml-cpp)
├── src/
│   ├── dram_controller/
│   │   ├── plugins/
│   │   │   ├── aes_encryption.cpp   # AES encryption implementation
│   │   │   ├── aes_scheduler.cpp    # Custom scheduler implementation
│   │   ├── aes_encryption.h        # AES encryption interface
│   │   ├── CMakeLists.txt           # Component-level CMake configuration
│   ├── ...
├── example_config_aes.yaml          # Sample configuration file
├── aestest.trace                    # Sample memory trace for testing
├── CMakeLists.txt                   # Project-level CMake configuration
```

## Extending the Plugin

The AES Encryption Plugin follows Ramulator 2.0’s modular design, using interfaces and implementations for extensibility.

### Adding a New Implementation

To add a new encryption algorithm or scheduler:

1. Create a new `.cpp` file in `src/dram_controller/plugins/` (e.g., `new_encryption.cpp`).
2. Define the implementation class, inheriting from the `AESEncryption` interface and `Implementation` base class:
   ```cpp
   #include "aes_encryption.h"
   #include "base/base.h"

   namespace Ramulator {
   class NewEncryption : public IAESEncryptionPlugin, public Implementation {
     RAMULATOR_REGISTER_IMPLEMENTATION(IAESEncryptionPlugin, NewEncryption, "NewEncryption", "A new encryption implementation.")
   public:
     void encrypt_data(uint8_t* data, size_t size) override {
       // Implement new encryption logic
     }
   };
   }  // namespace Ramulator
   ```
3. Update `src/dram_controller/CMakeLists.txt` to include the new file:
   ```cmake
   target_sources(ramulator PRIVATE plugins/new_encryption.cpp)
   ```
4. Specify the new implementation in the YAML configuration:
   ```yaml
   MemorySystem:
     Controller:
       impl: NewEncryption
   ```

### Adding a New Interface

To add a new component (e.g., a new security interface):

1. Create a new directory under `src/` (e.g., `src/security_component/`).
2. Define the interface in a `.h` file (e.g., `security_interface.h`):
   ```cpp
   #include "base/base.h"

   namespace Ramulator {
   class SecurityIfce {
     RAMULATOR_REGISTER_INTERFACE(SecurityIfce, "SecurityInterface", "Interface for security components.")
   public:
     virtual void secure_data(uint8_t* data, size_t size) = 0;
   };
   }  // namespace Ramulator
   ```
3. Add the implementation in `src/security_component/impl/` and update the corresponding `CMakeLists.txt`.
4. Register the new component in `src/CMakeLists.txt`:
   ```cmake
   add_subdirectory(security_component)
   ```

## Verification

The plugin has been verified using Ramulator 2.0’s memory-trace parser with the provided `aestest.trace` file. The implementation achieves a ~40% reduction in encryption cycles (from ~750 to ~450 cycles per operation) with the custom scheduler.

To verify the plugin:

1. Run the simulation with the provided trace:
   ```bash
   ./ramulator2 -f ./example_config_aes.yaml
   ```
2. Compare the output statistics (e.g., encryption cycles, latency) with the baseline configuration to confirm performance improvements.

## Limitations

- The plugin is currently tested in a simulated environment (Ramulator 2.0) and not on real hardware.
- Performance may vary depending on workload characteristics (e.g., memory-intensive applications).
- The plugin assumes AES as the primary encryption algorithm; alternative algorithms require additional implementations.


## Acknowledgments

This plugin is developed as part of the thesis work titled *"Implementing Encryption as an Architectural Approach to Securing Memory Systems"* by Amina Sokoli, under the supervision of Dr. Ina Papadhopulli at the Polytechnic University of Tirana. We thank the Ramulator 2.0 team for providing an extensible and robust simulation framework.
