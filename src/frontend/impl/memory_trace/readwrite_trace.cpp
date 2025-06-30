#include <filesystem>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include "frontend/frontend.h"
#include "base/exception.h"

namespace Ramulator {

namespace fs = std::filesystem;

class ReadWriteTrace : public IFrontEnd, public Implementation {
  RAMULATOR_REGISTER_IMPLEMENTATION(IFrontEnd, ReadWriteTrace, "ReadWriteTrace", "Read/Write DRAM address vector trace.")

  private:
    struct Trace {
      bool is_write;
      AddrVec_t addr_vec;
    };
    std::vector<Trace> m_trace;

    size_t m_trace_length = 0;
    size_t m_curr_trace_idx = 0;

    Logger_t m_logger;

  public:
    void init() override {
      std::string trace_path_str = param<std::string>("path").desc("Path to the load store trace file.").required();
      m_clock_ratio = param<uint>("clock_ratio").required();

      m_logger = Logging::create_logger("ReadWriteTrace");
      m_logger->info("Loading trace file {} ...", trace_path_str);
      init_trace(trace_path_str);
      m_logger->info("Loaded {} lines.", m_trace.size());
    };

  void tick() override {
    const Trace& t = m_trace[m_curr_trace_idx];

    // Create a Request object explicitly to set source_id
    Request req(t.addr_vec, t.is_write ? Request::Type::Write : Request::Type::Read);
    req.source_id = -1;  // Unique identifier for trace requests

    m_memory_system->send(req);
    m_curr_trace_idx = (m_curr_trace_idx + 1) % m_trace_length;
  }

  private:
    void init_trace(const std::string& file_path_str) {
      fs::path trace_path(file_path_str);
      if (!fs::exists(trace_path)) {
        throw ConfigurationError("Trace {} does not exist!", file_path_str);
      }

      std::ifstream trace_file(trace_path);
      if (!trace_file.is_open()) {
        throw ConfigurationError("Trace {} cannot be opened!", file_path_str);
      }

      std::cout << std::unitbuf; // Disable buffering for debug output

      std::string line;
      size_t line_num = 0;
      while (std::getline(trace_file, line)) {
        ++line_num;
        if (line.empty() || std::all_of(line.begin(), line.end(), isspace)) {
          std::cout << "Line " << line_num << ": Skipping empty line" << std::endl;
          continue;
        }
        std::cout << "Line " << line_num << ": '" << line << "'" << std::endl;

        std::vector<std::string> tokens;
        std::cout << "Tokenizing line..." << std::endl;
        tokenize(tokens, line, " ");
        std::cout << "Tokens size: " << tokens.size() << std::endl;

        if (tokens.size() != 2) {
          throw ConfigurationError("Trace {} format invalid at line {}: expected 2 tokens, got {}!", file_path_str, line_num, tokens.size());
        }

        std::cout << "Token[0]: '" << tokens[0] << "', Token[1]: '" << tokens[1] << "'" << std::endl;

        bool is_write = false;
        if (tokens[0] == "R") {
          is_write = false;
        } else if (tokens[0] == "W") {
          is_write = true;
        } else {
          throw ConfigurationError("Trace {} format invalid at line {}: invalid operation '{}'", file_path_str, line_num, tokens[0]);
        }

        if (tokens[1].empty()) {
          throw ConfigurationError("Trace {} format invalid at line {}: empty address field!", file_path_str, line_num);
        }

        std::vector<std::string> addr_vec_tokens;
        std::cout << "Tokenizing address field: '" << tokens[1] << "'" << std::endl;
        tokenize(addr_vec_tokens, tokens[1], ",");
        std::cout << "Address tokens: ";
        for (const auto& t : addr_vec_tokens) {
          std::cout << "'" << t << "' ";
        }
        std::cout << std::endl;

        if (addr_vec_tokens.empty()) {
          throw ConfigurationError("Trace {} format invalid at line {}: no address tokens found!", file_path_str, line_num);
        }

        AddrVec_t addr_vec;
        for (const auto& token : addr_vec_tokens) {
          if (token.empty()) {
            throw ConfigurationError("Trace {} format invalid at line {}: empty address token!", file_path_str, line_num);
          }
          std::cout << "Parsing token: '" << token << "'" << std::endl;
          std::string clean_token = token;
          int base = 10;
          if (clean_token.size() >= 2 && clean_token.substr(0, 2) == "0x") {
            clean_token = clean_token.substr(2);
            base = 16;
          }
          try {
            addr_vec.push_back(std::stoll(clean_token, nullptr, base));
          } catch (const std::invalid_argument& e) {
            throw ConfigurationError("Trace {} format invalid at line {}: invalid address '{}'", file_path_str, line_num, token);
          } catch (const std::out_of_range& e) {
            throw ConfigurationError("Trace {} format invalid at line {}: address out of range '{}'", file_path_str, line_num, token);
          }
        }

        m_trace.push_back({is_write, addr_vec});
      }

      trace_file.close();
      m_trace_length = m_trace.size();
    };

    // TODO: FIXME
    bool is_finished() override {
      return true;
    };
};

} // namespace Ramulator