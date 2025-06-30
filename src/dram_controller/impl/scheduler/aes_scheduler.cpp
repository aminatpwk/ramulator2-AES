#include <vector>

#include "../../controller.h"
#include "../../scheduler.h"
#include "../../../base/base.h"

namespace Ramulator {
    struct ReqBuffer;
    class IDRAM;

    class AESScheduler : public IScheduler, public Implementation {
        RAMULATOR_REGISTER_IMPLEMENTATION(IScheduler, AESScheduler, "EncryptionScheduler", "Encryption Scheduler")
    private:
        IDRAM* m_dram;

    public:
        void init() override {};

        void setup(IFrontEnd* frontend, IMemorySystem* memory_system) override {
          m_dram = cast_parent<IDRAMController>()->m_dram;
        };

        ReqBuffer::iterator compare(ReqBuffer::iterator req1, ReqBuffer::iterator req2) override {
            bool ready1 = m_dram->check_ready(req1->command, req1->addr_vec);
            bool ready2 = m_dram->check_ready(req2->command, req2->addr_vec);
            bool is_read1 = (req1->type_id == Request::Type::Read);
            bool is_read2 = (req2->type_id == Request::Type::Read);

            if (is_read1 != is_read2) {
                return is_read1 ? req1 : req2;
            }

            if (ready1 ^ ready2) {
                return ready1 ? req1 : req2;
            }

            return (req1->arrive <= req2->arrive) ? req1 : req2;
        };

        ReqBuffer::iterator get_best_request(ReqBuffer& buffer) override {
            if (buffer.size() == 0) {
                return buffer.end();
            }

            for (auto& req : buffer) {
                req.command = m_dram->get_preq_command(req.final_command, req.addr_vec);
            }

            auto candidate = buffer.begin();
            for (auto next = std::next(buffer.begin(), 1); next != buffer.end(); next++) {
                candidate = compare(candidate, next);
            }
            return candidate;
        }
    };
}