#ifndef ARGON2_NODE_H
#define ARGON2_NODE_H

#include <memory>
#include <nan.h>

namespace NodeArgon2 {

struct Options {
    // TODO: remove ctors and initializers when GCC<5 stops shipping on Ubuntu
    Options() = default;
    Options(Options&&) = default;

    std::string salt;

    uint32_t hash_length = {};
    uint32_t time_cost = {};
    uint32_t memory_cost = {};
    uint32_t parallelism = {};

    argon2_type type = {};
};

class HashWorker final: public Nan::AsyncWorker {
public:
    HashWorker(std::string plain, Options options);

    void Execute() override;

    void HandleOKCallback() override;

    void HandleErrorCallback() override;

private:
    std::string plain;
    Options options;

    std::string output;
};

NAN_METHOD(Hash);

NAN_METHOD(Verify);

}

#endif /* ARGON2_NODE_H */
