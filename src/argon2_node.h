#ifndef ARGON2_NODE_H
#define ARGON2_NODE_H

#include <nan.h>

namespace {

const auto ENCODED_LEN = 108u;
const auto HASH_LEN = 32u;

class HashAsyncWorker final : public Nan::AsyncWorker {
public:
    HashAsyncWorker(const std::string& plain, const std::string& salt,
            uint32_t time_cost, uint32_t memory_cost, uint32_t parallelism,
            Argon2_type type);

    void Execute() override;

    void HandleOKCallback() override;

    void HandleErrorCallback() override;

private:
    std::string plain;
    std::string salt;
    uint32_t time_cost;
    uint32_t memory_cost;
    uint32_t parallelism;
    Argon2_type type;
    std::string output;
};

class VerifyAsyncWorker final : public Nan::AsyncWorker {
public:
    VerifyAsyncWorker(const std::string& hash, const std::string& plain,
            argon2_type type);

    void Execute() override;

    void HandleOKCallback() override;

    void HandleErrorCallback() override;

private:
    std::string hash;
    std::string plain;
    argon2_type type;
};

NAN_METHOD(Hash);

NAN_METHOD(HashSync);

NAN_METHOD(Verify);

NAN_METHOD(VerifySync);

}

#endif /* ARGON2_NODE_H */