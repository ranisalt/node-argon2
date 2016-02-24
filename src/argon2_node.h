#ifndef ARGON2_NODE_H
#define ARGON2_NODE_H

#include <memory>
#include <nan.h>

namespace NodeArgon2 {

class HashAsyncWorker final: public Nan::AsyncWorker {
public:
    HashAsyncWorker(std::string&& plain, std::string&& salt, uint32_t time_cost,
            uint32_t memory_cost, uint32_t parallelism, argon2_type type);

    void Execute() override;

    void HandleOKCallback() override;

    void HandleErrorCallback() override;

private:
    std::string plain;
    std::string salt;
    uint32_t time_cost;
    uint32_t memory_cost;
    uint32_t parallelism;
    argon2_type type;
    std::unique_ptr<char[]> output;
};

class VerifyAsyncWorker final: public Nan::AsyncWorker {
public:
    VerifyAsyncWorker(std::string&& hash, std::string&& plain, argon2_type type);

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
