#ifndef ARGON2_NODE_H
#define ARGON2_NODE_H

#include <memory>
#include <nan.h>

namespace NodeArgon2 {

class HashWorker final: public Nan::AsyncWorker {
public:
    explicit HashWorker(std::string&& plain, std::string&& salt,
            std::tuple<uint32_t, uint32_t, uint32_t, argon2_type>&& params);

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
    std::unique_ptr<char[]> output{nullptr};
};

class VerifyWorker final: public Nan::AsyncWorker {
public:
    explicit VerifyWorker(std::string&& hash, std::string&& plain,
            argon2_type type);

    void Execute() override;

    void HandleOKCallback() override;

    void HandleErrorCallback() override;

private:
    std::string hash;
    std::string plain;
    argon2_type type;
    bool output{false};
};

NAN_METHOD(Hash);

NAN_METHOD(Verify);

}

#endif /* ARGON2_NODE_H */
