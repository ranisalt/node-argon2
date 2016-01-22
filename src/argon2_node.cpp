#include <nan.h>
#include <node.h>

#include <cstdint>
#include <cstring>
#include <string>

#include "../argon2/src/argon2.h"

namespace {

using std::uint32_t;

const auto ENCODED_LEN = 108u;
const auto HASH_LEN = 32u;
const auto SALT_LEN = 16u;

class HashAsyncWorker : public Nan::AsyncWorker {
public:
    HashAsyncWorker(Nan::Callback* callback, const std::string& plain,
            const std::string& salt, uint32_t time_cost, uint32_t memory_cost,
            uint32_t parallelism, argon2_type type);

    void Execute();

    void HandleOKCallback();

private:
    std::string plain;
    std::string salt;
    uint32_t time_cost;
    uint32_t memory_cost;
    uint32_t parallelism;
    std::string error;
    Argon2_type type;
    std::string output;
};

HashAsyncWorker::HashAsyncWorker(Nan::Callback* callback,
        const std::string& plain, const std::string& salt, uint32_t time_cost,
        uint32_t memory_cost, uint32_t parallelism, Argon2_type type):
    Nan::AsyncWorker(callback), plain{plain}, salt{salt}, time_cost{time_cost},
    memory_cost{memory_cost}, parallelism{parallelism}, error{}, type{type},
    output{}
{ }

void HashAsyncWorker::Execute()
{
    char encoded[ENCODED_LEN];

    auto result = argon2_hash(time_cost, memory_cost, parallelism,
            plain.c_str(), plain.size(), salt.c_str(), salt.size(), nullptr,
            HASH_LEN, encoded, ENCODED_LEN, type);
    if (result != ARGON2_OK) {
        SetErrorMessage(error_message(result));
        return;
    }

    output = std::string{encoded};
}

void HashAsyncWorker::HandleOKCallback()
{
    using v8::Local;
    using v8::Value;

    Nan::HandleScope scope;

    Local <Value> argv[] = {
        Nan::Undefined(), Nan::Encode(output.c_str(), output.size(), Nan::BINARY)
    };

    callback->Call(2, argv);
}

NAN_METHOD(Hash) {
    using v8::Function;
    using v8::Local;

    Nan::HandleScope scope;

    if (info.Length() < 7) {
        /* LCOV_EXCL_START */
        Nan::ThrowTypeError("7 arguments expected");
        return;
        /* LCOV_EXCL_STOP */
    }

    Nan::Utf8String plain{info[0]->ToString()};
    Nan::Utf8String raw_salt{info[1]->ToString()};
    auto time_cost = info[2]->Uint32Value();
    auto memory_cost = info[3]->Uint32Value();
    auto parallelism = info[4]->Uint32Value();
    argon2_type type = info[5]->BooleanValue() ? Argon2_d : Argon2_i;
    Local<Function> callback = Local<Function>::Cast(info[6]);

    auto salt = std::string{*raw_salt};
    salt.resize(SALT_LEN, 0x0);

    auto worker = new HashAsyncWorker(new Nan::Callback(callback), *plain, salt,
            time_cost, 1 << memory_cost, parallelism, type);

    Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(HashSync) {
    using std::strlen;

    Nan::HandleScope scope;

    if (info.Length() < 6) {
        /* LCOV_EXCL_START */
        Nan::ThrowTypeError("6 arguments expected");
        info.GetReturnValue().Set(Nan::Undefined());
        return;
        /* LCOV_EXCL_STOP */
    }

    Nan::Utf8String plain{info[0]->ToString()};
    Nan::Utf8String raw_salt{info[1]->ToString()};
    auto time_cost = info[2]->Uint32Value();
    auto memory_cost = info[3]->Uint32Value();
    auto parallelism = info[4]->Uint32Value();
    argon2_type type = info[5]->BooleanValue() ? Argon2_d : Argon2_i;

    char encoded[ENCODED_LEN];

    auto salt = std::string{*raw_salt};
    salt.resize(SALT_LEN, 0x0);

    auto result = argon2_hash(time_cost, 1 << memory_cost, parallelism, *plain,
            strlen(*plain), salt.c_str(), salt.size(), nullptr, HASH_LEN,
            encoded, ENCODED_LEN, type);

    if (result != ARGON2_OK) {
        Nan::ThrowError(error_message(result));
        info.GetReturnValue().Set(Nan::Undefined());
        return;
    }

    info.GetReturnValue().Set(Nan::Encode(encoded, strlen(encoded),
            Nan::BINARY));
}

class VerifyAsyncWorker : public Nan::AsyncWorker {
public:
    VerifyAsyncWorker(Nan::Callback* callback, const std::string& hash,
            const std::string& plain, argon2_type type);

    void Execute();

private:
    std::string hash;
    std::string plain;
    std::string error;
    argon2_type type;
    bool output;
};

VerifyAsyncWorker::VerifyAsyncWorker(Nan::Callback* callback,
        const std::string& hash, const std::string& plain, argon2_type type):
    Nan::AsyncWorker(callback), hash{hash}, plain{plain}, error{}, type{type},
    output{}
{ }

void VerifyAsyncWorker::Execute()
{
    auto result = argon2_verify(hash.c_str(), plain.c_str(), plain.size(), type);

    if (result != ARGON2_OK) {
        SetErrorMessage("The password did not match.");
    }
}

NAN_METHOD(Verify) {
    using v8::Function;
    using v8::Local;

    Nan::HandleScope scope;

    if (info.Length() < 3) {
        /* LCOV_EXCL_START */
        Nan::ThrowTypeError("3 arguments expected");
        return;
        /* LCOV_EXCL_STOP */
    }

    Nan::Utf8String hash{info[0]->ToString()};
    Nan::Utf8String plain{info[1]->ToString()};
    argon2_type type = info[2]->BooleanValue() ? Argon2_d : Argon2_i;
    Local<Function> callback = Local<Function>::Cast(info[3]);

    auto worker = new VerifyAsyncWorker(new Nan::Callback(callback), *hash,
            *plain, type);

    Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(VerifySync) {
    using std::strlen;

    Nan::HandleScope scope;

    if (info.Length() < 2) {
        /* LCOV_EXCL_START */
        Nan::ThrowTypeError("2 arguments expected");
        return;
        /* LCOV_EXCL_STOP */
    }

    Nan::Utf8String hash{info[0]->ToString()};
    Nan::Utf8String plain{info[1]->ToString()};
    argon2_type type = info[2]->BooleanValue() ? Argon2_d : Argon2_i;

    auto result = argon2_verify(*hash, *plain, strlen(*plain), type);

    info.GetReturnValue().Set(result == ARGON2_OK);
}

}

NAN_MODULE_INIT(init) {
    Nan::Export(target, "hash", Hash);
    Nan::Export(target, "hashSync", HashSync);
    Nan::Export(target, "verify", Verify);
    Nan::Export(target, "verifySync", VerifySync);
};

NODE_MODULE(argon2_lib, init);
