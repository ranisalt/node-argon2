#include <nan.h>
#include <node.h>

#include <cstring>
#include <string>

#include "../argon2/src/argon2.h"

namespace {

using uint = unsigned int;

const auto ENCODED_LEN = 108u;
const auto HASH_LEN = 32u;
const auto SALT_LEN = 16u;

class EncryptAsyncWorker : public Nan::AsyncWorker {
public:
    EncryptAsyncWorker(Nan::Callback* callback, const std::string& plain,
            const std::string& salt, uint time_cost, uint memory_cost,
            uint parallelism, argon2_type type);

    void Execute();

    void HandleOKCallback();

private:
    std::string plain;
    std::string salt;
    uint time_cost;
    uint memory_cost;
    uint parallelism;
    std::string error;
    Argon2_type type;
    std::string output;
};

EncryptAsyncWorker::EncryptAsyncWorker(Nan::Callback* callback,
        const std::string& plain, const std::string& salt, uint time_cost,
        uint memory_cost, uint parallelism, Argon2_type type):
    Nan::AsyncWorker(callback), plain{plain}, salt{salt}, time_cost{time_cost},
    memory_cost{memory_cost}, parallelism{parallelism}, error{}, type{type},
    output{}
{ }

void EncryptAsyncWorker::Execute()
{
    char encoded[ENCODED_LEN];

    auto result = argon2_hash(time_cost, memory_cost, parallelism,
            plain.c_str(), plain.size(), salt.c_str(), salt.size(), nullptr,
            HASH_LEN, encoded, ENCODED_LEN, type);
    if (result != ARGON2_OK) {
        return; // LCOV_EXCL_LINE
    }

    output = std::string{encoded};
}

void EncryptAsyncWorker::HandleOKCallback()
{
    using v8::Local;
    using v8::Value;

    Nan::HandleScope scope;

    Local <Value> argv[2];
    argv[0] = Nan::Undefined();
    argv[1] = Nan::Encode(output.c_str(), output.size(), Nan::BINARY);

    callback->Call(2, argv);
}

NAN_METHOD(Encrypt) {
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

    auto worker = new EncryptAsyncWorker(new Nan::Callback(callback), *plain,
            salt, time_cost, 1 << memory_cost, parallelism, type);

    Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(EncryptSync) {
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
        /* LCOV_EXCL_START */
        info.GetReturnValue().Set(Nan::Undefined());
        return;
        /* LCOV_EXCL_STOP */
    }

    info.GetReturnValue().Set(Nan::Encode(encoded, std::strlen(encoded),
            Nan::BINARY));
}

class VerifyAsyncWorker : public Nan::AsyncWorker {
public:
    VerifyAsyncWorker(Nan::Callback* callback, const std::string& encrypted,
            const std::string& plain, argon2_type type);

    void Execute();

private:
    std::string encrypted;
    std::string plain;
    std::string error;
    argon2_type type;
    bool output;
};

VerifyAsyncWorker::VerifyAsyncWorker(Nan::Callback* callback,
        const std::string& encrypted, const std::string& plain,
        argon2_type type):
    Nan::AsyncWorker(callback), encrypted{encrypted}, plain{plain}, error{},
    type{type}, output{}
{ }

void VerifyAsyncWorker::Execute()
{
    auto result = argon2_verify(encrypted.c_str(), plain.c_str(), plain.size(),
            type);

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

    Nan::Utf8String encrypted{info[0]->ToString()};
    Nan::Utf8String plain{info[1]->ToString()};
    argon2_type type = info[2]->BooleanValue() ? Argon2_d : Argon2_i;
    Local<Function> callback = Local<Function>::Cast(info[3]);

    auto worker = new VerifyAsyncWorker(new Nan::Callback(callback),
            *encrypted, *plain, type);

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

    Nan::Utf8String encrypted{info[0]->ToString()};
    Nan::Utf8String plain{info[1]->ToString()};
    argon2_type type = info[2]->BooleanValue() ? Argon2_d : Argon2_i;

    auto result = argon2_verify(*encrypted, *plain, strlen(*plain), type);

    info.GetReturnValue().Set(result == ARGON2_OK ? Nan::True() : Nan::False());
}

}

NAN_MODULE_INIT(init) {
    Nan::Export(target, "encrypt", Encrypt);
    Nan::Export(target, "encryptSync", EncryptSync);
    Nan::Export(target, "verify", Verify);
    Nan::Export(target, "verifySync", VerifySync);
};

NODE_MODULE(argon2_lib, init);
