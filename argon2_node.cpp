#include <nan.h>
#include <node.h>

#include <cstring>
#include <string>

#include "argon2/src/argon2.h"

namespace {

const auto ENCODED_LEN = 108u;
const auto HASH_LEN = 32u;
const auto SALT_LEN = 16u;

class EncryptAsyncWorker : public Nan::AsyncWorker {
public:
    EncryptAsyncWorker(Nan::Callback* callback,
        const std::string& plain, const std::string& salt);

    void Execute();

    void HandleOKCallback();

private:
    std::string plain;
    std::string salt;
    std::string error;
    std::string output;
};

EncryptAsyncWorker::EncryptAsyncWorker(Nan::Callback* callback,
    const std::string& plain, const std::string& salt) :
    Nan::AsyncWorker(callback), plain{plain},
    salt{salt}, error{}, output{}
{
    if (salt.size() < SALT_LEN) {
        this->salt.resize(SALT_LEN, 0x0);
    }
}

void EncryptAsyncWorker::Execute()
{
    char encoded[ENCODED_LEN];

    auto result = argon2i_hash_encoded(3, 4096, 1, plain.c_str(), plain.size(),
        salt.c_str(), salt.size(), HASH_LEN, encoded, ENCODED_LEN);
    if (result != ARGON2_OK) {
        return;
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

    if (info.Length() < 3) {
        Nan::ThrowTypeError("3 arguments expected");
        return;
    }

    Nan::Utf8String plain{info[0]->ToString()};
    Nan::Utf8String salt{info[1]->ToString()};
    Local<Function> callback = Local<Function>::Cast(info[2]);

    auto worker = new EncryptAsyncWorker(new Nan::Callback(callback), *plain, *salt);

    Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(EncryptSync) {
    Nan::HandleScope scope;

    if (info.Length() < 2) {
        Nan::ThrowTypeError("2 arguments expected");
        info.GetReturnValue().Set(Nan::Undefined());
        return;
    }

    Nan::Utf8String plain{info[0]->ToString()};
    Nan::Utf8String raw_salt{info[1]->ToString()};

    char encoded[ENCODED_LEN];

    auto salt = std::string{*raw_salt};
    salt.resize(SALT_LEN, 0x0);

    auto result = argon2i_hash_encoded(3, 4096, 1, *plain, strlen(*plain),
            salt.c_str(), salt.size(), HASH_LEN, encoded, ENCODED_LEN);
    if (result != ARGON2_OK) {
        info.GetReturnValue().Set(Nan::Undefined());
        return;
    }

    info.GetReturnValue().Set(Nan::Encode(encoded, std::strlen(encoded),
                Nan::BINARY));
}

class VerifyAsyncWorker : public Nan::AsyncWorker {
public:
    VerifyAsyncWorker(Nan::Callback* callback,
        const std::string& encrypted, const std::string& plain);

    void Execute();

private:
    std::string encrypted;
    std::string plain;
    std::string error;
    bool output;
};

VerifyAsyncWorker::VerifyAsyncWorker(Nan::Callback* callback,
    const std::string& encrypted, const std::string& plain) :
    Nan::AsyncWorker(callback), encrypted{encrypted}, plain{plain},
    error{}, output{}
{ }

void VerifyAsyncWorker::Execute()
{
    auto result = argon2i_verify(encrypted.c_str(), plain.c_str(),
        plain.size());

    if (result != ARGON2_OK) {
        SetErrorMessage("The password did not match.");
    }
}

NAN_METHOD(Verify) {
    using v8::Function;
    using v8::Local;

    Nan::HandleScope scope;

    if (info.Length() < 3) {
        Nan::ThrowTypeError("3 arguments expected");
        return;
    }

    Nan::Utf8String encrypted{ info[0]->ToString() };
    Nan::Utf8String plain{ info[1]->ToString() };
    Local<Function> callback = Local<Function>::Cast(info[2]);

    auto worker = new VerifyAsyncWorker(new Nan::Callback(callback),
    *encrypted, *plain);

    Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(VerifySync) {
    using std::strlen;

    Nan::HandleScope scope;

    if (info.Length() < 2) {
        Nan::ThrowTypeError("2 arguments expected");
        return;
    }

    Nan::Utf8String encrypted{info[0]->ToString()};
    Nan::Utf8String plain{info[1]->ToString()};

    auto result = argon2i_verify(*encrypted, *plain, strlen(*plain));

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
