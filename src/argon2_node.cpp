#include <node.h>

#include <stdint.h>
#include <cstring>
#include <string>

#include "../argon2/include/argon2.h"
#include "argon2_node.h"

namespace NodeArgon2 {

const auto ENCODED_LEN = 108u;
const auto HASH_LEN = 32u;

HashAsyncWorker::HashAsyncWorker(const std::string& plain,
        const std::string& salt, uint32_t time_cost, uint32_t memory_cost,
        uint32_t parallelism, Argon2_type type):
    Nan::AsyncWorker{nullptr}, plain{plain}, salt{salt}, time_cost{time_cost},
    memory_cost{memory_cost}, parallelism{parallelism}, type{type}, output{}
{ }

void HashAsyncWorker::Execute()
{
    char encoded[ENCODED_LEN];

    auto result = argon2_hash(time_cost, memory_cost, parallelism,
            plain.c_str(), plain.size(), salt.c_str(), salt.size(), nullptr,
            HASH_LEN, encoded, ENCODED_LEN, type);
    if (result != ARGON2_OK) {
        SetErrorMessage(argon2_error_message(result));
        return;
    }

    output = std::string{encoded};
}

void HashAsyncWorker::HandleOKCallback()
{
    using v8::Promise;

    Nan::HandleScope scope;

    auto promise = GetFromPersistent("resolver").As<Promise::Resolver>();
    promise->Resolve(Nan::Encode(output.c_str(), output.size()));
}

void HashAsyncWorker::HandleErrorCallback()
{
    using v8::Exception;
    using v8::Promise;
    using v8::String;

    Nan::HandleScope scope;

    auto promise = GetFromPersistent("resolver").As<Promise::Resolver>();
    auto reason = Nan::New<String>(ErrorMessage()).ToLocalChecked();
    promise->Reject(Exception::Error(reason));
}

NAN_METHOD(Hash) {
    using namespace node;
    using v8::Promise;

    Nan::HandleScope scope;

    if (info.Length() < 6) {
        /* LCOV_EXCL_START */
        Nan::ThrowTypeError("6 arguments expected");
        return;
        /* LCOV_EXCL_STOP */
    }

    Nan::Utf8String plain{info[0]->ToString()};
    auto raw_salt = info[1]->ToObject();
    auto time_cost = info[2]->Uint32Value();
    auto memory_cost = info[3]->Uint32Value();
    auto parallelism = info[4]->Uint32Value();
    argon2_type type = info[5]->BooleanValue() ? Argon2_d : Argon2_i;

    auto salt = std::string(Buffer::Data(raw_salt), Buffer::Length(raw_salt));

    auto worker = new HashAsyncWorker{*plain, salt, time_cost,
        1u << memory_cost, parallelism, type};

    auto resolver = Promise::Resolver::New(info.GetIsolate());
    worker->SaveToPersistent("resolver", resolver);

    Nan::AsyncQueueWorker(worker);
    info.GetReturnValue().Set(resolver->GetPromise());
}

NAN_METHOD(HashSync) {
    using namespace node;

    Nan::HandleScope scope;

    if (info.Length() < 6) {
        /* LCOV_EXCL_START */
        Nan::ThrowTypeError("6 arguments expected");
        info.GetReturnValue().Set(Nan::Undefined());
        return;
        /* LCOV_EXCL_STOP */
    }

    Nan::Utf8String plain{info[0]->ToString()};
    auto raw_salt = info[1]->ToObject();
    auto time_cost = info[2]->Uint32Value();
    auto memory_cost = info[3]->Uint32Value();
    auto parallelism = info[4]->Uint32Value();
    argon2_type type = info[5]->BooleanValue() ? Argon2_d : Argon2_i;

    char encoded[ENCODED_LEN];

    auto salt = std::string(Buffer::Data(raw_salt), Buffer::Length(raw_salt));

    auto result = argon2_hash(time_cost, 1 << memory_cost, parallelism, *plain,
            strlen(*plain), salt.c_str(), salt.size(), nullptr, HASH_LEN,
            encoded, ENCODED_LEN, type);

    if (result != ARGON2_OK) {
        Nan::ThrowError(argon2_error_message(result));
        info.GetReturnValue().Set(Nan::Undefined());
        return;
    }

    info.GetReturnValue().Set(Nan::Encode(encoded, strlen(encoded),
            Nan::BINARY));
}

VerifyAsyncWorker::VerifyAsyncWorker(const std::string& hash,
        const std::string& plain, argon2_type type):
    Nan::AsyncWorker{nullptr}, hash{hash}, plain{plain}, type{type}
{ }

void VerifyAsyncWorker::Execute()
{
    auto result = argon2_verify(hash.c_str(), plain.c_str(), plain.size(), type);

    if (result != ARGON2_OK) {
        SetErrorMessage(argon2_error_message(result));
    }
}

void VerifyAsyncWorker::HandleOKCallback()
{
    using v8::Promise;

    Nan::HandleScope scope;

    auto promise = GetFromPersistent("resolver").As<Promise::Resolver>();
    promise->Resolve(Nan::Undefined());
}

void VerifyAsyncWorker::HandleErrorCallback()
{
    using v8::Exception;
    using v8::Promise;
    using v8::String;

    Nan::HandleScope scope;

    auto promise = GetFromPersistent("resolver").As<Promise::Resolver>();
    promise->Reject(Nan::New<String>(ErrorMessage()).ToLocalChecked());
}

NAN_METHOD(Verify) {
    using v8::Promise;

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

    auto worker = new VerifyAsyncWorker(*hash, *plain, type);

    auto resolver = Promise::Resolver::New(info.GetIsolate());
    worker->SaveToPersistent("resolver", resolver);

    Nan::AsyncQueueWorker(worker);
    info.GetReturnValue().Set(resolver->GetPromise());
}

NAN_METHOD(VerifySync) {
    using std::strlen;

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

    auto result = argon2_verify(*hash, *plain, strlen(*plain), type);

    info.GetReturnValue().Set(result == ARGON2_OK);
}

constexpr uint32_t log(uint32_t number, uint32_t base = 2u)
{
    return (number > 1) ? 1u + log(number / base, base) : 0u;
}

}

NAN_MODULE_INIT(init) {
    using namespace NodeArgon2;
    using NodeArgon2::log;
    using v8::Number;
    using v8::Object;
    using v8::String;

    auto limits = Nan::New<Object>();

    {
        auto memoryCost = Nan::New<Object>();
        Nan::Set(memoryCost, Nan::New<String>("description").ToLocalChecked(),
                Nan::New<String>("memory cost").ToLocalChecked());
        Nan::Set(memoryCost, Nan::New<String>("max").ToLocalChecked(),
                Nan::New<Number>(log(ARGON2_MAX_MEMORY)));
        Nan::Set(memoryCost, Nan::New<String>("min").ToLocalChecked(),
                Nan::New<Number>(log(ARGON2_MIN_MEMORY)));
        Nan::Set(limits, Nan::New<String>("memoryCost").ToLocalChecked(),
                memoryCost);
    }

    {
        auto timeCost = Nan::New<Object>();
        Nan::Set(timeCost, Nan::New<String>("description").ToLocalChecked(),
                Nan::New<String>("time cost").ToLocalChecked());
        Nan::Set(timeCost, Nan::New<String>("max").ToLocalChecked(),
                Nan::New<Number>(ARGON2_MAX_TIME));
        Nan::Set(timeCost, Nan::New<String>("min").ToLocalChecked(),
                Nan::New<Number>(ARGON2_MIN_TIME));
        Nan::Set(limits, Nan::New<String>("timeCost").ToLocalChecked(),
                timeCost);
    }

    {
        auto parallelism = Nan::New<Object>();
        Nan::Set(parallelism, Nan::New<String>("description").ToLocalChecked(),
                Nan::New<String>("parallelism").ToLocalChecked());
        Nan::Set(parallelism, Nan::New<String>("max").ToLocalChecked(),
                Nan::New<Number>(ARGON2_MAX_LANES));
        Nan::Set(parallelism, Nan::New<String>("min").ToLocalChecked(),
                Nan::New<Number>(ARGON2_MIN_LANES));
        Nan::Set(limits, Nan::New<String>("parallelism").ToLocalChecked(),
                parallelism);
    }

    Nan::Set(target, Nan::New<String>("limits").ToLocalChecked(), limits);
    Nan::Export(target, "hash", Hash);
    Nan::Export(target, "hashSync", HashSync);
    Nan::Export(target, "verify", Verify);
    Nan::Export(target, "verifySync", VerifySync);
}

NODE_MODULE(argon2_lib, init)
