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
        uint32_t parallelism, argon2_type type):
    Nan::AsyncWorker{nullptr}, plain{plain}, salt{salt}, time_cost{time_cost},
    memory_cost{memory_cost}, parallelism{parallelism}, type{type}, output{}
{ }

void HashAsyncWorker::Execute()
{
    output.reset(new char[ENCODED_LEN]);

    auto result = argon2_hash(time_cost, memory_cost, parallelism,
            plain.c_str(), plain.size(), salt.c_str(), salt.size(), nullptr,
            HASH_LEN, output.get(), ENCODED_LEN, type);
    if (result != ARGON2_OK) {
        /* LCOV_EXCL_START */
        SetErrorMessage(argon2_error_message(result));
        return;
        /* LCOV_EXCL_STOP */
    }
}

void HashAsyncWorker::HandleOKCallback()
{
    using v8::Promise;

    Nan::HandleScope scope;

    auto promise = GetFromPersistent("resolver").As<Promise::Resolver>();
    promise->Resolve(Nan::Encode(output.get(), std::strlen(output.get())));
}

/* LCOV_EXCL_START */
void HashAsyncWorker::HandleErrorCallback()
{
    using v8::Exception;
    using v8::Promise;

    Nan::HandleScope scope;

    auto promise = GetFromPersistent("resolver").As<Promise::Resolver>();
    auto reason = Nan::New(ErrorMessage()).ToLocalChecked();
    promise->Reject(Exception::Error(reason));
}
/* LCOV_EXCL_STOP */

NAN_METHOD(Hash) {
    using namespace node;
    using v8::Promise;

    if (info.Length() < 6) {
        /* LCOV_EXCL_START */
        Nan::ThrowTypeError("6 arguments expected");
        return;
        /* LCOV_EXCL_STOP */
    }

    auto raw_plain = info[0]->ToObject();
    auto raw_salt = info[1]->ToObject();
    auto time_cost = info[2]->Uint32Value();
    auto memory_cost = info[3]->Uint32Value();
    auto parallelism = info[4]->Uint32Value();
    auto type = info[5]->BooleanValue() ? Argon2_d : Argon2_i;

    auto plain = std::string{Buffer::Data(raw_plain), Buffer::Length(raw_plain)};
    auto salt = std::string{Buffer::Data(raw_salt), Buffer::Length(raw_salt)};

    auto worker = new HashAsyncWorker{plain, salt, time_cost,
        1u << memory_cost, parallelism, type};

    auto resolver = Promise::Resolver::New(info.GetIsolate());
    worker->SaveToPersistent("resolver", resolver);

    Nan::AsyncQueueWorker(worker);
    info.GetReturnValue().Set(resolver->GetPromise());
}

NAN_METHOD(HashSync) {
    using namespace node;

    if (info.Length() < 6) {
        /* LCOV_EXCL_START */
        Nan::ThrowTypeError("6 arguments expected");
        return;
        /* LCOV_EXCL_STOP */
    }

    auto raw_plain = info[0]->ToObject();
    auto raw_salt = info[1]->ToObject();
    auto time_cost = info[2]->Uint32Value();
    auto memory_cost = info[3]->Uint32Value();
    auto parallelism = info[4]->Uint32Value();
    auto type = info[5]->BooleanValue() ? Argon2_d : Argon2_i;

    char encoded[ENCODED_LEN];

    auto result = argon2_hash(time_cost, 1u << memory_cost, parallelism,
            Buffer::Data(raw_plain), Buffer::Length(raw_plain),
            Buffer::Data(raw_salt), Buffer::Length(raw_salt), nullptr, HASH_LEN,
            encoded, ENCODED_LEN, type);

    if (result != ARGON2_OK) {
        /* LCOV_EXCL_START */
        Nan::ThrowError(argon2_error_message(result));
        return;
        /* LCOV_EXCL_STOP */
    }

    info.GetReturnValue().Set(Nan::Encode(encoded, std::strlen(encoded)));
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

    Nan::HandleScope scope;

    auto promise = GetFromPersistent("resolver").As<Promise::Resolver>();
    promise->Reject(Nan::New(ErrorMessage()).ToLocalChecked());
}

NAN_METHOD(Verify) {
    using v8::Promise;
    using namespace node;

    if (info.Length() < 3) {
        /* LCOV_EXCL_START */
        Nan::ThrowTypeError("3 arguments expected");
        return;
        /* LCOV_EXCL_STOP */
    }

    Nan::Utf8String hash{info[0]->ToString()};
    auto raw_plain = info[1]->ToObject();
    auto type = info[2]->BooleanValue() ? Argon2_d : Argon2_i;

    auto plain = std::string{Buffer::Data(raw_plain), Buffer::Length(raw_plain)};

    auto worker = new VerifyAsyncWorker(*hash, plain, type);

    auto resolver = Promise::Resolver::New(info.GetIsolate());
    worker->SaveToPersistent("resolver", resolver);

    Nan::AsyncQueueWorker(worker);
    info.GetReturnValue().Set(resolver->GetPromise());
}

NAN_METHOD(VerifySync) {
    using namespace node;

    if (info.Length() < 3) {
        /* LCOV_EXCL_START */
        Nan::ThrowTypeError("3 arguments expected");
        return;
        /* LCOV_EXCL_STOP */
    }

    Nan::Utf8String hash{info[0]->ToString()};
    auto raw_plain = info[1]->ToObject();
    auto type = info[2]->BooleanValue() ? Argon2_d : Argon2_i;

    auto result = argon2_verify(*hash, Buffer::Data(raw_plain),
            Buffer::Length(raw_plain), type);

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

    auto limits = Nan::New<Object>();

    auto memoryCost = Nan::New<Object>();
    Nan::Set(memoryCost, Nan::New("max").ToLocalChecked(),
            Nan::New<Number>(log(ARGON2_MAX_MEMORY)));
    Nan::Set(memoryCost, Nan::New("min").ToLocalChecked(),
            Nan::New<Number>(log(ARGON2_MIN_MEMORY)));
    Nan::Set(limits, Nan::New("memoryCost").ToLocalChecked(), memoryCost);

    auto timeCost = Nan::New<Object>();
    Nan::Set(timeCost, Nan::New("max").ToLocalChecked(),
            Nan::New<Number>(ARGON2_MAX_TIME));
    Nan::Set(timeCost, Nan::New("min").ToLocalChecked(),
            Nan::New<Number>(ARGON2_MIN_TIME));
    Nan::Set(limits, Nan::New("timeCost").ToLocalChecked(), timeCost);

    auto parallelism = Nan::New<Object>();
    Nan::Set(parallelism, Nan::New("max").ToLocalChecked(),
            Nan::New<Number>(ARGON2_MAX_LANES));
    Nan::Set(parallelism, Nan::New("min").ToLocalChecked(),
            Nan::New<Number>(ARGON2_MIN_LANES));
    Nan::Set(limits, Nan::New("parallelism").ToLocalChecked(), parallelism);

    Nan::Set(target, Nan::New("limits").ToLocalChecked(), limits);
    Nan::Export(target, "hash", Hash);
    Nan::Export(target, "hashSync", HashSync);
    Nan::Export(target, "verify", Verify);
    Nan::Export(target, "verifySync", VerifySync);
}

NODE_MODULE(argon2_lib, init)
