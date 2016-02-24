#include <node.h>

#include <stdint.h>
#include <cstring>
#include <string>

#include "../argon2/include/argon2.h"
#include "argon2_node.h"

namespace NodeArgon2 {

using size_type = std::string::size_type;
const auto HASH_LEN = 32u;

constexpr uint32_t log(uint32_t number, uint32_t base = 2u)
{
    return (number > 1) ? 1u + log(number / base, base) : 0u;
}

constexpr size_type base64Length(size_type length)
{
    using std::ceil;

    return static_cast<size_type>(ceil(length / 3.0)) * 4;
}

size_type encodedLength(size_type saltLength)
{
    using std::strlen;
    using std::to_string;

    /* statically calculate maximum encoded hash length, null byte included */
    static const auto extraLength = strlen("$argon2x$m=,t=,p=$$") + 1u,
            memoryCostLength = to_string(log(ARGON2_MAX_MEMORY)).size(),
            timeCostLength = to_string(ARGON2_MAX_TIME).size(),
            parallelismLength = to_string(ARGON2_MAX_LANES).size();

    /* (number + 3) & ~3 rounds up to the nearest 4-byte boundary */
    return (extraLength + memoryCostLength + timeCostLength + parallelismLength
        + base64Length(saltLength) + base64Length(HASH_LEN) + 3) & ~3;
}

HashAsyncWorker::HashAsyncWorker(std::string&& plain, std::string&& salt,
        uint32_t time_cost, uint32_t memory_cost, uint32_t parallelism,
        argon2_type type):
    Nan::AsyncWorker{nullptr}, plain{plain}, salt{salt}, time_cost{time_cost},
    memory_cost{memory_cost}, parallelism{parallelism}, type{type}, output{}
{ }

void HashAsyncWorker::Execute()
{
    const auto ENCODED_LEN = encodedLength(salt.size());
    output.reset(new char[ENCODED_LEN]);

    auto result = argon2_hash(time_cost, memory_cost, parallelism,
            plain.c_str(), plain.size(), salt.c_str(), salt.size(), nullptr,
            HASH_LEN, output.get(), ENCODED_LEN, type);

    if (result != ARGON2_OK) {
        /* LCOV_EXCL_START */
        SetErrorMessage(argon2_error_message(result));
        /* LCOV_EXCL_STOP */
    }
}

void HashAsyncWorker::HandleOKCallback()
{
    using std::strlen;
    using v8::Context;
    using v8::Promise;

    Nan::HandleScope scope;

    auto promise = GetFromPersistent(1).As<Promise::Resolver>();
    auto value = Nan::Encode(output.get(), strlen(output.get()));
    promise->Resolve(Nan::New<Context>(), value);
}

/* LCOV_EXCL_START */
void HashAsyncWorker::HandleErrorCallback()
{
    using v8::Context;
    using v8::Exception;
    using v8::Promise;

    Nan::HandleScope scope;

    auto promise = GetFromPersistent(1).As<Promise::Resolver>();
    auto reason = Nan::New(ErrorMessage()).ToLocalChecked();
    promise->Reject(Nan::New<Context>(), Exception::Error(reason));
}
/* LCOV_EXCL_STOP */

NAN_METHOD(Hash) {
    using namespace node;
    using v8::Object;
    using v8::Promise;

    if (info.Length() < 6) {
        /* LCOV_EXCL_START */
        Nan::ThrowTypeError("6 arguments expected");
        return;
        /* LCOV_EXCL_STOP */
    }

    const auto plain = Nan::To<Object>(info[0]).ToLocalChecked();
    const auto salt = Nan::To<Object>(info[1]).ToLocalChecked();
    auto time_cost = Nan::To<uint32_t>(info[2]).FromJust();
    auto memory_cost = Nan::To<uint32_t>(info[3]).FromJust();
    auto parallelism = Nan::To<uint32_t>(info[4]).FromJust();
    auto type = Nan::To<bool>(info[5]).FromJust() ? Argon2_d : Argon2_i;

    auto worker = new HashAsyncWorker{
            {Buffer::Data(plain), Buffer::Length(plain)},
            {Buffer::Data(salt), Buffer::Length(salt)},
            time_cost, 1u << memory_cost, parallelism, type};

    auto resolver = Promise::Resolver::New(Nan::GetCurrentContext()).ToLocalChecked();
    worker->SaveToPersistent(1, resolver);

    Nan::AsyncQueueWorker(worker);
    info.GetReturnValue().Set(resolver->GetPromise());
}

NAN_METHOD(HashSync) {
    using namespace node;
    using std::strlen;
    using v8::Object;

    if (info.Length() < 6) {
        /* LCOV_EXCL_START */
        Nan::ThrowTypeError("6 arguments expected");
        return;
        /* LCOV_EXCL_STOP */
    }

    const auto plain = Nan::To<Object>(info[0]).ToLocalChecked();
    const auto salt = Nan::To<Object>(info[1]).ToLocalChecked();
    auto time_cost = Nan::To<uint32_t>(info[2]).FromJust();
    auto memory_cost = Nan::To<uint32_t>(info[3]).FromJust();
    auto parallelism = Nan::To<uint32_t>(info[4]).FromJust();
    auto type = Nan::To<bool>(info[5]).FromJust() ? Argon2_d : Argon2_i;

    const auto ENCODED_LEN = encodedLength(Buffer::Length(salt));
    auto output = std::unique_ptr<char[]>{new char[ENCODED_LEN]};

    auto result = argon2_hash(time_cost, 1u << memory_cost, parallelism,
            Buffer::Data(plain), Buffer::Length(plain), Buffer::Data(salt),
            Buffer::Length(salt), nullptr, HASH_LEN, output.get(), ENCODED_LEN,
            type);

    if (result != ARGON2_OK) {
        /* LCOV_EXCL_START */
        Nan::ThrowError(argon2_error_message(result));
        return;
        /* LCOV_EXCL_STOP */
    }

    info.GetReturnValue().Set(Nan::Encode(output.get(), strlen(output.get())));
}

VerifyAsyncWorker::VerifyAsyncWorker(std::string&& hash, std::string&& plain,
        argon2_type type):
    Nan::AsyncWorker{nullptr}, hash{hash}, plain{plain}, type{type}, output{}
{ }

void VerifyAsyncWorker::Execute()
{
    auto result = argon2_verify(hash.c_str(), plain.c_str(), plain.size(), type);

    if (result != ARGON2_OK && result != ARGON2_VERIFY_MISMATCH) {
        SetErrorMessage(argon2_error_message(result));
        return;
    }

    output = result == ARGON2_OK;
}

void VerifyAsyncWorker::HandleOKCallback()
{
    using v8::Context;
    using v8::Promise;

    Nan::HandleScope scope;

    auto promise = GetFromPersistent(1).As<Promise::Resolver>();
    promise->Resolve(Nan::GetCurrentContext(), Nan::New(output));
}

/* LCOV_EXCL_START */
void VerifyAsyncWorker::HandleErrorCallback()
{
    using v8::Context;
    using v8::Exception;
    using v8::Promise;

    Nan::HandleScope scope;

    auto promise = GetFromPersistent(1).As<Promise::Resolver>();
    auto reason = Nan::New(ErrorMessage()).ToLocalChecked();
    promise->Reject(Nan::GetCurrentContext(), Exception::Error(reason));
}
/* LCOV_EXCL_STOP */

NAN_METHOD(Verify) {
    using namespace node;
    using v8::Object;
    using v8::Promise;
    using v8::String;

    if (info.Length() < 3) {
        /* LCOV_EXCL_START */
        Nan::ThrowTypeError("3 arguments expected");
        return;
        /* LCOV_EXCL_STOP */
    }

    Nan::Utf8String hash{Nan::To<String>(info[0]).ToLocalChecked()};
    const auto plain = Nan::To<Object>(info[1]).ToLocalChecked();
    auto type = Nan::To<bool>(info[2]).FromJust() ? Argon2_d : Argon2_i;

    auto worker = new VerifyAsyncWorker(*hash,
            {Buffer::Data(plain), Buffer::Length(plain)}, type);

    auto resolver = Promise::Resolver::New(Nan::GetCurrentContext()).ToLocalChecked();
    worker->SaveToPersistent(1, resolver);

    Nan::AsyncQueueWorker(worker);
    info.GetReturnValue().Set(resolver->GetPromise());
}

NAN_METHOD(VerifySync) {
    using namespace node;
    using v8::Object;
    using v8::String;

    if (info.Length() < 3) {
        /* LCOV_EXCL_START */
        Nan::ThrowTypeError("3 arguments expected");
        return;
        /* LCOV_EXCL_STOP */
    }

    Nan::Utf8String hash{Nan::To<String>(info[0]).ToLocalChecked()};
    const auto plain = Nan::To<Object>(info[1]).ToLocalChecked();
    auto type = Nan::To<bool>(info[2]).FromJust() ? Argon2_d : Argon2_i;

    auto result = argon2_verify(*hash, Buffer::Data(plain),
            Buffer::Length(plain), type);

    if (result != ARGON2_OK && result != ARGON2_VERIFY_MISMATCH) {
        /* LCOV_EXCL_START */
        Nan::ThrowError(argon2_error_message(result));
        return;
        /* LCOV_EXCL_STOP */
    }

    info.GetReturnValue().Set(result == ARGON2_OK);
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
