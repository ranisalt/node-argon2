#include <node.h>

#include <stdint.h>
#include <cstring>
#include <string>
#include <tuple>

#include "../argon2/include/argon2.h"
#include "argon2_node.h"

namespace NodeArgon2 {

#define GET_ARG(type, index) Nan::To<type>(info[index]).FromJust()

using size_type = std::string::size_type;
const auto HASH_LEN = 32u;

constexpr auto log(uint64_t number, uint64_t base = 2u) -> decltype(number)
{
    return (number > 1) ? 1u + log(number / base, base) : 0u;
}

constexpr auto base64Length(size_type length) -> decltype(length)
{
    return ((length  + 2u) / 3u) * 4u;
}

auto encodedLength(size_type saltLength) -> decltype(saltLength)
{
    /* statically calculate maximum encoded hash length */
    constexpr size_type extraLength = sizeof "$argon2x$m=,t=,p=$$" +
        log(ARGON2_MAX_MEMORY + 1u, 10u) + log(ARGON2_MAX_TIME + 1u, 10u) +
        log(ARGON2_MAX_LANES + 1u, 10u) + base64Length(HASH_LEN);

    /* (number + 3) & ~3 rounds up to the nearest 4-byte boundary */
    return extraLength + base64Length(saltLength);
}

HashAsyncWorker::HashAsyncWorker(std::string&& plain, std::string&& salt,
        std::tuple<uint32_t, uint32_t, uint32_t, argon2_type>&& params):
    Nan::AsyncWorker{nullptr}, plain{plain}, salt{salt},
    time_cost{std::get<0>(params)}, memory_cost{std::get<1>(params)},
    parallelism{std::get<2>(params)}, type{std::get<3>(params)}
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
    using namespace v8;
    using std::strlen;

    Nan::HandleScope scope;

    auto promise = GetFromPersistent(1).As<Promise::Resolver>();
    auto value = Nan::Encode(output.get(), strlen(output.get()));
    promise->Resolve(Nan::GetCurrentContext(), value);
}

/* LCOV_EXCL_START */
void HashAsyncWorker::HandleErrorCallback()
{
    using namespace v8;

    Nan::HandleScope scope;

    auto promise = GetFromPersistent(1).As<Promise::Resolver>();
    auto reason = Nan::New(ErrorMessage()).ToLocalChecked();
    promise->Reject(Nan::GetCurrentContext(), Exception::Error(reason));
}
/* LCOV_EXCL_STOP */

NAN_METHOD(Hash) {
    using namespace node;
    using namespace v8;

    assert(info.Length() >= 6);

    const auto plain = Nan::To<Object>(info[0]).ToLocalChecked();
    const auto salt = Nan::To<Object>(info[1]).ToLocalChecked();

    auto worker = new HashAsyncWorker{
            {Buffer::Data(plain), Buffer::Length(plain)},
            {Buffer::Data(salt), Buffer::Length(salt)},
            std::make_tuple(GET_ARG(uint32_t, 2), 1u << GET_ARG(uint32_t, 3),
                GET_ARG(uint32_t, 4), GET_ARG(bool, 5) ? Argon2_d : Argon2_i)};

    auto resolver = Promise::Resolver::New(Nan::GetCurrentContext()).ToLocalChecked();
    worker->SaveToPersistent(1, resolver);

    Nan::AsyncQueueWorker(worker);
    info.GetReturnValue().Set(resolver->GetPromise());
}

NAN_METHOD(HashSync) {
    using namespace node;
    using namespace v8;
    using std::strlen;

    assert(info.Length() >= 6);

    const auto plain = Nan::To<Object>(info[0]).ToLocalChecked();
    const auto salt = Nan::To<Object>(info[1]).ToLocalChecked();

    const auto ENCODED_LEN = encodedLength(Buffer::Length(salt));
    auto output = std::unique_ptr<char[]>{new char[ENCODED_LEN]};

    auto result = argon2_hash(GET_ARG(uint32_t, 2), 1u << GET_ARG(uint32_t, 3),
            GET_ARG(uint32_t, 4), Buffer::Data(plain), Buffer::Length(plain),
            Buffer::Data(salt), Buffer::Length(salt), nullptr, HASH_LEN,
            output.get(), ENCODED_LEN, GET_ARG(bool, 5) ? Argon2_d : Argon2_i);

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
    Nan::AsyncWorker{nullptr}, hash{hash}, plain{plain}, type{type}
{ }

void VerifyAsyncWorker::Execute()
{
    auto result = argon2_verify(hash.c_str(), plain.c_str(), plain.size(), type);

    switch (result) {
        case ARGON2_OK:
        case ARGON2_VERIFY_MISMATCH:
            output = result == ARGON2_OK;
            break;
        default:
            /* LCOV_EXCL_START */
            SetErrorMessage(argon2_error_message(result));
            break;
            /* LCOV_EXCL_STOP */
    }
}

void VerifyAsyncWorker::HandleOKCallback()
{
    using namespace v8;

    Nan::HandleScope scope;

    auto promise = GetFromPersistent(1).As<Promise::Resolver>();
    promise->Resolve(Nan::GetCurrentContext(), Nan::New(output));
}

/* LCOV_EXCL_START */
void VerifyAsyncWorker::HandleErrorCallback()
{
    using namespace v8;

    Nan::HandleScope scope;

    auto promise = GetFromPersistent(1).As<Promise::Resolver>();
    auto reason = Nan::New(ErrorMessage()).ToLocalChecked();
    promise->Reject(Nan::GetCurrentContext(), Exception::Error(reason));
}
/* LCOV_EXCL_STOP */

NAN_METHOD(Verify) {
    using namespace node;
    using namespace v8;

    assert(info.Length() >= 3);

    Nan::Utf8String hash{Nan::To<String>(info[0]).ToLocalChecked()};
    const auto plain = Nan::To<Object>(info[1]).ToLocalChecked();
    auto type = GET_ARG(bool, 2) ? Argon2_d : Argon2_i;

    auto worker = new VerifyAsyncWorker(*hash,
            {Buffer::Data(plain), Buffer::Length(plain)}, type);

    auto resolver = Promise::Resolver::New(Nan::GetCurrentContext()).ToLocalChecked();
    worker->SaveToPersistent(1, resolver);

    Nan::AsyncQueueWorker(worker);
    info.GetReturnValue().Set(resolver->GetPromise());
}

NAN_METHOD(VerifySync) {
    using namespace node;
    using namespace v8;

    assert(info.Length() >= 3);

    Nan::Utf8String hash{Nan::To<String>(info[0]).ToLocalChecked()};
    const auto plain = Nan::To<Object>(info[1]).ToLocalChecked();

    auto result = argon2_verify(*hash, Buffer::Data(plain),
            Buffer::Length(plain), GET_ARG(bool, 2) ? Argon2_d : Argon2_i);

    switch (result) {
        case ARGON2_OK:
        case ARGON2_VERIFY_MISMATCH:
            info.GetReturnValue().Set(result == ARGON2_OK);
            break;
        default:
            /* LCOV_EXCL_START */
            Nan::ThrowError(argon2_error_message(result));
            break;
            /* LCOV_EXCL_STOP */
    }
}

NAN_MODULE_INIT(init) {
    using namespace v8;

    auto limits = Nan::New<Object>();

    #define setMaxMin(target, max, min) \
        auto target = Nan::New<Object>(); \
        Nan::Set(target, Nan::New("max").ToLocalChecked(), Nan::New<Number>(max)); \
        Nan::Set(target, Nan::New("min").ToLocalChecked(), Nan::New<Number>(min)); \
        Nan::Set(limits, Nan::New(#target).ToLocalChecked(), target);

    setMaxMin(memoryCost, log(ARGON2_MAX_MEMORY), log(ARGON2_MIN_MEMORY));
    setMaxMin(timeCost, ARGON2_MAX_TIME, ARGON2_MIN_TIME);
    setMaxMin(parallelism, ARGON2_MAX_LANES, ARGON2_MIN_LANES);

    #undef setMaxMin

    Nan::Set(target, Nan::New("limits").ToLocalChecked(), limits);
    Nan::Export(target, "hash", Hash);
    Nan::Export(target, "hashSync", HashSync);
    Nan::Export(target, "verify", Verify);
    Nan::Export(target, "verifySync", VerifySync);
}

#undef GET_ARG

}

NODE_MODULE(argon2_lib, NodeArgon2::init);
