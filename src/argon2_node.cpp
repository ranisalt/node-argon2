#include <node.h>

#include <stdint.h>
#include <cstring>
#include <string>
#include <tuple>

#include "../argon2/include/argon2.h"
#include "argon2_node.h"

namespace NodeArgon2 {

template<class T>
T fromJust(v8::Local<v8::Value> info) {
    return Nan::To<T>(info).FromJust();
}

using size_type = std::string::size_type;
const auto HASH_LEN = 32u;

enum OBJECTS {
    kRESERVED = 0,
    kTHIS,
    kRESOLVE,
    kREJECT,
};

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

HashWorker::HashWorker(std::string&& plain, std::string&& salt,
        std::tuple<uint32_t, uint32_t, uint32_t, argon2_type>&& params):
    Nan::AsyncWorker{nullptr}, plain{plain}, salt{salt},
    time_cost{std::get<0>(params)}, memory_cost{std::get<1>(params)},
    parallelism{std::get<2>(params)}, type{std::get<3>(params)}
{ }

void HashWorker::Execute()
{
    const auto ENCODED_LEN = encodedLength(salt.size());
    output.reset(new char[ENCODED_LEN]);

    auto result = argon2_hash(time_cost, memory_cost, parallelism,
            plain.c_str(), plain.size(), salt.c_str(), salt.size(), nullptr,
            HASH_LEN, output.get(), ENCODED_LEN, type, ARGON2_VERSION_NUMBER);

    if (result != ARGON2_OK) {
        /* LCOV_EXCL_START */
        SetErrorMessage(argon2_error_message(result));
        /* LCOV_EXCL_STOP */
    }
}

void HashWorker::HandleOKCallback()
{
    using namespace v8;
    using std::strlen;

    Nan::HandleScope scope;

    Local<Value> argv[] = {Nan::Encode(output.get(), strlen(output.get()))};
    Nan::MakeCallback(GetFromPersistent(kTHIS).As<Object>(),
            GetFromPersistent(kRESOLVE).As<Function>(), 1, argv);
}

/* LCOV_EXCL_START */
void HashWorker::HandleErrorCallback()
{
    using namespace v8;

    Nan::HandleScope scope;

    Local<Value> argv[] = {Nan::New(ErrorMessage()).ToLocalChecked()};
    Nan::MakeCallback(GetFromPersistent(kTHIS).As<Object>(),
            GetFromPersistent(kREJECT).As<Function>(), 1, argv);
}
/* LCOV_EXCL_STOP */

NAN_METHOD(Hash) {
    using namespace node;
    using namespace v8;

    assert(info.Length() >= 8);

    const auto plain = Nan::To<Object>(info[0]).ToLocalChecked();
    const auto salt = Nan::To<Object>(info[1]).ToLocalChecked();
    const auto options = Nan::To<Object>(info[2]).ToLocalChecked();

    const auto getArg = [&](const char* key) {
        auto localKey = Nan::New(key).ToLocalChecked();
        return Nan::Get(options, localKey).ToLocalChecked();
    };

    auto worker = new HashWorker{
            {Buffer::Data(plain), Buffer::Length(plain)},
            {Buffer::Data(salt), Buffer::Length(salt)},
            std::make_tuple(fromJust<uint32_t>(getArg("timeCost")),
                    1u << fromJust<uint32_t>(getArg("memoryCost")),
                    fromJust<uint32_t>(getArg("parallelism")),
                    fromJust<bool>(getArg("argon2d")) ? Argon2_d : Argon2_i)};

    worker->SaveToPersistent(kTHIS, info.This());
    worker->SaveToPersistent(kRESOLVE, Local<Function>::Cast(info[3]));
    worker->SaveToPersistent(kREJECT, Local<Function>::Cast(info[4]));

    Nan::AsyncQueueWorker(worker);
}

VerifyWorker::VerifyWorker(std::string&& hash, std::string&& plain):
    Nan::AsyncWorker{nullptr}, hash{hash}, plain{plain}
{ }

void VerifyWorker::Execute()
{
    auto type = (hash.at(7) == 'd') ? Argon2_d : Argon2_i;
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

void VerifyWorker::HandleOKCallback()
{
    using namespace v8;

    Nan::HandleScope scope;

    Local<Value> argv[] = {Nan::New(output)};
    Nan::MakeCallback(GetFromPersistent(kTHIS).As<Object>(),
            GetFromPersistent(kRESOLVE).As<Function>(), 1, argv);
}

/* LCOV_EXCL_START */
void VerifyWorker::HandleErrorCallback()
{
    using namespace v8;

    Nan::HandleScope scope;

    Local<Value> argv[] = {Nan::New(ErrorMessage()).ToLocalChecked()};
    Nan::MakeCallback(GetFromPersistent(kTHIS).As<Object>(),
            GetFromPersistent(kREJECT).As<Function>(), 1, argv);
}
/* LCOV_EXCL_STOP */

NAN_METHOD(Verify) {
    using namespace node;
    using namespace v8;

    assert(info.Length() >= 5);

    const auto hash = Nan::To<Object>(info[0]).ToLocalChecked();
    const auto plain = Nan::To<Object>(info[1]).ToLocalChecked();

    auto worker = new VerifyWorker{{Buffer::Data(hash), Buffer::Length(hash)},
            {Buffer::Data(plain), Buffer::Length(plain)}};

    worker->SaveToPersistent(kTHIS, info.This());
    worker->SaveToPersistent(kRESOLVE, Local<Function>::Cast(info[2]));
    worker->SaveToPersistent(kREJECT, Local<Function>::Cast(info[3]));

    Nan::AsyncQueueWorker(worker);
}

NAN_MODULE_INIT(init) {
    using namespace v8;

    auto limits = Nan::New<Object>();

    const auto setMaxMin = [&](const char* name, uint32_t max, uint32_t min) {
        auto obj = Nan::New<Object>();
        Nan::Set(obj, Nan::New("max").ToLocalChecked(), Nan::New<Number>(max));
        Nan::Set(obj, Nan::New("min").ToLocalChecked(), Nan::New<Number>(min));
        Nan::Set(limits, Nan::New(name).ToLocalChecked(), obj);
    };

    setMaxMin("memoryCost", log(ARGON2_MAX_MEMORY), log(ARGON2_MIN_MEMORY));
    setMaxMin("timeCost", ARGON2_MAX_TIME, ARGON2_MIN_TIME);
    setMaxMin("parallelism", ARGON2_MAX_LANES, ARGON2_MIN_LANES);

    Nan::Set(target, Nan::New("limits").ToLocalChecked(), limits);
    Nan::Export(target, "hash", Hash);
    Nan::Export(target, "verify", Verify);
}

}

NODE_MODULE(argon2_lib, NodeArgon2::init);
