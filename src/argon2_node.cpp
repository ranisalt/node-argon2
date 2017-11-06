#include <node.h>

#include <stdint.h>
#include <cstring>
#include <string>

#include "../argon2/include/argon2.h"
#include "argon2_node.h"

namespace NodeArgon2 {

template<class T = uint32_t>
T fromJust(v8::Local<v8::Value> info) {
    return Nan::To<T>(info).FromJust();
}

using size_type = std::string::size_type;

enum OBJECTS {
    RESERVED = 0,
    THIS_OBJ,
    RESOLVE,
    REJECT,
};

constexpr uint32_t log(uint64_t number, uint64_t base = 2u)
{
    return (number > 1) ? 1u + log(number / base, base) : 0u;
}

constexpr size_type base64Length(size_type length)
{
    return ((length + 2u) / 3u) * 4u;
}

size_type encodedLength(size_type hashLength, size_type saltLength)
{
    /* statically calculate maximum encoded hash length */
    constexpr size_type extraLength = sizeof "$argon2xx$v=$m=,t=,p=$$" +
        log(static_cast<uint64_t>(ARGON2_VERSION_NUMBER) + 1u, 10u) +
        log(static_cast<uint64_t>(ARGON2_MAX_MEMORY) + 1u, 10u) +
        log(static_cast<uint64_t>(ARGON2_MAX_TIME) + 1u, 10u) +
        log(static_cast<uint64_t>(ARGON2_MAX_LANES) + 1u, 10u);

    return extraLength + base64Length(hashLength) + base64Length(saltLength);
}

HashWorker::HashWorker(std::string&& plain, std::string&& salt,
        uint32_t l, uint32_t t, uint32_t m, uint32_t p, argon2_type a, bool raw):
    Nan::AsyncWorker{nullptr}, plain{std::move(plain)}, salt{std::move(salt)},
    hash_length{l}, time_cost{t}, memory_cost{m}, parallelism{p}, type{a}, raw{raw}
{ }

void HashWorker::Execute()
{
    int result;

    if (raw) {
        output.reset(new char[hash_length]);

        result = argon2_hash(time_cost, 1u << memory_cost, parallelism,
                plain.c_str(), plain.size(), salt.c_str(), salt.size(), output.get(),
                hash_length, nullptr, 0, type, ARGON2_VERSION_NUMBER);
    } else {
        const auto ENCODED_LEN = encodedLength(hash_length, salt.size());
        output.reset(new char[ENCODED_LEN]);

        result = argon2_hash(time_cost, 1u << memory_cost, parallelism,
                plain.c_str(), plain.size(), salt.c_str(), salt.size(), nullptr,
                hash_length, output.get(), ENCODED_LEN, type, ARGON2_VERSION_NUMBER);
    }

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

    if (raw) {
        Local<Value> argv[] = {Nan::NewBuffer(output.release(), hash_length).ToLocalChecked()};
        Nan::MakeCallback(GetFromPersistent(THIS_OBJ).As<Object>(),
            GetFromPersistent(RESOLVE).As<Function>(), 1, argv);
    } else {
        Local<Value> argv[] = {Nan::Encode(output.get(), strlen(output.get()))};
        Nan::MakeCallback(GetFromPersistent(THIS_OBJ).As<Object>(),
            GetFromPersistent(RESOLVE).As<Function>(), 1, argv);
    }
}

/* LCOV_EXCL_START */
void HashWorker::HandleErrorCallback()
{
    using namespace v8;

    Nan::HandleScope scope;

    Local<Value> argv[] = {Nan::New(ErrorMessage()).ToLocalChecked()};
    Nan::MakeCallback(GetFromPersistent(THIS_OBJ).As<Object>(),
            GetFromPersistent(REJECT).As<Function>(), 1, argv);
}
/* LCOV_EXCL_STOP */

NAN_METHOD(Hash) {
    using namespace node;
    using namespace v8;

    assert(info.Length() >= 5);

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
            fromJust(getArg("hashLength")), fromJust(getArg("timeCost")),
            fromJust(getArg("memoryCost")), fromJust(getArg("parallelism")),
            argon2_type(fromJust(getArg("type"))), fromJust<bool>(getArg("raw"))
            };

    worker->SaveToPersistent(THIS_OBJ, info.This());
    worker->SaveToPersistent(RESOLVE, Local<Function>::Cast(info[3]));
    worker->SaveToPersistent(REJECT, Local<Function>::Cast(info[4]));

    Nan::AsyncQueueWorker(worker);
}

VerifyWorker::VerifyWorker(std::string&& hash, std::string&& plain):
    Nan::AsyncWorker{nullptr}, hash{std::move(hash)}, plain{std::move(plain)}
{ }

void VerifyWorker::Execute()
{
    argon2_type type;

    if(hash.at(7) == 'd') {
        type = Argon2_d;
    }
    else if(hash.at(8) == 'd') {
        type = Argon2_id;
    }
    else {
        type = Argon2_i;
    }

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
    Nan::MakeCallback(GetFromPersistent(THIS_OBJ).As<Object>(),
            GetFromPersistent(RESOLVE).As<Function>(), 1, argv);
}

/* LCOV_EXCL_START */
void VerifyWorker::HandleErrorCallback()
{
    using namespace v8;

    Nan::HandleScope scope;

    Local<Value> argv[] = {Nan::New(ErrorMessage()).ToLocalChecked()};
    Nan::MakeCallback(GetFromPersistent(THIS_OBJ).As<Object>(),
            GetFromPersistent(REJECT).As<Function>(), 1, argv);
}
/* LCOV_EXCL_STOP */

NAN_METHOD(Verify) {
    using namespace node;
    using namespace v8;

    assert(info.Length() >= 4);

    const auto hash = Nan::To<Object>(info[0]).ToLocalChecked();
    const auto plain = Nan::To<Object>(info[1]).ToLocalChecked();

    auto worker = new VerifyWorker{{Buffer::Data(hash), Buffer::Length(hash)},
            {Buffer::Data(plain), Buffer::Length(plain)}};

    worker->SaveToPersistent(THIS_OBJ, info.This());
    worker->SaveToPersistent(RESOLVE, Local<Function>::Cast(info[2]));
    worker->SaveToPersistent(REJECT, Local<Function>::Cast(info[3]));

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

    setMaxMin("hashLength", ARGON2_MAX_OUTLEN, ARGON2_MIN_OUTLEN);
    setMaxMin("memoryCost", log(ARGON2_MAX_MEMORY), log(ARGON2_MIN_MEMORY));
    setMaxMin("timeCost", ARGON2_MAX_TIME, ARGON2_MIN_TIME);
    setMaxMin("parallelism", ARGON2_MAX_LANES, ARGON2_MIN_LANES);

    Nan::Set(target, Nan::New("limits").ToLocalChecked(), limits);
    Nan::Export(target, "hash", Hash);
    Nan::Export(target, "verify", Verify);
}

}

NODE_MODULE(argon2_lib, NodeArgon2::init);
