#include <node.h>

#include <stdint.h>
#include <cstring>
#include <string>

#include "../argon2/include/argon2.h"
#include "argon2_node.h"

namespace NodeArgon2 {

namespace {

using size_type = std::string::size_type;

enum OBJECTS {
    RESERVED = 0,
    THIS_OBJ,
    RESOLVE,
    REJECT,
};

constexpr uint32_t log2(uint64_t number)
{
    return (number > 1) ? 1u + log2(number / 2) : 0u;
}

}

HashWorker::HashWorker(std::string plain, std::string salt,
        uint32_t hash_length, uint32_t time_cost, uint32_t memory_cost,
        uint32_t parallelism, argon2_type type, bool raw):
    Nan::AsyncWorker{nullptr}, plain{std::move(plain)}, salt{std::move(salt)},
    hash_length{hash_length}, time_cost{time_cost}, memory_cost{memory_cost},
    parallelism{parallelism}, type{type}, raw{raw}
{ }

void HashWorker::Execute()
{
    char buf[hash_length];
    argon2_context ctx;

    ctx.out = reinterpret_cast<uint8_t*>(buf);
    ctx.outlen = hash_length;
    ctx.pwd = reinterpret_cast<uint8_t*>(const_cast<char*>(plain.data()));
    ctx.pwdlen = plain.size();
    ctx.salt = reinterpret_cast<uint8_t*>(const_cast<char*>(salt.data()));
    ctx.saltlen = salt.size();
    ctx.secret = nullptr;
    ctx.secretlen = 0;
    ctx.ad = nullptr;
    ctx.adlen = 0;
    ctx.t_cost = time_cost;
    ctx.m_cost = 1u << memory_cost;
    ctx.lanes = parallelism;
    ctx.threads = parallelism;
    ctx.allocate_cbk = nullptr;
    ctx.free_cbk = nullptr;
    ctx.flags = ARGON2_DEFAULT_FLAGS;
    ctx.version = ARGON2_VERSION_NUMBER;

    int result = argon2_ctx(&ctx, type);

    if (result != ARGON2_OK) {
        /* LCOV_EXCL_START */
        SetErrorMessage(argon2_error_message(result));
        /* LCOV_EXCL_STOP */
    } else {
        output.assign(buf, hash_length);
    }

    std::fill_n(buf, hash_length, 0);
}

void HashWorker::HandleOKCallback()
{
    Nan::HandleScope scope;

    v8::Local<v8::Value> argv[] = {
        Nan::NewBuffer(strdup(output.data()), output.size()).ToLocalChecked()
    };
    Nan::MakeCallback(GetFromPersistent(THIS_OBJ).As<v8::Object>(),
        GetFromPersistent(RESOLVE).As<v8::Function>(), 1, argv);
}

/* LCOV_EXCL_START */
void HashWorker::HandleErrorCallback()
{
    Nan::HandleScope scope;

    v8::Local<v8::Value> argv[] = {Nan::New(ErrorMessage()).ToLocalChecked()};
    Nan::MakeCallback(GetFromPersistent(THIS_OBJ).As<v8::Object>(),
            GetFromPersistent(REJECT).As<v8::Function>(), 1, argv);
}
/* LCOV_EXCL_STOP */

template<class Object>
v8::Local<v8::Value> from_object(const Object& object, const char* key) {
    return Nan::Get(object, Nan::New(key).ToLocalChecked()).ToLocalChecked();
}

template<class ReturnValue, class T>
ReturnValue to_just(const T& object) {
    return Nan::To<ReturnValue>(object).FromJust();
}

template<class T>
std::string to_string(const T& object) {
    auto&& conv = Nan::To<v8::Object>(object).ToLocalChecked();
    return {node::Buffer::Data(conv), node::Buffer::Length(conv)};
}

NAN_METHOD(Hash) {
    assert(info.Length() == 4);

    auto&& plain = to_string(info[0]);
    auto&& options = Nan::To<v8::Object>(info[1]).ToLocalChecked();

    auto&& salt = to_string(from_object(options, "salt"));

    auto worker = new HashWorker{
        std::move(plain), std::move(salt),
        to_just<uint32_t>(from_object(options, "hashLength")),
        to_just<uint32_t>(from_object(options, "timeCost")),
        to_just<uint32_t>(from_object(options, "memoryCost")),
        to_just<uint32_t>(from_object(options, "parallelism")),
        argon2_type(to_just<uint32_t>(from_object(options, "type"))),
        to_just<bool>(from_object(options, "raw"))
    };

    worker->SaveToPersistent(THIS_OBJ, info.This());
    worker->SaveToPersistent(RESOLVE, v8::Local<v8::Function>::Cast(info[2]));
    worker->SaveToPersistent(REJECT, v8::Local<v8::Function>::Cast(info[3]));

    Nan::AsyncQueueWorker(worker);
}

VerifyWorker::VerifyWorker(std::string&& hash, std::string&& plain):
    Nan::AsyncWorker{nullptr}, hash{std::move(hash)}, plain{std::move(plain)}
{ }

void VerifyWorker::Execute()
{
    argon2_type type = hash.at(7) == 'd' ? Argon2_d
                     : hash.at(8) == 'd' ? Argon2_id
                     : Argon2_i;

    auto result = argon2_verify(hash.data(), plain.data(), plain.size(), type);

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
    Nan::HandleScope scope;

    v8::Local<v8::Value> argv[] = {Nan::New(output)};
    Nan::MakeCallback(GetFromPersistent(THIS_OBJ).As<v8::Object>(),
            GetFromPersistent(RESOLVE).As<v8::Function>(), 1, argv);
}

/* LCOV_EXCL_START */
void VerifyWorker::HandleErrorCallback()
{
    Nan::HandleScope scope;

    v8::Local<v8::Value> argv[] = {Nan::New(ErrorMessage()).ToLocalChecked()};
    Nan::MakeCallback(GetFromPersistent(THIS_OBJ).As<v8::Object>(),
            GetFromPersistent(REJECT).As<v8::Function>(), 1, argv);
}
/* LCOV_EXCL_STOP */

NAN_METHOD(Verify) {
    assert(info.Length() == 4);

    auto&& hash = to_string(info[0]);
    auto&& plain = to_string(info[1]);

    auto worker = new VerifyWorker{std::move(hash), std::move(plain)};

    worker->SaveToPersistent(THIS_OBJ, info.This());
    worker->SaveToPersistent(RESOLVE, v8::Local<v8::Function>::Cast(info[2]));
    worker->SaveToPersistent(REJECT, v8::Local<v8::Function>::Cast(info[3]));

    Nan::AsyncQueueWorker(worker);
}

NAN_MODULE_INIT(init) {
    auto limits = Nan::New<v8::Object>();

    const auto setMaxMin = [&](const char* name, uint32_t max, uint32_t min) {
        auto obj = Nan::New<v8::Object>();
        Nan::Set(obj, Nan::New("max").ToLocalChecked(), Nan::New<v8::Number>(max));
        Nan::Set(obj, Nan::New("min").ToLocalChecked(), Nan::New<v8::Number>(min));
        Nan::Set(limits, Nan::New(name).ToLocalChecked(), obj);
    };

    setMaxMin("hashLength", ARGON2_MAX_OUTLEN, ARGON2_MIN_OUTLEN);
    setMaxMin("memoryCost", log2(ARGON2_MAX_MEMORY), log2(ARGON2_MIN_MEMORY));
    setMaxMin("timeCost", ARGON2_MAX_TIME, ARGON2_MIN_TIME);
    setMaxMin("parallelism", ARGON2_MAX_LANES, ARGON2_MIN_LANES);

    auto types = Nan::New<v8::Object>();

    const auto setType = [&](argon2_type type) {
        Nan::Set(types,
                Nan::New(argon2_type2string(type, false)).ToLocalChecked(),
                Nan::New<v8::Number>(type));
    };

    setType(Argon2_d);
    setType(Argon2_i);
    setType(Argon2_id);

    Nan::Set(target, Nan::New("limits").ToLocalChecked(), limits);
    Nan::Set(target, Nan::New("types").ToLocalChecked(), types);
    Nan::Set(target, Nan::New("version").ToLocalChecked(),
            Nan::New<v8::Number>(ARGON2_VERSION_NUMBER));

    Nan::Export(target, "hash", Hash);
    Nan::Export(target, "verify", Verify);
}

}

NODE_MODULE(argon2_lib, NodeArgon2::init);
