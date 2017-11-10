#include <node.h>

#include <stdint.h>
#include <cstring>
#include <string>

#include "../argon2/include/argon2.h"
#include "argon2_node.h"

namespace NodeArgon2 {

namespace {

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

constexpr uint32_t log2(uint64_t number)
{
    return (number > 1) ? 1u + log2(number / 2) : 0u;
}

}

HashWorker::HashWorker(std::string plain, std::string salt,
        uint32_t hash_length, uint32_t time_cost, uint32_t memory_cost,
        uint32_t parallelism, argon2_type type, bool raw):
    Nan::AsyncWorker{nullptr}, plain{std::move(plain)}, salt{std::move(salt)},
    hash_length{hash_length}, time_cost{time_cost},
    memory_cost{1u << memory_cost}, parallelism{parallelism}, type{type},
    raw{raw}
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
    ctx.m_cost = memory_cost;
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
    using namespace v8;
    using std::strlen;

    Nan::HandleScope scope;

    Local<Value> argv[] = {
        Nan::NewBuffer(strdup(output.c_str()), output.size()).ToLocalChecked()
    };
    Nan::MakeCallback(GetFromPersistent(THIS_OBJ).As<Object>(),
        GetFromPersistent(RESOLVE).As<Function>(), 1, argv);
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

    assert(info.Length() >= 4);

    const auto plain = Nan::To<Object>(info[0]).ToLocalChecked();
    const auto options = Nan::To<Object>(info[1]).ToLocalChecked();

    const auto saltKey = Nan::New("salt").ToLocalChecked();
    const auto saltValue = Nan::Get(options, saltKey).ToLocalChecked();
    const auto salt = Nan::To<Object>(saltValue).ToLocalChecked();

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
    worker->SaveToPersistent(RESOLVE, Local<Function>::Cast(info[2]));
    worker->SaveToPersistent(REJECT, Local<Function>::Cast(info[3]));

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
    setMaxMin("memoryCost", log2(ARGON2_MAX_MEMORY), log2(ARGON2_MIN_MEMORY));
    setMaxMin("timeCost", ARGON2_MAX_TIME, ARGON2_MIN_TIME);
    setMaxMin("parallelism", ARGON2_MAX_LANES, ARGON2_MIN_LANES);

    auto types = Nan::New<Object>();

    const auto setType = [&](argon2_type type) {
        Nan::Set(types,
                Nan::New(argon2_type2string(type, false)).ToLocalChecked(),
                Nan::New<Number>(type));
    };

    setType(Argon2_d);
    setType(Argon2_i);
    setType(Argon2_id);

    Nan::Set(target, Nan::New("limits").ToLocalChecked(), limits);
    Nan::Set(target, Nan::New("types").ToLocalChecked(), types);
    Nan::Set(target, Nan::New("version").ToLocalChecked(),
            Nan::New<Number>(ARGON2_VERSION_NUMBER));

    Nan::Export(target, "hash", Hash);
    Nan::Export(target, "verify", Verify);
}

}

NODE_MODULE(argon2_lib, NodeArgon2::init);
