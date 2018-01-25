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

v8::Local<v8::Value> from_object(const v8::Local<v8::Object>& object, const char* key) {
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

Options extractOptions(const v8::Local<v8::Object>& options) {
    Options ret;
    ret.salt = to_string(from_object(options, "salt"));
    ret.hash_length = to_just<uint32_t>(from_object(options, "hashLength"));
    ret.time_cost = to_just<uint32_t>(from_object(options, "timeCost"));
    ret.memory_cost = to_just<uint32_t>(from_object(options, "memoryCost"));
    ret.parallelism = to_just<uint32_t>(from_object(options, "parallelism"));
    ret.type = argon2_type(to_just<uint32_t>(from_object(options, "type")));
    return ret;
}

argon2_context make_context(char* buf, const std::string& plain,
        const Options& options) {
    argon2_context ctx;

    ctx.out = reinterpret_cast<uint8_t*>(buf);
    ctx.outlen = options.hash_length;
    ctx.pwd = reinterpret_cast<uint8_t*>(const_cast<char*>(plain.data()));
    ctx.pwdlen = plain.size();
    ctx.salt = reinterpret_cast<uint8_t*>(const_cast<char*>(options.salt.data()));
    ctx.saltlen = options.salt.size();
    ctx.secret = nullptr;
    ctx.secretlen = 0;
    ctx.ad = nullptr;
    ctx.adlen = 0;
    ctx.t_cost = options.time_cost;
    ctx.m_cost = 1u << options.memory_cost;
    ctx.lanes = options.parallelism;
    ctx.threads = options.parallelism;
    ctx.allocate_cbk = nullptr;
    ctx.free_cbk = nullptr;
    ctx.flags = ARGON2_DEFAULT_FLAGS;
    ctx.version = ARGON2_VERSION_NUMBER;

    return ctx;
}

}

HashWorker::HashWorker(std::string plain, Options options):
    Nan::AsyncWorker{nullptr},
    plain{std::move(plain)},
    options{std::move(options)}
{}

void HashWorker::Execute()
{
#ifdef _MSC_VER
    char* buf = new char[options.hash_length];
#else
    char buf[options.hash_length];
#endif

    auto ctx = make_context(buf, plain, options);
    int result = argon2_ctx(&ctx, options.type);

    if (result != ARGON2_OK) {
        /* LCOV_EXCL_START */
        SetErrorMessage(argon2_error_message(result));
        /* LCOV_EXCL_STOP */
    } else {
        output.assign(buf, options.hash_length);
    }

    std::fill_n(buf, options.hash_length, 0);

#ifdef _MSC_VER
    delete[] buf;
#endif
}

void HashWorker::HandleOKCallback()
{
    Nan::HandleScope scope;

    v8::Local<v8::Value> argv[] = {
        Nan::CopyBuffer(output.data(), output.size()).ToLocalChecked()
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

NAN_METHOD(Hash) {
    assert(info.Length() == 4);

    auto&& plain = to_string(info[0]);
    auto&& options = Nan::To<v8::Object>(info[1]).ToLocalChecked();

    auto worker = new HashWorker{
        std::move(plain), extractOptions(options),
    };

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
}

}

NODE_MODULE(argon2_lib, NodeArgon2::init);
