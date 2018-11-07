#include <cassert>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>

#include <napi.h>
#include "../argon2/include/argon2.h"

#ifndef _MSC_VER
namespace {
#endif

class Options {
public:
    // TODO: remove ctors and initializers when GCC<5 stops shipping on Ubuntu
    Options() = default;
    Options(Options&&) = default;

    Napi::Object dump(const std::string& hash,
                      const Napi::Env&   env) const
    {
        Napi::Object out = Napi::Object::New(env);
        out.Set(Napi::String::New(env, "id"), Napi::String::New(env, argon2_type2string(type, false)));
        out.Set(Napi::String::New(env, "version"), Napi::Number::New(env, version));

        auto params = Napi::Object::New(env);
        params.Set(Napi::String::New(env, "m"), Napi::Number::New(env, memory_cost));
        params.Set(Napi::String::New(env, "t"), Napi::Number::New(env, time_cost));
        params.Set(Napi::String::New(env, "p"), Napi::Number::New(env, parallelism));
        out.Set(Napi::String::New(env, "params"), params);

        out.Set(Napi::String::New(env, "salt"), Napi::Buffer<char>::Copy(env, salt.c_str(), salt.size()));
        out.Set(Napi::String::New(env, "hash"), Napi::Buffer<char>::Copy(env, hash.c_str(), hash.size()));
        return out;
    }

    std::string salt;

    uint32_t hash_length = {};
    uint32_t time_cost = {};
    uint32_t memory_cost = {};
    uint32_t parallelism = {};
    uint32_t version = {};

    argon2_type type = {};
};

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
    ctx.m_cost = options.memory_cost;
    ctx.lanes = options.parallelism;
    ctx.threads = options.parallelism;
    ctx.allocate_cbk = nullptr;
    ctx.free_cbk = nullptr;
    ctx.flags = ARGON2_DEFAULT_FLAGS;
    ctx.version = options.version;

    return ctx;
}

class HashWorker final: public Napi::AsyncWorker {
public:
    HashWorker(const Napi::Function& callback,
               std::string plain,
               Options options,
               Napi::Env env) :
        Napi::AsyncWorker{callback, "argon2:HashWorker"},
        plain{std::move(plain)},
        options{std::move(options)},
        env{std::move(env)}
    {}

    void Execute() override
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
            SetError(argon2_error_message(result));
            /* LCOV_EXCL_STOP */
        } else {
            hash.assign(buf, options.hash_length);
        }

        std::fill_n(buf, options.hash_length, 0);

#ifdef _MSC_VER
        delete[] buf;
#endif
    }

    void OnOK() override
    {
        Napi::HandleScope scope(env);
        Callback().Call({env.Null(), options.dump(hash, env)});
    }

private:
    std::string plain;
    Options options;

    std::string hash;
    Napi::Env env;
};

using size_type = std::string::size_type;

Napi::Value from_object(const Napi::Object& object, const char* key)
{
    return object.Get(Napi::Value::From(object.Env(), key));
}

std::string buffer_to_string(const Napi::Value& value)
{
    auto buffer = value.As<Napi::Buffer<char> >();
    return {buffer.Data(), buffer.Length()};
}

Options extract_options(const Napi::Object& options)
{
    Options ret;
    ret.salt = buffer_to_string(from_object(options, "salt"));
    ret.hash_length = from_object(options, "hashLength").ToNumber();
    ret.time_cost = from_object(options, "timeCost").ToNumber();
    ret.memory_cost = from_object(options, "memoryCost").ToNumber();
    ret.parallelism = from_object(options, "parallelism").ToNumber();
    ret.version = from_object(options, "version").ToNumber();
    uint32_t type = from_object(options, "type").ToNumber();
    ret.type = static_cast<argon2_type>(type);

    return ret;
}

#ifndef _MSC_VER
}
#endif

Napi::Value Hash(const Napi::CallbackInfo& info) {
    assert(info.Length() == 3 and
           info[0].IsBuffer() and
           info[1].IsObject() and
           info[2].IsFunction());

    std::string plain = buffer_to_string(info[0]);
    auto options = info[1].As<Napi::Object>();
    auto callback = info[2].As<Napi::Function>();

    auto worker = new HashWorker{
        callback, std::move(plain), extract_options(options), info.Env()
    };

    worker->Queue();
    return info.Env().Undefined();
}

Napi::Object init(Napi::Env env, Napi::Object exports) {
    auto limits = Napi::Object::New(env);

    const auto setMaxMin = [&](const char* name, uint32_t max, uint32_t min) {
        auto obj = Napi::Object::New(env);
        (obj).Set(Napi::String::New(env, "max"), Napi::Number::New(env, max));
        (obj).Set(Napi::String::New(env, "min"), Napi::Number::New(env, min));
        (limits).Set(Napi::String::New(env, name), obj);
    };

    setMaxMin("hashLength", ARGON2_MAX_OUTLEN, ARGON2_MIN_OUTLEN);
    setMaxMin("memoryCost", ARGON2_MAX_MEMORY, 64 /*ARGON2_MIN_MEMORY*/);
    setMaxMin("timeCost", ARGON2_MAX_TIME, ARGON2_MIN_TIME);
    setMaxMin("parallelism", ARGON2_MAX_LANES, ARGON2_MIN_LANES);

    auto types = Napi::Object::New(env);

    const auto setType = [&](argon2_type type) {
        types.Set(Napi::String::New(env, argon2_type2string(type, false)),
                  Napi::Number::New(env, type));
    };

    setType(Argon2_d);
    setType(Argon2_i);
    setType(Argon2_id);

    auto hashFunc = Napi::Function::New(env, Hash);

    exports.Set(Napi::String::New(env, "limits"), limits);
    exports.Set(Napi::String::New(env, "types"), types);
    exports.Set(Napi::String::New(env, "version"),
            Napi::Number::New(env, ARGON2_VERSION_NUMBER));
    exports.Set(Napi::String::New(env, "hash"), hashFunc);
    return exports;
}

NODE_API_MODULE(argon2_lib, init);
