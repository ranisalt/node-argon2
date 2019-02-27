#include <cassert>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>

#include <napi.h>
#include "../argon2/include/argon2.h"

using namespace Napi;

#ifndef _MSC_VER
namespace {
#endif

struct Options {
    // TODO: remove ctors and initializers when GCC<5 stops shipping
    Options(Options&&) = default;

    Object dump(const std::string& hash, const std::string& salt, const Env& env) const
    {
        auto out = Object::New(env);
        out.Set(String::New(env, "id"), String::New(env, argon2_type2string(type, false)));
        out.Set(String::New(env, "version"), Number::New(env, version));

        auto params = Object::New(env);
        params.Set(String::New(env, "m"), Number::New(env, memory_cost));
        params.Set(String::New(env, "t"), Number::New(env, time_cost));
        params.Set(String::New(env, "p"), Number::New(env, parallelism));
        out.Set(String::New(env, "params"), params);

        out.Set(String::New(env, "salt"), Buffer<char>::Copy(env, salt.c_str(), salt.size()));
        out.Set(String::New(env, "hash"), Buffer<char>::Copy(env, hash.c_str(), hash.size()));
        return out;
    }

    uint32_t hash_length;
    uint32_t time_cost;
    uint32_t memory_cost;
    uint32_t parallelism;
    uint32_t version;

    argon2_type type;
};

argon2_context make_context(char* buf, const std::string& plain, const std::string& salt, const Options& opts)
{
    argon2_context ctx;

    ctx.out = reinterpret_cast<uint8_t*>(buf);
    ctx.outlen = opts.hash_length;
    ctx.pwd = reinterpret_cast<uint8_t*>(const_cast<char*>(plain.data()));
    ctx.pwdlen = plain.size();
    ctx.salt = reinterpret_cast<uint8_t*>(const_cast<char*>(salt.data()));
    ctx.saltlen = salt.size();
    ctx.secret = nullptr;
    ctx.secretlen = 0;
    ctx.ad = nullptr;
    ctx.adlen = 0;
    ctx.t_cost = opts.time_cost;
    ctx.m_cost = opts.memory_cost;
    ctx.lanes = opts.parallelism;
    ctx.threads = opts.parallelism;
    ctx.allocate_cbk = nullptr;
    ctx.free_cbk = nullptr;
    ctx.flags = ARGON2_DEFAULT_FLAGS;
    ctx.version = opts.version;

    return ctx;
}

class HashWorker final: public AsyncWorker {
public:
    HashWorker(const Function& callback, std::string&& plain, std::string&& salt, Options&& opts):
        // TODO: use brackets when GCC <5 stops shipping
        AsyncWorker(callback, "argon2:HashWorker"),
        plain(std::move(plain)),
        salt(std::move(salt)),
        opts(std::move(opts))
    {}

    void Execute() override
    {
#ifdef _MSC_VER
        char* buf = new char[opts.hash_length];
#else
        char buf[opts.hash_length];
#endif

        auto ctx = make_context(buf, plain, salt, opts);
        int result = argon2_ctx(&ctx, opts.type);

        if (result != ARGON2_OK) {
            /* LCOV_EXCL_START */
            SetError(argon2_error_message(result));
            /* LCOV_EXCL_STOP */
        } else {
            hash.assign(buf, opts.hash_length);
        }

        std::fill_n(buf, opts.hash_length, 0);

#ifdef _MSC_VER
        delete[] buf;
#endif
    }

    void OnOK() override
    {
        const auto& env = Env();
        HandleScope scope{env};
        Callback().Call({env.Undefined(), opts.dump(hash, salt, env)});
    }

private:
    std::string plain;
    std::string salt;
    Options opts;

    std::string hash;
};

Value from_object(const Object& object, const char* key)
{
    return object.Get(Value::From(object.Env(), key));
}

std::string buffer_to_string(const Value& value)
{
    const auto& buffer = value.As<Buffer<char>>();
    return {buffer.Data(), buffer.Length()};
}

Options extract_opts(const Object& opts)
{
    return {
        from_object(opts, "hashLength").ToNumber(),
        from_object(opts, "timeCost").ToNumber(),
        from_object(opts, "memoryCost").ToNumber(),
        from_object(opts, "parallelism").ToNumber(),
        from_object(opts, "version").ToNumber(),
        static_cast<argon2_type>(int(from_object(opts, "type").ToNumber())),
    };
}

#ifndef _MSC_VER
}
#endif

Value Hash(const CallbackInfo& info)
{
    assert(info.Length() == 4 and info[0].IsBuffer() and info[1].IsBuffer() and info[2].IsObject() and info[3].IsFunction());

    std::string plain = buffer_to_string(info[0]);
    std::string salt = buffer_to_string(info[1]);
    const auto& opts = info[2].As<Object>();
    auto callback = info[3].As<Function>();

    auto worker = new HashWorker{
        callback, std::move(plain), std::move(salt), extract_opts(opts)
    };

    worker->Queue();
    return info.Env().Undefined();
}

Object init(Env env, Object exports)
{
    auto limits = Object::New(env);

    const auto& setMaxMin = [&](const char* name, uint32_t max, uint32_t min) {
        auto obj = Object::New(env);
        obj.Set(String::New(env, "max"), Number::New(env, max));
        obj.Set(String::New(env, "min"), Number::New(env, min));
        limits.Set(String::New(env, name), obj);
    };

    setMaxMin("hashLength", ARGON2_MAX_OUTLEN, ARGON2_MIN_OUTLEN);
    setMaxMin("memoryCost", ARGON2_MAX_MEMORY, 64 /*ARGON2_MIN_MEMORY*/);
    setMaxMin("timeCost", ARGON2_MAX_TIME, ARGON2_MIN_TIME);
    setMaxMin("parallelism", ARGON2_MAX_LANES, ARGON2_MIN_LANES);

    auto types = Object::New(env);

    const auto& setType = [&](argon2_type type) {
        types.Set(String::New(env, argon2_type2string(type, false)), Number::New(env, type));
    };

    setType(Argon2_d);
    setType(Argon2_i);
    setType(Argon2_id);

    exports.Set(String::New(env, "limits"), limits);
    exports.Set(String::New(env, "types"), types);
    exports.Set(String::New(env, "version"), Number::New(env, ARGON2_VERSION_NUMBER));
    exports.Set(String::New(env, "hash"), Function::New(env, Hash));
    return exports;
}

NODE_API_MODULE(argon2_lib, init);
