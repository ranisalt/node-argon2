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
    // TODO: remove ctors and initializers when GCC<5 stops shipping on Ubuntu
    Options(Options&&) = default;

    Object dump(const std::string& hash, const Env& env) const
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

    std::string salt;

    uint32_t hash_length;
    uint32_t time_cost;
    uint32_t memory_cost;
    uint32_t parallelism;
    uint32_t version;

    argon2_type type;
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

class HashWorker final: public AsyncWorker {
public:
    HashWorker(const Function& callback, std::string plain, Options options):
        AsyncWorker{callback, "argon2:HashWorker"},
        plain{std::move(plain)},
        options{std::move(options)}
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
        const auto& env = Env();
        HandleScope scope{env};
        Callback().Call({env.Undefined(), options.dump(hash, env)});
    }

private:
    std::string plain;
    Options options;

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

Options extract_options(const Object& options)
{
    return {
        buffer_to_string(from_object(options, "salt")),
        from_object(options, "hashLength").ToNumber(),
        from_object(options, "timeCost").ToNumber(),
        from_object(options, "memoryCost").ToNumber(),
        from_object(options, "parallelism").ToNumber(),
        from_object(options, "version").ToNumber(),
        static_cast<argon2_type>(int(from_object(options, "type").ToNumber())),
    };
}

#ifndef _MSC_VER
}
#endif

Value Hash(const CallbackInfo& info) {
    assert(info.Length() == 3 and info[0].IsBuffer() and info[1].IsObject() and info[2].IsFunction());

    std::string plain = buffer_to_string(info[0]);
    const auto& options = info[1].As<Object>();
    auto callback = info[2].As<Function>();

    auto worker = new HashWorker{
        callback, std::move(plain), extract_options(options)
    };

    worker->Queue();
    return info.Env().Undefined();
}

Object init(Env env, Object exports) {
    auto limits = Object::New(env);

    const auto setMaxMin = [&](const char* name, uint32_t max, uint32_t min) {
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

    const auto setType = [&](argon2_type type) {
        types.Set(String::New(env, argon2_type2string(type, false)), Number::New(env, type));
    };

    setType(Argon2_d);
    setType(Argon2_i);
    setType(Argon2_id);

    const auto& hashFunc = Function::New(env, Hash);

    exports.Set(String::New(env, "limits"), limits);
    exports.Set(String::New(env, "types"), types);
    exports.Set(String::New(env, "version"), Number::New(env, ARGON2_VERSION_NUMBER));
    exports.Set(String::New(env, "hash"), hashFunc);
    return exports;
}

NODE_API_MODULE(argon2_lib, init);
