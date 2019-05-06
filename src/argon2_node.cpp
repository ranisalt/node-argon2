#include <cassert>
#include <cstdint>
#include <string>

#include <napi.h>
#include "../argon2/include/argon2.h"

using namespace Napi;

#ifndef _MSC_VER
namespace {
#endif

using ustring = std::basic_string<uint8_t>;
const char* type2string(argon2_type type) { return argon2_type2string(type, false); };

ustring from_buffer(const Value& value)
{
    const auto& buf = value.As<Buffer<uint8_t>>();
    return {buf.Data(), buf.Length()};
}

Buffer<uint8_t> to_buffer(const Env& env, const ustring& str)
{
    return Buffer<uint8_t>::Copy(env, str.data(), str.size());
}

struct Options {
    // TODO: remove ctors and initializers when GCC<5 stops shipping
    Options(Options&&) = default;

    ustring ad;

    uint32_t hash_length;
    uint32_t time_cost;
    uint32_t memory_cost;
    uint32_t parallelism;
    uint32_t version;

    argon2_type type;
};

argon2_context make_context(uint8_t* buf, const ustring& plain, const ustring& salt, const Options& opts)
{
    argon2_context ctx;

    ctx.out = buf;
    ctx.outlen = opts.hash_length;
    ctx.pwd = const_cast<uint8_t*>(plain.data());
    ctx.pwdlen = plain.size();
    ctx.salt = const_cast<uint8_t*>(salt.data());
    ctx.saltlen = salt.length();
    ctx.secret = nullptr;
    ctx.secretlen = 0;
    ctx.ad = opts.ad.empty() ? nullptr : const_cast<uint8_t*>(opts.ad.data());
    ctx.adlen = opts.ad.size();
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
    HashWorker(const Function& callback, ustring&& plain, ustring&& salt, Options&& opts):
        // TODO: use brackets when GCC <5 stops shipping
        AsyncWorker(callback, "argon2:HashWorker"),
        plain(std::move(plain)),
        salt(std::move(salt)),
        opts(std::move(opts))
    {}

    void Execute() override
    {
        uint8_t* buf = new uint8_t[opts.hash_length];

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

        delete[] buf;
    }

    void OnOK() override
    {
        const auto& env = Env();
        HandleScope scope{env};
        Callback()({env.Undefined(), to_buffer(env, hash)});
    }

private:
    ustring plain;
    ustring salt;
    Options opts;

    ustring hash;
};

Options extract_opts(const Object& opts)
{
    return {
        opts.Has("associatedData") ? from_buffer(opts["associatedData"]) : ustring{},
        opts["hashLength"].ToNumber(),
        opts["timeCost"].ToNumber(),
        opts["memoryCost"].ToNumber(),
        opts["parallelism"].ToNumber(),
        opts["version"].ToNumber(),
        argon2_type(int(opts["type"].ToNumber())),
    };
}

#ifndef _MSC_VER
}
#endif

Value Hash(const CallbackInfo& info)
{
    assert(info.Length() == 4 and info[0].IsBuffer() and info[1].IsBuffer() and info[2].IsObject() and info[3].IsFunction());

    auto worker = new HashWorker{
        info[3].As<Function>(), from_buffer(info[0]), from_buffer(info[1]), extract_opts(info[2].As<Object>())
    };

    worker->Queue();
    return info.Env().Undefined();
}

Object init(Env env, Object exports)
{
    auto limits = Object::New(env);

    const auto& setMaxMin = [&](const char* name, uint32_t max, uint32_t min) {
        auto obj = Object::New(env);
        obj["max"] = max;
        obj["min"] = min;
        limits[name] = obj;
    };

    setMaxMin("hashLength", ARGON2_MAX_OUTLEN, ARGON2_MIN_OUTLEN);
    setMaxMin("memoryCost", ARGON2_MAX_MEMORY, 64 /*ARGON2_MIN_MEMORY*/);
    setMaxMin("timeCost", ARGON2_MAX_TIME, ARGON2_MIN_TIME);
    setMaxMin("parallelism", ARGON2_MAX_LANES, ARGON2_MIN_LANES);

    auto types = Object::New(env);
    types[type2string(Argon2_d)] = uint32_t(Argon2_d);
    types[type2string(Argon2_i)] = uint32_t(Argon2_i);
    types[type2string(Argon2_id)] = uint32_t(Argon2_id);

    auto names = Object::New(env);
    names[uint32_t(Argon2_d)] = type2string(Argon2_d);
    names[uint32_t(Argon2_i)] = type2string(Argon2_i);
    names[uint32_t(Argon2_id)] = type2string(Argon2_id);

    exports["limits"] = limits;
    exports["types"] = types;
    exports["names"] = names;
    exports["version"] = int(ARGON2_VERSION_NUMBER);
    exports["hash"] = Function::New(env, Hash);
    return exports;
}

NODE_API_MODULE(argon2_lib, init);
