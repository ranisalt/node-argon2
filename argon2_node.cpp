
#include "argon2/include/argon2.h"
#include <cassert>
#include <cstdint>
#include <napi.h>
#include <vector>

using namespace Napi;
using ustring = std::vector<uint8_t>;

static ustring from_buffer(const Value &value) {
    const auto &buf = value.As<Buffer<uint8_t>>();
    const auto &data = buf.Data();
    return {data, data + buf.Length()};
}

static Buffer<uint8_t> to_buffer(const Env &env, const ustring &str) {
    return Buffer<uint8_t>::Copy(env, str.data(), str.size());
}

struct Options {
    ustring secret;
    ustring ad;

    uint32_t hash_length;
    uint32_t time_cost;
    uint32_t memory_cost;
    uint32_t parallelism;
    uint32_t version;

    argon2_type type;
};

static argon2_context make_context(uint8_t *buf, ustring &plain, ustring &salt,
                                   Options &opts) {
    argon2_context ctx;

    ctx.out = buf;
    ctx.outlen = opts.hash_length;
    ctx.pwd = plain.data();
    ctx.pwdlen = plain.size();
    ctx.salt = salt.data();
    ctx.saltlen = salt.size();
    ctx.secret = opts.secret.empty() ? nullptr : opts.secret.data();
    ctx.secretlen = opts.secret.size();
    ctx.ad = opts.ad.empty() ? nullptr : opts.ad.data();
    ctx.adlen = opts.ad.size();
    ctx.t_cost = opts.time_cost;
    ctx.m_cost = opts.memory_cost;
    ctx.lanes = opts.parallelism;
    ctx.threads = opts.parallelism;
    ctx.allocate_cbk = nullptr;
    ctx.free_cbk = nullptr;
    ctx.flags = ARGON2_FLAG_CLEAR_PASSWORD | ARGON2_FLAG_CLEAR_SECRET;
    ctx.version = opts.version;

    return ctx;
}

class HashWorker final : public AsyncWorker {
public:
    HashWorker(const Function &callback, ustring &&plain, ustring &&salt,
               Options &&opts)
        : AsyncWorker{callback, "argon2:HashWorker"}, plain{std::move(plain)},
          salt{std::move(salt)}, opts{std::move(opts)} {}

    void Execute() override {
        auto buf = std::make_unique<uint8_t[]>(opts.hash_length);

        auto ctx = make_context(buf.get(), plain, salt, opts);
        int result = argon2_ctx(&ctx, opts.type);

        if (result != ARGON2_OK) {
            /* LCOV_EXCL_START */
            SetError(argon2_error_message(result));
            /* LCOV_EXCL_STOP */
        } else {
            hash.assign(buf.get(), buf.get() + opts.hash_length);
        }
    }

    void OnOK() override {
        const auto &env = Env();
        HandleScope scope{env};
        Callback()({env.Undefined(), to_buffer(env, hash)});
    }

private:
    ustring plain;
    ustring salt;
    Options opts;

    ustring hash;
};

static Options extract_opts(const Object &opts) {
    return {
        opts.Has("secret") ? from_buffer(opts["secret"]) : ustring{},
        opts.Has("associatedData") ? from_buffer(opts["associatedData"])
                                   : ustring{},
        opts["hashLength"].ToNumber(),
        opts["timeCost"].ToNumber(),
        opts["memoryCost"].ToNumber(),
        opts["parallelism"].ToNumber(),
        opts["version"].ToNumber(),
        argon2_type(int(opts["type"].ToNumber())),
    };
}

static Value Hash(const CallbackInfo &info) {
    assert(info.Length() == 4 && info[0].IsBuffer() && info[1].IsBuffer() &&
           info[2].IsObject() && info[3].IsFunction());

    auto worker = new HashWorker{info[3].As<Function>(), from_buffer(info[0]),
                                 from_buffer(info[1]),
                                 extract_opts(info[2].As<Object>())};

    worker->Queue();
    return info.Env().Undefined();
}

static Object init(Env env, Object exports) {
    exports["hash"] = Function::New(env, Hash);
    return exports;
}

NODE_API_MODULE(argon2_lib, init);
