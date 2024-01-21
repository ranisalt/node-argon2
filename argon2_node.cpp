#include "argon2/include/argon2.h"
#include <cassert>
#include <cstdint>
#include <napi.h>
#include <vector>

using ustring = std::vector<uint8_t>;

static ustring from_buffer(const Napi::Value &value) {
    const auto &buf = value.As<Napi::Buffer<uint8_t>>();
    const auto &data = buf.Data();
    return {data, data + buf.Length()};
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
    ctx.pwdlen = static_cast<uint32_t>(plain.size());
    ctx.salt = salt.data();
    ctx.saltlen = static_cast<uint32_t>(salt.size());
    ctx.secret = opts.secret.empty() ? nullptr : opts.secret.data();
    ctx.secretlen = static_cast<uint32_t>(opts.secret.size());
    ctx.ad = opts.ad.empty() ? nullptr : opts.ad.data();
    ctx.adlen = static_cast<uint32_t>(opts.ad.size());
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

class HashWorker final : public Napi::AsyncWorker {
public:
    HashWorker(const Napi::Env &env, ustring &&plain, ustring &&salt,
               Options &&opts)
        : AsyncWorker{env, "argon2:HashWorker"}, deferred{env},
          plain{std::move(plain)}, salt{std::move(salt)},
          opts{std::move(opts)} {}

    Napi::Promise GetPromise() { return deferred.Promise(); }

protected:
    void Execute() override {
        hash = std::make_unique<uint8_t[]>(opts.hash_length);

        auto ctx = make_context(hash.get(), plain, salt, opts);
        int result = argon2_ctx(&ctx, opts.type);

        if (result != ARGON2_OK) {
            /* LCOV_EXCL_START */
            SetError(argon2_error_message(result));
            /* LCOV_EXCL_STOP */
        }
    }

    void OnOK() override {
        deferred.Resolve(
            Napi::Buffer<uint8_t>::Copy(Env(), hash.get(), opts.hash_length));
    }

    void OnError(const Napi::Error &err) override {
        deferred.Reject(err.Value());
    }

private:
    Napi::Promise::Deferred deferred;
    ustring plain;
    ustring salt;
    Options opts;

    std::unique_ptr<uint8_t[]> hash;
};

static Options extract_opts(const Napi::Object &opts) {
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

static Napi::Value Hash(const Napi::CallbackInfo &info) {
    assert(info.Length() == 4 && info[0].IsBuffer() && info[1].IsBuffer() &&
           info[2].IsObject());

    auto worker =
        new HashWorker{info.Env(), from_buffer(info[0]), from_buffer(info[1]),
                       extract_opts(info[2].As<Napi::Object>())};

    worker->Queue();
    return worker->GetPromise();
}

static Napi::Object init(Napi::Env env, Napi::Object exports) {
    exports["hash"] = Napi::Function::New(env, Hash);
    return exports;
}

NODE_API_MODULE(argon2_lib, init)
