#include "argon2/include/argon2.h"
#include <cassert>
#include <cstdint>
#include <napi.h>
#include <vector>

namespace {

class HashWorker final : public Napi::AsyncWorker {
public:
    HashWorker(const Napi::Env &env, const Napi::Buffer<uint8_t> &plain,
               const Napi::Buffer<uint8_t> &salt,
               const Napi::Buffer<uint8_t> &secret,
               const Napi::Buffer<uint8_t> &ad, uint32_t hash_length,
               uint32_t memory_cost, uint32_t time_cost, uint32_t parallelism,
               uint32_t version, uint32_t type)
        : AsyncWorker{env, "argon2:HashWorker"}, deferred{env},
          plain{plain.Data(), plain.Data() + plain.ByteLength()},
          salt{salt.Data(), salt.Data() + salt.ByteLength()},
          secret{secret.Data(), secret.Data() + secret.ByteLength()},
          ad{ad.Data(), ad.Data() + ad.ByteLength()}, hash_length{hash_length},
          memory_cost{memory_cost}, time_cost{time_cost},
          parallelism{parallelism}, version{version},
          type{static_cast<argon2_type>(type)} {}

    Napi::Promise GetPromise() { return deferred.Promise(); }

protected:
    void Execute() override {
        hash.resize(hash_length);

        argon2_context ctx;
        ctx.out = hash.data();
        ctx.outlen = static_cast<uint32_t>(hash.size());
        ctx.pwd = plain.data();
        ctx.pwdlen = static_cast<uint32_t>(plain.size());
        ctx.salt = salt.data();
        ctx.saltlen = static_cast<uint32_t>(salt.size());
        ctx.secret = secret.empty() ? nullptr : secret.data();
        ctx.secretlen = static_cast<uint32_t>(secret.size());
        ctx.ad = ad.empty() ? nullptr : ad.data();
        ctx.adlen = static_cast<uint32_t>(ad.size());
        ctx.m_cost = memory_cost;
        ctx.t_cost = time_cost;
        ctx.lanes = parallelism;
        ctx.threads = parallelism;
        ctx.allocate_cbk = nullptr;
        ctx.free_cbk = nullptr;
        ctx.flags = ARGON2_FLAG_CLEAR_PASSWORD | ARGON2_FLAG_CLEAR_SECRET;
        ctx.version = version;

        if (int result = argon2_ctx(&ctx, type); result != ARGON2_OK) {
            /* LCOV_EXCL_START */
            SetError(argon2_error_message(result));
            /* LCOV_EXCL_STOP */
        }
    }

    void OnOK() override {
        deferred.Resolve(
            Napi::Buffer<uint8_t>::Copy(Env(), hash.data(), hash.size()));
    }

    void OnError(const Napi::Error &err) override {
        deferred.Reject(err.Value());
    }

private:
    using ustring = std::basic_string<uint8_t>;

    Napi::Promise::Deferred deferred;
    ustring hash = {};

    ustring plain;
    ustring salt;
    ustring secret;
    ustring ad;

    uint32_t hash_length;
    uint32_t memory_cost;
    uint32_t time_cost;
    uint32_t parallelism;
    uint32_t version;

    argon2_type type;
};

static Napi::Value Hash(const Napi::CallbackInfo &info) {
    NAPI_CHECK(info.Length() == 1, "Hash", "expected 1 argument");

    const auto &args = info[0].As<Napi::Object>();
    auto worker = new HashWorker{info.Env(),
                                 args["password"].As<Napi::Buffer<uint8_t>>(),
                                 args["salt"].As<Napi::Buffer<uint8_t>>(),
                                 args["secret"].As<Napi::Buffer<uint8_t>>(),
                                 args["data"].As<Napi::Buffer<uint8_t>>(),
                                 args["hashLength"].ToNumber(),
                                 args["m"].ToNumber(),
                                 args["t"].ToNumber(),
                                 args["p"].ToNumber(),
                                 args["version"].ToNumber(),
                                 args["type"].ToNumber()};

    worker->Queue();
    return worker->GetPromise();
}

static Napi::Object init(Napi::Env env, Napi::Object exports) {
    exports["hash"] = Napi::Function::New(env, Hash);
    return exports;
}

} // namespace

NODE_API_MODULE(argon2_lib, init)
