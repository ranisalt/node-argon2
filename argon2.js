"use strict";
const assert = require("assert");
const { randomBytes, timingSafeEqual } = require("crypto");
const { promisify } = require("util");

const { hash: _hash } = require("./lib/binding/napi-v3/argon2.node");

const { deserialize, serialize } = require("@phc/format");

const types = Object.freeze({ argon2d: 0, argon2i: 1, argon2id: 2 });

const defaults = Object.freeze({
  hashLength: 32,
  saltLength: 16,
  timeCost: 3,
  memoryCost: 1 << 16,
  parallelism: 4,
  type: types.argon2id,
  version: 0x13,
});

const limits = Object.freeze({
  hashLength: { min: 4, max: 2 ** 32 - 1 },
  memoryCost: { min: 1 << 10, max: 2 ** 32 - 1 },
  timeCost: { min: 2, max: 2 ** 32 - 1 },
  parallelism: { min: 1, max: 2 ** 24 - 1 },
});

const names = Object.freeze({
  [types.argon2d]: "argon2d",
  [types.argon2i]: "argon2i",
  [types.argon2id]: "argon2id",
});

const bindingsHash = promisify(_hash);
const generateSalt = promisify(randomBytes);

const assertLimits =
  (options) =>
  ([key, { max, min }]) => {
    const value = options[key];
    assert(
      min <= value && value <= max,
      `Invalid ${key}, must be between ${min} and ${max}.`
    );
  };

const hash = async (plain, { raw, salt, ...options } = {}) => {
  options = { ...defaults, ...options };

  Object.entries(limits).forEach(assertLimits(options));

  salt = salt || (await generateSalt(options.saltLength));

  const hash = await bindingsHash(Buffer.from(plain), salt, options);
  if (raw) {
    return hash;
  }

  const {
    type,
    version,
    memoryCost: m,
    timeCost: t,
    parallelism: p,
    associatedData: data,
  } = options;
  return serialize({
    id: names[type],
    version,
    params: { m, t, p, ...(data ? { data } : {}) },
    salt,
    hash,
  });
};

const needsRehash = (digest, options) => {
  const { memoryCost, timeCost, version } = { ...defaults, ...options };

  const {
    version: v,
    params: { m, t },
  } = deserialize(digest);
  return +v !== +version || +m !== +memoryCost || +t !== +timeCost;
};

const verify = async (digest, plain, options) => {
  const obj = deserialize(digest);
  // Only these have the "params" key, so if the password was encoded
  // using any other method, the destructuring throws an error
  if (!(obj.id in types)) {
    return false;
  }

  const {
    id,
    version = 0x10,
    params: { m, t, p, data },
    salt,
    hash,
  } = obj;

  return timingSafeEqual(
    await bindingsHash(Buffer.from(plain), salt, {
      ...options,
      type: types[id],
      version: +version,
      hashLength: hash.length,
      memoryCost: +m,
      timeCost: +t,
      parallelism: +p,
      ...(data ? { associatedData: Buffer.from(data, "base64") } : {}),
    }),
    hash
  );
};

module.exports = { defaults, limits, hash, needsRehash, verify, ...types };
