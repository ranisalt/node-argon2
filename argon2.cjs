const { randomBytes, timingSafeEqual } = require("node:crypto");
const { promisify } = require("node:util");
const { deserialize, serialize } = require("@phc/format");
const gypBuild = require("node-gyp-build");

const { hash: bindingsHash } = gypBuild(__dirname);

/** @type {(size: number) => Promise<Buffer>} */
const generateSalt = promisify(randomBytes);

const argon2d = 0;
const argon2i = 1;
const argon2id = 2;

module.exports.argon2d = argon2d;
module.exports.argon2i = argon2i;
module.exports.argon2id = argon2id;

/** @enum {argon2i | argon2d | argon2id} */
const types = Object.freeze({ argon2d, argon2i, argon2id });

/** @enum {'argon2d' | 'argon2i' | 'argon2id'} */
const names = Object.freeze({
  [types.argon2d]: "argon2d",
  [types.argon2i]: "argon2i",
  [types.argon2id]: "argon2id",
});

const defaults = {
  hashLength: 32,
  timeCost: 3,
  memoryCost: 1 << 16,
  parallelism: 4,
  type: argon2id,
  version: 0x13,
};

/**
 * @typedef {Object} Options
 * @property {number} [hashLength=32]
 * @property {number} [timeCost=3]
 * @property {number} [memoryCost=65536]
 * @property {number} [parallelism=4]
 * @property {keyof typeof names} [type=argon2id]
 * @property {number} [version=19]
 * @property {Buffer} [salt]
 * @property {Buffer} [associatedData]
 * @property {Buffer} [secret]
 */

/**
 * Hashes a password with Argon2, producing a raw hash
 *
 * @overload
 * @param {Buffer | string} password The plaintext password to be hashed
 * @param {Options & { raw: true }} options The parameters for Argon2
 * @returns {Promise<Buffer>} The raw hash generated from `password`
 */
/**
 * Hashes a password with Argon2, producing an encoded hash
 *
 * @overload
 * @param {Buffer | string} password The plaintext password to be hashed
 * @param {Options & { raw?: boolean }} [options] The parameters for Argon2
 * @returns {Promise<string>} The encoded hash generated from `password`
 */
/**
 * @param {Buffer | string} password The plaintext password to be hashed
 * @param {Options & { raw?: boolean }} [options] The parameters for Argon2
 */
async function hash(password, options) {
  let { raw, salt, ...rest } = { ...defaults, ...options };

  if (rest.hashLength > 2 ** 32 - 1) {
    throw new RangeError("Hash length is too large");
  }

  if (rest.memoryCost > 2 ** 32 - 1) {
    throw new RangeError("Memory cost is too large");
  }

  if (rest.timeCost > 2 ** 32 - 1) {
    throw new RangeError("Time cost is too large");
  }

  if (rest.parallelism > 2 ** 24 - 1) {
    throw new RangeError("Parallelism is too large");
  }

  salt = salt ?? (await generateSalt(16));

  const {
    hashLength,
    secret = Buffer.alloc(0),
    type,
    version,
    memoryCost: m,
    timeCost: t,
    parallelism: p,
    associatedData: data = Buffer.alloc(0),
  } = rest;

  const hash = await bindingsHash({
    password: Buffer.from(password),
    salt,
    secret,
    data,
    hashLength,
    m,
    t,
    p,
    version,
    type,
  });
  if (raw) {
    return hash;
  }

  return serialize({
    id: names[type],
    version,
    params: { m, t, p, ...(data.byteLength > 0 ? { data } : {}) },
    salt,
    hash,
  });
}
module.exports.hash = hash;

/**
 * @param {string} digest The digest to be checked
 * @param {Object} [options] The current parameters for Argon2
 * @param {number} [options.timeCost=3]
 * @param {number} [options.memoryCost=65536]
 * @param {number} [options.parallelism=4]
 * @param {number} [options.version=0x13]
 * @returns {boolean} `true` if the digest parameters do not match the parameters in `options`, otherwise `false`
 */
function needsRehash(digest, options = {}) {
  const { memoryCost, timeCost, parallelism, version } = {
    ...defaults,
    ...options,
  };

  const {
    version: v,
    params: { m, t, p },
  } = deserialize(digest);

  return (
    +v !== +version ||
    +m !== +memoryCost ||
    +t !== +timeCost ||
    +p !== +parallelism
  );
}
module.exports.needsRehash = needsRehash;

/**
 * @param {string} digest The digest to be checked
 * @param {Buffer | string} password The plaintext password to be verified
 * @param {Object} [options] The current parameters for Argon2
 * @param {Buffer} [options.secret]
 * @returns {Promise<boolean>} `true` if the digest parameters matches the hash generated from `password`, otherwise `false`
 */
async function verify(digest, password, options = {}) {
  const { id, ...rest } = deserialize(digest);
  if (!(id in types)) {
    return false;
  }

  const {
    version = 0x10,
    params: { m, t, p, data = "" },
    salt,
    hash,
  } = rest;

  const { secret = Buffer.alloc(0) } = options;

  return timingSafeEqual(
    await bindingsHash({
      password: Buffer.from(password),
      salt,
      secret,
      data: Buffer.from(data, "base64"),
      hashLength: hash.byteLength,
      m: +m,
      t: +t,
      p: +p,
      version: +version,
      type: types[id],
    }),
    hash,
  );
}
module.exports.verify = verify;
