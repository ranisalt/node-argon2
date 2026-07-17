import { argon2, randomBytes, timingSafeEqual } from "node:crypto";
import { deserialize, serialize } from "@phc/format";
import { promisify } from "node:util";

const fn = promisify(argon2);
const generateSalt = promisify(randomBytes);

export const argon2d = "argon2d";
export const argon2i = "argon2i";
export const argon2id = "argon2id";

/** @type {Set<import("node:crypto").Argon2Algorithm>} */
const types = new Set([argon2d, argon2i, argon2id]);

const defaults = Object.freeze({
  hashLength: 32,
  memoryCost: 1 << 16,
  parallelism: 4,
  timeCost: 3,
  type: argon2id,
});

/**
 * Hashes a password with Argon2, producing an encoded hash
 *
 * @param {Buffer | string} password The plaintext password to be hashed
 * @param {Object} [options] The parameters for Argon2
 * @param {number} [options.hashLength=32]
 * @param {number} [options.timeCost=3]
 * @param {number} [options.memoryCost=65536]
 * @param {number} [options.parallelism=4]
 * @param {import("node:crypto").Argon2Algorithm} [options.type=argon2id]
 * @param {Buffer} [options.salt]
 * @param {Buffer} [options.associatedData]
 * @param {Buffer} [options.secret]
 * @returns {Promise<string>} The encoded hash generated from `password`
 */
export const hash = async (password, options) => {
  const {
    hashLength,
    timeCost,
    secret = Buffer.alloc(0),
    type,
    memoryCost,
    parallelism,
    salt,
    associatedData = Buffer.alloc(0),
  } = { ...defaults, ...options };

  if (hashLength > 2 ** 32 - 1) {
    throw new RangeError("Hash length is too large");
  }

  if (memoryCost > 2 ** 32 - 1) {
    throw new RangeError("Memory cost is too large");
  }

  if (timeCost > 2 ** 32 - 1) {
    throw new RangeError("Time cost is too large");
  }

  if (parallelism > 2 ** 24 - 1) {
    throw new RangeError("Parallelism is too large");
  }

  const nonce = salt ?? (await generateSalt(16));

  const derivedKey = await fn(type, {
    associatedData,
    memory: memoryCost,
    message: password,
    nonce,
    parallelism,
    passes: timeCost,
    secret,
    tagLength: hashLength,
  });

  /** @type {{ m: number, p: number, t: number, data?: Buffer }} */
  const params = { m: memoryCost, p: parallelism, t: timeCost };
  if (associatedData.byteLength > 0) {
    params.data = associatedData;
  }

  return serialize({ hash: derivedKey, id: type, params, salt: nonce, version: 0x13 });
};

/**
 * @param {string} digest The digest to be checked
 * @param {Object} [options] The current parameters for Argon2
 * @param {number} [options.timeCost=3]
 * @param {number} [options.memoryCost=65536]
 * @param {number} [options.parallelism=4]
 * @returns {boolean} `true` if the digest parameters do not match the parameters in `options`, otherwise `false`
 */
export const needsRehash = (digest, options = {}) => {
  const { memoryCost, timeCost, parallelism } = {
    ...defaults,
    ...options,
  };

  const {
    version: v,
    params: { m, t, p },
  } = deserialize(digest);

  return v !== 0x13 || m !== memoryCost || t !== timeCost || p !== parallelism;
};

/**
 * @param {string} digest The digest to be checked
 * @param {Buffer | string} password The plaintext password to be verified
 * @param {Object} [options] The current parameters for Argon2
 * @param {Buffer} [options.secret]
 * @returns {Promise<boolean>} `true` if the digest parameters matches the hash generated from `password`, otherwise `false`
 */
export const verify = async (digest, password, options = {}) => {
  const { id, ...rest } = deserialize(digest);
  if (!types.has(id)) {
    return false;
  }

  const {
    version,
    params: { m, t, p, data = "" },
    salt,
    hash: actual,
  } = rest;

  if (version !== 0x13) {
    return false;
  }

  const { secret = Buffer.alloc(0) } = options;

  const derivedKey = await fn(id, {
    associatedData: Buffer.from(data, "base64"),
    memory: Number(m),
    message: password,
    nonce: salt,
    parallelism: Number(p),
    passes: Number(t),
    secret,
    tagLength: actual.byteLength,
  });

  return timingSafeEqual(derivedKey, actual);
};
