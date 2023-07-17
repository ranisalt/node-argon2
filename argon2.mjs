import assert from "node:assert";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { deserialize, serialize } from "@phc/format";
import gypBuild from "node-gyp-build";

const { hash: _hash } = gypBuild(fileURLToPath(new URL(".", import.meta.url)));

const bindingsHash = promisify(_hash);

/** @type {(size: number) => Promise<Buffer>} */
const generateSalt = promisify(randomBytes);

export const argon2d = 0;
export const argon2i = 1;
export const argon2id = 2;

/** @enum {argon2i | argon2d | argon2id} */
const types = Object.freeze({ argon2d, argon2i, argon2id });

/** @enum {'argon2d' | 'argon2i' | 'argon2id'} */
const names = Object.freeze({
  [types.argon2d]: "argon2d",
  [types.argon2i]: "argon2i",
  [types.argon2id]: "argon2id",
});

const defaults = Object.freeze({
  hashLength: 32,
  saltLength: 16,
  timeCost: 3,
  memoryCost: 1 << 16,
  parallelism: 4,
  type: argon2id,
  version: 0x13,
});

export const limits = Object.freeze({
  hashLength: { min: 4, max: 2 ** 32 - 1 },
  memoryCost: { min: 1 << 10, max: 2 ** 32 - 1 },
  timeCost: { min: 2, max: 2 ** 32 - 1 },
  parallelism: { min: 1, max: 2 ** 24 - 1 },
});

/**
 * @typedef {object} Options
 * @property {number} [hashLength=32]
 * @property {number} [timeCost=3]
 * @property {number} [memoryCost=65536]
 * @property {number} [parallelism=4]
 * @property {number} [saltLength=16]
 * @property {keyof typeof names} [type=argon2id]
 * @property {number} [version=19]
 * @property {Buffer} [salt]
 * @property {Buffer} [associatedData]
 * @property {Buffer} [secret]
 */

/**>
 * Hashes a password with Argon2, producing a raw hash
 *
 * @overload
 * @param {Buffer | string} plain The plaintext password to be hashed
 * @param {Options & { raw: true }} options The parameters for Argon2
 * @return {Promise<Buffer>} The raw hash generated from `plain`
 */
/**
 * Hashes a password with Argon2, producing an encoded hash
 *
 * @overload
 * @param {Buffer | string} plain The plaintext password to be hashed
 * @param {Options & { raw?: boolean }} [options] The parameters for Argon2
 * @return {Promise<string>} The encoded hash generated from `plain`
 */
/**
 * @param {Buffer | string} plain
 * @param {Options & { raw?: boolean }} options
 * @returns {Promise<Buffer | string>}
 */
export async function hash(plain, options) {
  const { raw, salt, saltLength, ...rest } = { ...defaults, ...options };

  for (const [key, { min, max }] of Object.entries(limits)) {
    const value = rest[key];
    assert(
      min <= value && value <= max,
      `Invalid ${key}, must be between ${min} and ${max}.`,
    );
  }

  const salt_ = salt ?? (await generateSalt(saltLength));

  const hash = await bindingsHash(Buffer.from(plain), salt_, rest);
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
  } = rest;

  return serialize({
    id: names[type],
    version,
    params: { m, t, p, ...(data ? { data } : {}) },
    salt: salt_,
    hash,
  });
}

/**
 * @param {string} digest The digest to be checked
 * @param {Options} [options] The current parameters for Argon2
 * @return {boolean} `true` if the digest parameters do not match the parameters in `options`, otherwise `false`
 */
export function needsRehash(digest, options) {
  const { memoryCost, timeCost, version } = { ...defaults, ...options };

  const {
    version: v,
    params: { m, t },
  } = deserialize(digest);

  return +v !== +version || +m !== +memoryCost || +t !== +timeCost;
}

/**
 * @param {string} digest The digest to be checked
 * @param {Buffer | string} plain The plaintext password to be verified
 * @param {Options} [options] The current parameters for Argon2
 * @return {Promise<boolean>} `true` if the digest parameters matches the hash generated from `plain`, otherwise `false`
 */
export async function verify(digest, plain, options) {
  const {
    id,
    version = 0x10,
    params: { m, t, p, data },
    salt,
    hash,
  } = deserialize(digest);

  // Only "types" have the "params" key, so if the password was encoded
  // using any other method, the destructuring throws an error
  return (
    id in types &&
    timingSafeEqual(
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
      hash,
    )
  );
}
