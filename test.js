import * as argon2 from "./argon2.js";
import { describe, it } from "node:test";
import assert from "node:assert/strict";

const password = "password";
const salt = Buffer.alloc(16, "salt");
const associatedData = Buffer.alloc(16, "ad");
const secret = Buffer.alloc(16, "secret");

// Hashes for argon2i and argon2d with default options
const hashes = {
  argon2d:
    "$argon2d$v=19$m=65536,p=4,t=3$c2FsdHNhbHRzYWx0c2FsdA$VtxJNl5Jr/yZ2UIhvfvL4sGPdDQyGCcy45Cs7rIdFq8",
  argon2i:
    "$argon2i$v=19$m=65536,p=4,t=3$c2FsdHNhbHRzYWx0c2FsdA$1Ccmp7ECb+Rb5XPjqRwEuAjCufY1xQDOJwnHrB+orZ4",
  argon2id:
    "$argon2id$v=19$m=65536,p=4,t=3$c2FsdHNhbHRzYWx0c2FsdA$rBWULD5jOGpQy32rLvGcmvQMVqIVNAmrCtekWvUA8bw",
  oldFormat:
    "$argon2i$m=4096,p=1,t=3$tbagT6b1YH33niCo9lVzuA$htv/k+OqWk1V9zD9k5DOBi2kcfcZ6Xu3tWmwEPV3/nc",
  withAd:
    "$argon2id$v=19$m=65536,p=4,t=3,data=YWRhZGFkYWRhZGFkYWRhZA$c2FsdHNhbHRzYWx0c2FsdA$TEIIM4GBSUxvMLolL9ePXYP5G/qcr0vywQqqm/ILvsM",
  withNull:
    "$argon2id$v=19$m=65536,p=4,t=3$c2FsdHNhbHRzYWx0c2FsdA$NqchDOxwWbcBzA+0gtsCtyspEQxqKFf4/PO/AoIvo+Q",
  withSecret:
    "$argon2id$v=19$m=65536,p=4,t=3$c2FsdHNhbHRzYWx0c2FsdA$8dZyo1MdHgdzBm+VU7+tyW06dUO7B9FyaPImH5ejVOU",
};

describe("hash", () => {
  it("hash with argon2i", async () => {
    assert.equal(hashes.argon2i, await argon2.hash(password, { salt, type: "argon2i" }));
  });

  it("hash with argon2d", async () => {
    assert.equal(hashes.argon2d, await argon2.hash(password, { salt, type: "argon2d" }));
  });

  it("hash with argon2id", async () => {
    assert.equal(hashes.argon2id, await argon2.hash(password, { salt, type: "argon2id" }));
  });

  it("with null in password", async () => {
    assert.equal(hashes.withNull, await argon2.hash("pass\0word", { salt }));
  });

  it("with associated data", async () => {
    assert.equal(hashes.withAd, await argon2.hash(password, { associatedData, salt }));
  });

  it("with secret", async () => {
    assert.equal(hashes.withSecret, await argon2.hash(password, { salt, secret }));
  });
});

describe("set options", () => {
  it("hash with time cost", async () => {
    assert.match(await argon2.hash(password, { timeCost: 4 }), /t=4/u);
  });

  it("hash with high time cost", () => {
    assert.rejects(
      argon2.hash(password, { timeCost: Number.MAX_SAFE_INTEGER }),
      RangeError,
      "Time cost is too large",
    );
  });

  it("hash with hash length", async () => {
    // 4 bytes ascii == 6 bytes base64
    assert.match(await argon2.hash(password, { hashLength: 4 }), /\$[^$]{6}$/u);
  });

  it("hash with high hash length", () => {
    assert.rejects(
      argon2.hash(password, { hashLength: Number.MAX_SAFE_INTEGER }),
      RangeError,
      "Hash length is too large",
    );
  });

  it("hash with memory cost", async () => {
    assert.match(await argon2.hash(password, { memoryCost: 1 << 13 }), /m=8192/u);
  });

  it("hash with high memory cost", () => {
    assert.rejects(
      argon2.hash(password, { memoryCost: Number.MAX_SAFE_INTEGER }),
      RangeError,
      "Memory cost is too large",
    );
  });

  it("hash with parallelism", async () => {
    assert.match(await argon2.hash(password, { parallelism: 2 }), /p=2/u);
  });

  it("hash with high parallelism", () => {
    assert.rejects(
      argon2.hash(password, { parallelism: Number.MAX_SAFE_INTEGER }),
      RangeError,
      "Parallelism is too large",
    );
  });

  it("hash with all options", async () => {
    assert.match(
      await argon2.hash(password, {
        memoryCost: 1 << 13,
        parallelism: 2,
        timeCost: 4,
      }),
      /m=8192,p=2,t=4/u,
    );
  });
});

describe("needsRehash", () => {
  it("needs rehash low memory cost", async () => {
    const hash = await argon2.hash(password, { memoryCost: 1 << 15 });
    assert.equal(argon2.needsRehash(hash), true);
    assert.equal(argon2.needsRehash(hash, { memoryCost: 1 << 15 }), false);
  });

  it("needs rehash low time cost", async () => {
    const hash = await argon2.hash(password, { timeCost: 2 });
    assert.equal(argon2.needsRehash(hash), true);
    assert.equal(argon2.needsRehash(hash, { timeCost: 2 }), false);
  });
});

describe("verify", () => {
  it("verify correct password", async () => {
    assert.equal(await argon2.verify(await argon2.hash(password), password), true);
  });

  it("verify wrong password", async () => {
    assert.equal(await argon2.verify(await argon2.hash(password), "passworld"), false);
  });

  it("verify with null in password", async () => {
    assert.equal(await argon2.verify(await argon2.hash("pass\0word"), "pass\0word"), true);
  });

  it("verify with associated data", async () => {
    assert.equal(
      await argon2.verify(await argon2.hash(password, { associatedData }), "password"),
      true,
    );
  });

  it("verify with secret", async () => {
    assert.equal(
      await argon2.verify(await argon2.hash(password, { secret }), "password", {
        secret,
      }),
      true,
    );
  });

  it("verify with options without secret", async () => {
    // https://github.com/ranisalt/node-argon2/issues/407
    await assert.doesNotReject(
      argon2.verify(await argon2.hash(password, { secret }), "password", {}),
    );
  });

  it("verify argon2d correct password", async () => {
    assert.equal(
      await argon2.verify(await argon2.hash(password, { type: "argon2d" }), password),
      true,
    );
  });

  it("verify argon2d wrong password", async () => {
    assert.equal(
      await argon2.verify(await argon2.hash(password, { type: "argon2d" }), "passworld"),
      false,
    );
  });

  it("verify argon2id correct password", async () => {
    assert.equal(
      await argon2.verify(await argon2.hash(password, { type: "argon2id" }), password),
      true,
    );
  });

  it("verify argon2id wrong password", async () => {
    assert.equal(
      await argon2.verify(await argon2.hash(password, { type: "argon2id" }), "passworld"),
      false,
    );
  });

  it("verify invalid hash function", async () => {
    assert.equal(
      await argon2.verify(
        "$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW",
        "abc123xyz",
      ),
      false,
    );
  });
});
