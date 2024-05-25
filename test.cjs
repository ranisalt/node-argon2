const assert = require("node:assert/strict");
const { describe, it } = require("node:test");
const argon2 = require("./argon2.cjs");

const { argon2i, argon2d, argon2id, limits } = argon2;

const password = "password";
const salt = Buffer.alloc(16, "salt");
const associatedData = Buffer.alloc(16, "ad");
const secret = Buffer.alloc(16, "secret");

// hashes for argon2i and argon2d with default options
const hashes = {
  argon2id:
    "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$rBWULD5jOGpQy32rLvGcmvQMVqIVNAmrCtekWvUA8bw",
  withNull:
    "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$NqchDOxwWbcBzA+0gtsCtyspEQxqKFf4/PO/AoIvo+Q",
  withAd:
    "$argon2id$v=19$m=65536,t=3,p=4,data=YWRhZGFkYWRhZGFkYWRhZA$c2FsdHNhbHRzYWx0c2FsdA$TEIIM4GBSUxvMLolL9ePXYP5G/qcr0vywQqqm/ILvsM",
  withSecret:
    "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$8dZyo1MdHgdzBm+VU7+tyW06dUO7B9FyaPImH5ejVOU",
  argon2i:
    "$argon2i$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$1Ccmp7ECb+Rb5XPjqRwEuAjCufY1xQDOJwnHrB+orZ4",
  argon2d:
    "$argon2d$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$VtxJNl5Jr/yZ2UIhvfvL4sGPdDQyGCcy45Cs7rIdFq8",
  rawArgon2id: Buffer.from(
    "ac15942c3e63386a50cb7dab2ef19c9af40c56a2153409ab0ad7a45af500f1bc",
    "hex",
  ),
  rawWithNull: Buffer.from(
    "36a7210cec7059b701cc0fb482db02b72b29110c6a2857f8fcf3bf02822fa3e4",
    "hex",
  ),
  rawArgon2i: Buffer.from(
    "d42726a7b1026fe45be573e3a91c04b808c2b9f635c500ce2709c7ac1fa8ad9e",
    "hex",
  ),
  rawArgon2d: Buffer.from(
    "56dc49365e49affc99d94221bdfbcbe2c18f743432182732e390aceeb21d16af",
    "hex",
  ),
  oldFormat:
    "$argon2i$m=4096,t=3,p=1$tbagT6b1YH33niCo9lVzuA$htv/k+OqWk1V9zD9k5DOBi2kcfcZ6Xu3tWmwEPV3/nc",
};

describe("hash", () => {
  it("hash with argon2i", async () => {
    assert.equal(
      hashes.argon2i,
      await argon2.hash(password, { type: argon2i, salt }),
    );
  });

  it("argon2i with raw hash", async () => {
    assert(
      hashes.rawArgon2i.equals(
        await argon2.hash(password, { type: argon2i, raw: true, salt }),
      ),
    );
  });

  it("hash with argon2d", async () => {
    assert.equal(
      hashes.argon2d,
      await argon2.hash(password, { type: argon2d, salt }),
    );
  });

  it("argon2d with raw hash", async () => {
    assert(
      hashes.rawArgon2d.equals(
        await argon2.hash(password, { type: argon2d, raw: true, salt }),
      ),
    );
  });

  it("hash with argon2id", async () => {
    assert.equal(
      hashes.argon2id,
      await argon2.hash(password, { type: argon2id, salt }),
    );
  });

  it("argon2id with raw hash", async () => {
    assert(
      hashes.rawArgon2id.equals(
        await argon2.hash(password, { type: argon2id, raw: true, salt }),
      ),
    );
  });

  it("with null in password", async () => {
    assert.equal(hashes.withNull, await argon2.hash("pass\0word", { salt }));
  });

  it("with raw hash, null in password", async () => {
    assert(
      hashes.rawWithNull.equals(
        await argon2.hash("pass\0word", { raw: true, salt }),
      ),
    );
  });

  it("with associated data", async () => {
    assert.equal(
      hashes.withAd,
      await argon2.hash(password, { associatedData, salt }),
    );
  });

  it("with secret", async () => {
    assert.equal(
      hashes.withSecret,
      await argon2.hash(password, { secret, salt }),
    );
  });
});

describe("set options", () => {
  it("hash with time cost", async () => {
    assert.match(await argon2.hash(password, { timeCost: 4 }), /t=4/);
  });

  it("hash with low time cost", async () => {
    assert.rejects(
      argon2.hash(password, { timeCost: limits.timeCost.min - 1 }),
      /invalid timeCost.+between \d+ and \d+/i,
    );
  });

  it("hash with high time cost", async () => {
    assert.rejects(
      argon2.hash(password, { timeCost: limits.timeCost.max + 1 }),
      /invalid timeCost.+between \d+ and \d+/i,
    );
  });

  it("hash with hash length", async () => {
    // 4 bytes ascii == 6 bytes base64
    assert.match(await argon2.hash(password, { hashLength: 4 }), /\$[^$]{6}$/);
  });

  it("hash with low hash length", async () => {
    assert.rejects(
      argon2.hash(password, { hashLength: limits.hashLength.min - 1 }),
      /invalid hashLength.+between \d+ and \d+/i,
    );
  });

  it("hash with high hash length", async () => {
    assert.rejects(
      argon2.hash(password, { hashLength: limits.hashLength.max + 1 }),
      /invalid hashLength.+between \d+ and \d+/i,
    );
  });

  it("hash with memory cost", async () => {
    assert.match(
      await argon2.hash(password, { memoryCost: 1 << 13 }),
      /m=8192/,
    );
  });

  it("hash with low memory cost", async () => {
    assert.rejects(
      argon2.hash(password, { memoryCost: limits.memoryCost.min / 2 }),
      /invalid memoryCost.+between \d+ and \d+/i,
    );
  });

  it("hash with high memory cost", async () => {
    assert.rejects(
      argon2.hash(password, { memoryCost: limits.memoryCost.max * 2 }),
      /invalid memoryCost.+between \d+ and \d+/i,
    );
  });

  it("hash with parallelism", async () => {
    assert.match(await argon2.hash(password, { parallelism: 2 }), /p=2/);
  });

  it("hash with low parallelism", async () => {
    assert.rejects(
      argon2.hash(password, { parallelism: limits.parallelism.min - 1 }),
      /invalid parallelism.+between \d+ and \d+/i,
    );
  });

  it("hash with high parallelism", async () => {
    assert.rejects(
      argon2.hash(password, { parallelism: limits.parallelism.max + 1 }),
      /invalid parallelism.+between \d+ and \d+/i,
    );
  });

  it("hash with all options", async () => {
    assert.match(
      await argon2.hash(password, {
        timeCost: 4,
        memoryCost: 1 << 13,
        parallelism: 2,
      }),
      /m=8192,t=4,p=2/,
    );
  });
});

describe("needsRehash", () => {
  it("needs rehash old version", async () => {
    const hash = await argon2.hash(password, { version: 0x10 });
    assert(argon2.needsRehash(hash));
    assert(!argon2.needsRehash(hash, { version: 0x10 }));
  });

  it("needs rehash low memory cost", async () => {
    const hash = await argon2.hash(password, { memoryCost: 1 << 15 });
    assert(argon2.needsRehash(hash));
    assert(!argon2.needsRehash(hash, { memoryCost: 1 << 15 }));
  });

  it("needs rehash low time cost", async () => {
    const hash = await argon2.hash(password, { timeCost: 2 });
    assert(argon2.needsRehash(hash));
    assert(!argon2.needsRehash(hash, { timeCost: 2 }));
  });
});

describe("verify", () => {
  it("verify correct password", async () => {
    assert(await argon2.verify(await argon2.hash(password), password));
  });

  it("verify wrong password", async () => {
    assert(!(await argon2.verify(await argon2.hash(password), "passworld")));
  });

  it("verify with null in password", async () => {
    assert(await argon2.verify(await argon2.hash("pass\0word"), "pass\0word"));
  });

  it("verify with associated data", async () => {
    assert(
      await argon2.verify(
        await argon2.hash(password, { associatedData }),
        "password",
      ),
    );
  });

  it("verify with secret", async () => {
    assert(
      await argon2.verify(await argon2.hash(password, { secret }), "password", {
        secret,
      }),
    );
  });

  it("verify with options without secret", async () => {
    // https://github.com/ranisalt/node-argon2/issues/407
    await assert.doesNotReject(
      argon2.verify(await argon2.hash(password, { secret }), "password", {}),
    );
  });

  it("verify argon2d correct password", async () => {
    assert(
      await argon2.verify(
        await argon2.hash(password, { type: argon2d }),
        password,
      ),
    );
  });

  it("verify argon2d wrong password", async () => {
    assert(
      !(await argon2.verify(
        await argon2.hash(password, { type: argon2d }),
        "passworld",
      )),
    );
  });

  it("verify argon2id correct password", async () => {
    assert(
      await argon2.verify(
        await argon2.hash(password, { type: argon2id }),
        password,
      ),
    );
  });

  it("verify argon2id wrong password", async () => {
    assert(
      !(await argon2.verify(
        await argon2.hash(password, { type: argon2id }),
        "passworld",
      )),
    );
  });

  it("verify old hash format", async () => {
    // older hashes did not contain the v (version) parameter
    assert(await argon2.verify(hashes.oldFormat, "password"));
  });

  it("verify invalid hash function", async () => {
    assert(
      !(await argon2.verify(
        "$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW",
        "abc123xyz",
      )),
    );
  });
});
