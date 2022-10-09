const assert = require("assert").strict;
const argon2 = require("../argon2");
const { argon2i, argon2d, argon2id, defaults, limits } = argon2;
const password = "password";
const salt = Buffer.alloc(16, "salt");
const associatedData = Buffer.alloc(16, "ad");
const secret = Buffer.alloc(16, "secret");

// hashes for argon2i and argon2d with default options
const hashes = Object.freeze({
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
    "hex"
  ),
  rawWithNull: Buffer.from(
    "36a7210cec7059b701cc0fb482db02b72b29110c6a2857f8fcf3bf02822fa3e4",
    "hex"
  ),
  rawArgon2i: Buffer.from(
    "d42726a7b1026fe45be573e3a91c04b808c2b9f635c500ce2709c7ac1fa8ad9e",
    "hex"
  ),
  rawArgon2d: Buffer.from(
    "56dc49365e49affc99d94221bdfbcbe2c18f743432182732e390aceeb21d16af",
    "hex"
  ),
  oldFormat:
    "$argon2i$m=4096,t=3,p=1$tbagT6b1YH33niCo9lVzuA$htv/k+OqWk1V9zD9k5DOBi2kcfcZ6Xu3tWmwEPV3/nc",
});

describe("Argon2", () => {
  describe("hash", () => {
    it("hash with argon2i", async () => {
      const hash = await argon2.hash(password, { type: argon2i, salt });
      assert.equal(hashes.argon2i, hash);
    });

    it("argon2i with raw hash", async () => {
      const hash = await argon2.hash(password, {
        type: argon2i,
        raw: true,
        salt,
      });
      assert(hashes.rawArgon2i.equals(hash));
    });

    it("hash with argon2d", async () => {
      const hash = await argon2.hash(password, { type: argon2d, salt });
      assert.equal(hashes.argon2d, hash);
    });

    it("argon2d with raw hash", async () => {
      const hash = await argon2.hash(password, {
        type: argon2d,
        raw: true,
        salt,
      });
      assert(hashes.rawArgon2d.equals(hash));
    });

    it("hash with argon2id", async () => {
      const hash = await argon2.hash(password, { type: argon2id, salt });
      assert.equal(hashes.argon2id, hash);
    });

    it("argon2id with raw hash", async () => {
      const hash = await argon2.hash(password, {
        type: argon2id,
        raw: true,
        salt,
      });
      assert(hashes.rawArgon2id.equals(hash));
    });

    it("with null in password", async () => {
      const hash = await argon2.hash("pass\0word", { salt });
      assert.equal(hashes.withNull, hash);
    });

    it("with raw hash, null in password", async () => {
      const hash = await argon2.hash("pass\0word", {
        raw: true,
        salt,
      });
      assert(hashes.rawWithNull.equals(hash));
    });

    it("with associated data", async () => {
      const hash = await argon2.hash(password, {
        associatedData,
        salt,
      });
      assert.equal(hashes.withAd, hash);
    });

    it("with secret", async () => {
      const hash = await argon2.hash(password, {
        secret,
        salt,
      });
      assert.equal(hashes.withSecret, hash);
    });
  });

  describe("set options", () => {
    it("hash with time cost", async () => {
      const hash = await argon2.hash(password, { timeCost: 4 });
      assert(/t=4/.test(hash));
    });

    it("hash with low time cost", async () => {
      try {
        await argon2.hash(password, { timeCost: limits.timeCost.min - 1 });
        assert.fail("This test should fail");
      } catch (err) {
        assert(/invalid timeCost.+between \d+ and \d+/i.test(err.message));
      }
    });

    it("hash with high time cost", async () => {
      try {
        await argon2.hash(password, { timeCost: limits.timeCost.max + 1 });
        assert.fail("This test should fail");
      } catch (err) {
        assert(/invalid timeCost.+between \d+ and \d+/i.test(err.message));
      }
    });

    it("hash with hash length", async () => {
      // 4 bytes ascii == 6 bytes base64
      const hash = await argon2.hash(password, { hashLength: 4 });
      assert(/\$[^$]{6}$/.test(hash));
    });

    it("hash with low hash length", async () => {
      try {
        await argon2.hash(password, { hashLength: limits.hashLength.min - 1 });
        assert.fail("This test should fail");
      } catch (err) {
        assert(/invalid hashLength.+between \d+ and \d+/i.test(err.message));
      }
    });

    it("hash with high hash length", async () => {
      try {
        await argon2.hash(password, { hashLength: limits.hashLength.max + 1 });
        assert.fail("This test should fail");
      } catch (err) {
        assert(/invalid hashLength.+between \d+ and \d+/i.test(err.message));
      }
    });

    it("hash with memory cost", async () => {
      const hash = await argon2.hash(password, { memoryCost: 1 << 13 });
      assert(/m=8192/.test(hash));
    });

    it("hash with low memory cost", async () => {
      try {
        await argon2.hash(password, { memoryCost: limits.memoryCost.min / 2 });
        assert.fail("This test should fail");
      } catch (err) {
        assert(/invalid memoryCost.+between \d+ and \d+/i.test(err.message));
      }
    });

    it("hash with high memory cost", async () => {
      try {
        await argon2.hash(password, { memoryCost: limits.memoryCost.max * 2 });
        assert.fail("This test should fail");
      } catch (err) {
        assert(/invalid memoryCost.+between \d+ and \d+/i.test(err.message));
      }
    });

    it("hash with parallelism", async () => {
      const hash = await argon2.hash(password, { parallelism: 2 });
      assert(/p=2/.test(hash));
    });

    it("hash with low parallelism", async () => {
      try {
        await await argon2.hash(password, {
          parallelism: limits.parallelism.min - 1,
        });
        assert.fail("This test should fail");
      } catch (err) {
        assert(/invalid parallelism.+between \d+ and \d+/i.test(err.message));
      }
    });

    it("hash with high parallelism", async () => {
      try {
        await argon2.hash(password, {
          parallelism: limits.parallelism.max + 1,
        });
        assert.fail("This test should fail");
      } catch (err) {
        assert(/invalid parallelism.+between \d+ and \d+/i.test(err.message));
      }
    });

    it("hash with all options", async () => {
      const hash = await argon2.hash(password, {
        timeCost: 4,
        memoryCost: 1 << 13,
        parallelism: 2,
      });
      assert(/m=8192,t=4,p=2/.test(hash));
    });
  });

  describe("needsRehash", () => {
    it("needs rehash old version", async () => {
      const hash = await argon2.hash(password, { version: 0x10 });
      assert(argon2.needsRehash(hash));
      assert(!argon2.needsRehash(hash, { version: 0x10 }));
    });

    it("needs rehash low memory cost", async () => {
      const hash = await argon2.hash(password, {
        memoryCost: defaults.memoryCost / 2,
      });
      assert(argon2.needsRehash(hash));
      assert(
        !argon2.needsRehash(hash, { memoryCost: defaults.memoryCost / 2 })
      );
    });

    it("needs rehash low time cost", async () => {
      const hash = await argon2.hash(password, {
        timeCost: defaults.timeCost - 1,
      });
      assert(argon2.needsRehash(hash));
      assert(!argon2.needsRehash(hash, { timeCost: defaults.timeCost - 1 }));
    });
  });

  describe("verify", () => {
    it("verify correct password", async () => {
      const hash = await argon2.hash(password);
      assert(await argon2.verify(hash, password));
    });

    it("verify wrong password", async () => {
      const hash = await argon2.hash(password);
      assert(!(await argon2.verify(hash, "passworld")));
    });

    it("verify with null in password", async () => {
      const hash = await argon2.hash("pass\0word");
      assert(await argon2.verify(hash, "pass\0word"));
    });

    it("verify with associated data", async () => {
      const hash = await argon2.hash(password, { associatedData });
      assert(await argon2.verify(hash, "password"));
    });

    it("verify with secret", async () => {
      const hash = await argon2.hash(password, { secret });
      assert(await argon2.verify(hash, "password", { secret }));
    });

    it("verify argon2d correct password", async () => {
      const hash = await argon2.hash(password, { type: argon2d });
      assert(await argon2.verify(hash, password));
    });

    it("verify argon2d wrong password", async () => {
      const hash = await argon2.hash(password, { type: argon2d });
      assert(!(await argon2.verify(hash, "passworld")));
    });

    it("verify argon2id correct password", async () => {
      const hash = await argon2.hash(password, { type: argon2id });
      assert(await argon2.verify(hash, password));
    });

    it("verify argon2id wrong password", async () => {
      const hash = await argon2.hash(password, { type: argon2id });
      assert(!(await argon2.verify(hash, "passworld")));
    });

    it("verify old hash format", async () => {
      // older hashes did not contain the v (version) parameter
      assert(await argon2.verify(hashes.oldFormat, "password"));
    });
  });
});
