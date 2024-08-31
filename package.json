{
  "name": "argon2",
  "version": "0.41.1",
  "description": "An Argon2 library for Node",
  "keywords": [
    "argon2",
    "crypto",
    "encryption",
    "hashing",
    "password"
  ],
  "homepage": "https://github.com/ranisalt/node-argon2#readme",
  "bugs": {
    "url": "https://github.com/ranisalt/node-argon2/issues"
  },
  "repository": {
    "type": "git",
    "url": "https://github.com/ranisalt/node-argon2.git"
  },
  "license": "MIT",
  "author": "Ranieri Althoff <ranisalt+argon2@gmail.com>",
  "type": "commonjs",
  "main": "argon2.cjs",
  "types": "argon2.d.cts",
  "files": [
    "argon2.cpp",
    "argon2.d.cts",
    "argon2.d.cts.map",
    "binding.gyp",
    "argon2/CHANGELOG.md",
    "argon2/LICENSE",
    "argon2/include/",
    "argon2/src/blake2/",
    "argon2/src/argon2.c",
    "argon2/src/core.c",
    "argon2/src/core.h",
    "argon2/src/encoding.c",
    "argon2/src/encoding.h",
    "argon2/src/opt.c",
    "argon2/src/ref.c",
    "argon2/src/thread.c",
    "argon2/src/thread.h",
    "prebuilds/**/*.node"
  ],
  "binary": {
    "napi_versions": [
      8
    ]
  },
  "scripts": {
    "build": "prebuildify --napi --strip --tag-armv --tag-libc",
    "install": "node-gyp-build",
    "lint": "biome check .",
    "prepare": "tsc",
    "test": "node --test test.cjs"
  },
  "dependencies": {
    "@phc/format": "^1.0.0",
    "node-addon-api": "^8.1.0",
    "node-gyp-build": "^4.8.1"
  },
  "devDependencies": {
    "@biomejs/biome": "1.8.3",
    "@types/node": "20.16.1",
    "node-gyp": "10.2.0",
    "prebuildify": "6.0.1",
    "typescript": "5.5.4"
  },
  "packageManager": "npm@10.8.2+sha512.c7f0088c520a46596b85c6f8f1da943400199748a0f7ea8cb8df75469668dc26f6fb3ba26df87e2884a5ebe91557292d0f3db7d0929cdb4f14910c3032ac81fb",
  "engines": {
    "node": ">=16.17.0"
  },
  "collective": {
    "type": "opencollective",
    "url": "https://opencollective.com/node-argon2"
  }
}
