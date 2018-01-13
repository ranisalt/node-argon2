// TypeScript compile test using type declarations.
// These tests don't validate anything except the interface.

/// <reference types="node" />

import * as argon2 from "./index";

const password = "password";
const passwordBuffer = new Buffer("password");

// hashes for argon2i and argon2d with default options
const hashes = Object.freeze({
    argon2i: "$argon2i$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$iWh06vD8Fy27wf9npn6FXWiCX4K6pW6Ue1Bnzz07Z8A",
    argon2d: "$argon2d$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$2+JCoQtY/2x5F0VB9pEVP3xBNguWP1T25Ui0PtZuk8o"
});

function test_options() {
    const defaults: argon2.Options = {
        hashLength: 32,
        timeCost: 3,
        memoryCost: 12,
        parallelism: 1,
        type: argon2.argon2i,
        raw: false
    };

    console.log(argon2.defaults.hashLength === defaults.hashLength);
    console.log(argon2.defaults.timeCost === defaults.timeCost);
    console.log(argon2.defaults.memoryCost === defaults.memoryCost);
    console.log(argon2.defaults.parallelism === defaults.parallelism);
    console.log(argon2.defaults.type === defaults.type);
    console.log(argon2.defaults.raw === defaults.raw);
}

function test_hash() {
    return Promise.all([
        argon2.hash(password), // String pw
        argon2.hash(passwordBuffer) // Buffer pw
    ]);
}

function test_hashOptions() {
    // All options separately, and together
    return Promise.all([
        argon2.hash(password, {type: argon2.argon2d}),
        argon2.hash(password, {timeCost: 4}),
        argon2.hash(password, {hashLength: 4}),
        argon2.hash(password, {memoryCost: 13}),
        argon2.hash(password, {parallelism: 2}),
        argon2.hash(password, {salt: Buffer.from('1234567890abcdef')}),
        argon2.hash(password, {timeCost: 4, memoryCost: 13, parallelism: 2})
    ]);
}

function test_verify() {
    // Verify with string and buffer
    return Promise.all([
        argon2.verify(hashes.argon2d, password),
        argon2.verify(hashes.argon2i, passwordBuffer)
    ]);
}

function test_raw(): Promise<Buffer> {
    return argon2.hash(password, {raw: true});
}
