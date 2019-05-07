# node-argon2

[![Greenkeeper badge](https://badges.greenkeeper.io/ranisalt/node-argon2.svg)](https://greenkeeper.io/)
[![NPM package][npm-image]][npm-url] [![Coverage status][coverage-image]][coveralls-url] [![Code Quality][codequality-image]][codequality-url] [![Dependencies][david-dm-image]][david-dm-url]
- Linux/OS X: [![Linux build status][travis-image]][travis-url]
- Windows: [![Windows build status][appveyor-image]][appveyor-url]

Bindings to the reference [Argon2](https://github.com/P-H-C/phc-winner-argon2)
implementation.

**Want to use it on command line? Instead check
[node-argon2-cli](https://github.com/ranisalt/node-argon2-cli).**

### Usage
It's possible to hash using either Argon2i (default), Argon2d and Argon2id, and
verify if a password matches a hash.

To hash a password:
```js
const argon2 = require('argon2');

try {
  const hash = await argon2.hash("password");
} catch (err) {
  //...
}
```

To see how you can modify the output (hash length, encoding) and parameters
(time cost, memory cost and parallelism),
[read the wiki](https://github.com/ranisalt/node-argon2/wiki/Options)

To verify a password:
```js
try {
  if (await argon2.verify("<big long hash>", "password")) {
    // password match
  } else {
    // password did not match
  }
} catch (err) {
  // internal failure
}
```

### TypeScript Usage
A TypeScript type declaration file is published with this module. If you are
using TypeScript >= 2.0.0 that means you do not need to install any additional
typings in order to get access to the strongly typed interface. Simply use the
library as mentioned above. This library uses Promises, so make sure you are
targeting ES6+, including the es2015.promise lib in your build, or globally
importing a Promise typings library.

Some example tsconfig.json compiler options:

```json
{
    "compilerOptions": {
        "lib": ["es2015.promise"]
    }
}

or

{
    "compilerOptions": {
        "target": "es6"
    }
}
```

```ts
import * as argon2 from "argon2";

const hash = await argon2.hash(..);
```

### Differences from [node-argon2-ffi](https://github.com/cjlarose/argon2-ffi)
This library is implemented natively, meaning it is an extension to the node
engine. Thus, half of the code are C++ bindings, the other half are Javascript
functions. node-argon2-ffi uses ffi, a mechanism to call functions from one
language in another, and handles the type bindings (e.g. JS Number -> C++ int).

The interface of both are very similar, notably node-argon2-ffi splits the
argon2i and argon2d function set, but this module also has the argon2id option.
Also, while node-argon2-ffi suggests you promisify `crypto.randomBytes`, this
library does that internally.

Performance-wise, the libraries are equal. You can run the same benchmark suite
if you are curious, but both can perform around 130 hashes/second on an Intel
Core i5-4460 @ 3.2GHz with default options.

### Before installing
You **MUST** have a **node-gyp** global install before proceeding with install,
along with GCC >= 5 / Clang >= 3.3. On Windows, you must compile under Visual
Studio 2015 or newer.

**node-argon2** works only and is tested against Node >=8.0.0.

#### OSX
To install GCC >= 5 on OSX, use [homebrew](http://brew.sh/):
```console
$ brew install gcc
```

Once you've got GCC installed and ready to run, you then need to install
node-gyp, you must do this globally:
```console
$ npm install -g node-gyp
```

Finally, once node-gyp is installed and ready to go, you can install this
library, specifying the GCC or Clang binary to use:

```console
$ CXX=g++-6 npm install argon2
```

**NOTE**: If your GCC or Clang binary is named something different than `g++-6`,
you'll need to specify that in the command.

# License
Work licensed under the [MIT License](LICENSE). Please check
[P-H-C/phc-winner-argon2](https://github.com/P-H-C/phc-winner-argon2) for
license over Argon2 and the reference implementation.

[npm-image]: https://img.shields.io/npm/v/argon2.svg?style=flat-square
[npm-url]: https://www.npmjs.com/package/argon2
[travis-image]: https://img.shields.io/travis/ranisalt/node-argon2/master.svg?style=flat-square
[travis-url]: https://travis-ci.org/ranisalt/node-argon2
[appveyor-image]: https://img.shields.io/appveyor/ci/ranisalt/node-argon2/master.svg?style=flat-square
[appveyor-url]: https://ci.appveyor.com/project/ranisalt/node-argon2
[coverage-image]: https://img.shields.io/coveralls/github/ranisalt/node-argon2/master.svg?style=flat-square
[coverage-url]: https://coveralls.io/github/ranisalt/node-argon2
[codequality-image]: https://img.shields.io/codacy/grade/15927f4eb15747fd8a537e48a04bd4f6/master.svg?style=flat-square
[codequality-url]: https://www.codacy.com/app/ranisalt/node-argon2
[david-dm-image]: https://img.shields.io/david/ranisalt/node-argon2.svg?style=flat-square
[david-dm-url]: https://david-dm.org/ranisalt/node-argon2
