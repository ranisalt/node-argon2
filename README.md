# node-argon2

[![Financial contributors on Open Collective][opencollective-image]][opencollective-url]
[![Build status][actions-image]][actions-url]
[![NPM package][npm-image]][npm-url]
[![Coverage status][coverage-image]][coverage-url]
[![Code Quality][codequality-image]][codequality-url]
[![Dependencies][david-image]][david-url]

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

### Migrating from another hash function
See [this article on the wiki](https://github.com/ranisalt/node-argon2/wiki/Migrating-from-another-hash-function) for steps how to migrate your existing code to Argon2. It's easy!

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
The interface of both are very similar, notably node-argon2-ffi splits the
argon2i and argon2d function set, but this module also has the argon2id option,
which node-argon2-ffi **does not support**.  Also, while node-argon2-ffi
suggests you promisify `crypto.randomBytes`, node-argon2 library does that
internally.

**node-argon2** is much lighter than **node-argon2-ffi**, at 184 KB for
argon2@0.27.0 against 2.56 MB for argon2-ffi@1.2.0. Performance-wise, the
libraries are equal. You can run the same benchmark suite if you are curious,
but both can perform around 130 hashes/second on an Intel Core i5-4460 @ 3.2GHz
with default options.

This library is implemented natively, meaning it is an extension to the node
engine. Thus, half of the code are C++ bindings, the other half are Javascript
functions. node-argon2-ffi uses ffi, a mechanism to call functions from one
language in another, and handles the type bindings (e.g. JS Number -> C++ int).

### Prebuilt Binaries
**node-argon2** provides prebuilt binaries from `v0.26.0` onwards. They are
built per release using GitHub Actions.

The current prebuilt binaries are built (and tested) with the following matrix:
1. Node 10.x, 12.x, 13.x
2. Ubuntu 16.04, Alpine Linux, Windows Server 2019, macOS Catalina 10.15

If your plaform is below the above requirements, you can follow the
[Before Installing](#before-installing) section below to manually compile from
source. It is also always recommended to build from source to ensure consistency
of the compiled module.

### Before Installing
> You can skip this section if the prebuilt binaries work for you.

You **MUST** have a **node-gyp** global install before proceeding with install,
along with GCC >= 5 / Clang >= 3.3. On Windows, you must compile under Visual
Studio 2015 or newer.

**node-argon2** works only and is tested against Node >=10.0.0.

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

### FAQ
<details>
  <summary>How do I manually rebuild the binaries?</summary>

  ```console
  $ npx node-pre-gyp rebuild -C ./node_modules/argon2
  ```

  > Run `node-pre-gyp` instead of `node-gyp` because node-argon2's `binding.gyp`
  file relies on variables from `node-pre-gyp`.

  > You can omit `npx` if you have a global installation of `node-pre-gyp`,
  otherwise prefixing `npx` will use the local one in `./node_modules/.bin`
</details>

<details>
  <summary>
    How do I skip installing prebuilt binaries and manually compile from source?
  </summary>
  
  You can do either of the two methods below:
  
  1. Force build from source on install.
  ```console
  $ npm install argon2 --build-from-source
  ```
  
  2. Ignore `node-argon2` install script and build manually.
  ```console
  $ npm install argon2 --ignore-scripts
  $ npx node-pre-gyp rebuild -C ./node_modules/argon2
  ```
</details>

## Contributors

### Code Contributors

This project exists thanks to all the people who contribute. [[Contribute](CONTRIBUTING.md)].
<a href="https://github.com/ranisalt/node-argon2/graphs/contributors"><img src="https://opencollective.com/node-argon2/contributors.svg?width=890&button=false" /></a>

### Financial Contributors

Become a financial contributor and help us sustain our community. [[Contribute](https://opencollective.com/node-argon2/contribute)]

#### Individuals

<a href="https://opencollective.com/node-argon2"><img src="https://opencollective.com/node-argon2/individuals.svg?width=890"></a>

#### Organizations

Support this project with your organization. Your logo will show up here with a link to your website. [[Contribute](https://opencollective.com/node-argon2/contribute)]

<a href="https://opencollective.com/node-argon2/organization/0/website"><img src="https://opencollective.com/node-argon2/organization/0/avatar.svg"></a>
<a href="https://opencollective.com/node-argon2/organization/1/website"><img src="https://opencollective.com/node-argon2/organization/1/avatar.svg"></a>
<a href="https://opencollective.com/node-argon2/organization/2/website"><img src="https://opencollective.com/node-argon2/organization/2/avatar.svg"></a>
<a href="https://opencollective.com/node-argon2/organization/3/website"><img src="https://opencollective.com/node-argon2/organization/3/avatar.svg"></a>
<a href="https://opencollective.com/node-argon2/organization/4/website"><img src="https://opencollective.com/node-argon2/organization/4/avatar.svg"></a>
<a href="https://opencollective.com/node-argon2/organization/5/website"><img src="https://opencollective.com/node-argon2/organization/5/avatar.svg"></a>
<a href="https://opencollective.com/node-argon2/organization/6/website"><img src="https://opencollective.com/node-argon2/organization/6/avatar.svg"></a>
<a href="https://opencollective.com/node-argon2/organization/7/website"><img src="https://opencollective.com/node-argon2/organization/7/avatar.svg"></a>
<a href="https://opencollective.com/node-argon2/organization/8/website"><img src="https://opencollective.com/node-argon2/organization/8/avatar.svg"></a>
<a href="https://opencollective.com/node-argon2/organization/9/website"><img src="https://opencollective.com/node-argon2/organization/9/avatar.svg"></a>

# License
Work licensed under the [MIT License](LICENSE). Please check
[P-H-C/phc-winner-argon2](https://github.com/P-H-C/phc-winner-argon2) for
license over Argon2 and the reference implementation.

[opencollective-image]: https://img.shields.io/opencollective/all/node-argon2.svg?style=flat-square
[opencollective-url]: https://opencollective.com/node-argon2
[npm-image]: https://img.shields.io/npm/v/argon2.svg?style=flat-square
[npm-url]: https://www.npmjs.com/package/argon2
[actions-image]: https://img.shields.io/github/workflow/status/ranisalt/node-argon2/CI?style=flat-square
[actions-url]: https://github.com/ranisalt/node-argon2/actions
[coverage-image]: https://img.shields.io/coveralls/github/ranisalt/node-argon2/master.svg?style=flat-square
[coverage-url]: https://coveralls.io/github/ranisalt/node-argon2
[codequality-image]: https://img.shields.io/codacy/grade/15927f4eb15747fd8a537e48a04bd4f6/master.svg?style=flat-square
[codequality-url]: https://www.codacy.com/app/ranisalt/node-argon2
[david-image]: https://img.shields.io/david/ranisalt/node-argon2.svg?style=flat-square
[david-url]: https://david-dm.org/ranisalt/node-argon2
