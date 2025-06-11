# node-argon2

[![Financial contributors on Open Collective][opencollective-image]][opencollective-url]
[![Build status][actions-image]][actions-url]
[![NPM package][npm-image]][npm-url]

Bindings to the reference [Argon2](https://github.com/P-H-C/phc-winner-argon2)
implementation.

## Usage
It's possible to hash using either Argon2i, Argon2d or Argon2id (default), and
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
See [this article on the wiki](https://github.com/ranisalt/node-argon2/wiki/Migrating-from-another-hash-function) for steps on how to migrate your existing code to Argon2. It's easy!

### TypeScript usage
A TypeScript type declaration file is published with this module. If you are
using TypeScript 2.0.0 or later, that means you do not need to install any
additional typings in order to get access to the strongly typed interface.
Simply use the library as mentioned above.

```ts
import * as argon2 from "argon2";

const hash = await argon2.hash(..);
```

## Prebuilt binaries
**node-argon2** provides prebuilt binaries from `v0.26.0` onwards. They are
built every release using GitHub Actions.

The current prebuilt binaries are built and tested with the following systems:
- Ubuntu 22.04 (x86-64; ARM64 from v0.28.2; ARMv7 from v0.43.0)
- MacOS 13 (x86-64)
- MacOS 14 (ARM64 from v0.29.0)
- Windows Server 2022 (x86-64)
- Alpine Linux 3.18 (x86-64 from v0.28.1; ARM64 from v0.28.2; ARMv7 from v0.43.0)
- FreeBSD 14 (x86-64 from v0.29.1; ARM64 from v0.44.0)

Binaries should also work for any version more recent than the ones listed
above. For example, the binary for Ubuntu 20.04 also works on Ubuntu 22.04, or
any other Linux system that ships a newer version of glibc; the binary for
MacOS 11 also works on MacOS 12. If your platform is below the above
requirements, you can follow the [Before installing](#before-installing)
section below to manually compile from source. It is also always recommended to
build from source to ensure consistency of the compiled module.

## Before installing
*You can skip this section if the [prebuilt binaries](#prebuilt-binaries) work for you.*

You **MUST** have a **node-gyp** global install before proceeding with the install,
along with GCC >= 5 / Clang >= 3.3. On Windows, you must compile under Visual
Studio 2015 or newer.

**node-argon2** works only and is tested against Node >=18.0.0.

### OSX
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
$ CXX=g++-12 npm install argon2
```

**NOTE**: If your GCC or Clang binary is named something different than `g++-12`,
you'll need to specify that in the command.

## FAQ
<details>
  <summary>How do I manually rebuild the binaries?</summary>

  ```bash
  $ npx @mapbox/node-pre-gyp rebuild -C ./node_modules/argon2
  ```

  Run `@mapbox/node-pre-gyp` instead of `node-gyp` because node-argon2's
  `binding.gyp` file relies on variables from `@mapbox/node-pre-gyp`.

  You can omit `npx @mapbox` and use just `node-pre-gyp` if you have a global
  installation of `@mapbox/node-pre-gyp`, otherwise prefixing `npx` will use
  the local one in `./node_modules/.bin`
</details>

<details>
  <summary>
    How do I skip installing prebuilt binaries and manually compile from source?
  </summary>

  You can do either of the two methods below:

  1. Force build from source on install.
  ```bash
  $ npm install argon2 --build-from-source
  ```

  2. Ignore `node-argon2` install script and build manually.
  ```bash
  $ npm install argon2 --ignore-scripts
  $ npx node-gyp rebuild -C ./node_modules/argon2
  ```
</details>

<details>
  <summary>
    I installed Node as a <a href="https://snapcraft.io/node">snap</a>, and I can't install node-argon2.
  </summary>

  This seems to be an issue related to snap (see [#345 (comment)](https://github.com/ranisalt/node-argon2/issues/345#issuecomment-1164178674)). Installing Node with another package manager, such as [asdf](https://asdf-vm.com/) or [nvm](https://github.com/nvm-sh/nvm), is a possible workaround.
</details>

## Contributors

### Code contributors

This project exists thanks to all the people who contribute. [[Contribute](CONTRIBUTING.md)].
<a href="https://github.com/ranisalt/node-argon2/graphs/contributors"><img src="https://opencollective.com/node-argon2/contributors.svg?width=890&button=false" /></a>

### Financial contributors

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

## License
Work licensed under the [MIT License](LICENSE). Please check
[P-H-C/phc-winner-argon2](https://github.com/P-H-C/phc-winner-argon2) for
license over Argon2 and the reference implementation.

[opencollective-image]: https://img.shields.io/opencollective/all/node-argon2.svg?style=flat-square
[opencollective-url]: https://opencollective.com/node-argon2
[npm-image]: https://img.shields.io/npm/v/argon2.svg?style=flat-square
[npm-url]: https://www.npmjs.com/package/argon2
[actions-image]: https://img.shields.io/github/actions/workflow/status/ranisalt/node-argon2/ci.yml?branch=master&style=flat-square
[actions-url]: https://github.com/ranisalt/node-argon2/actions
