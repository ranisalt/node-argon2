# node-argon2

[![Financial contributors on Open Collective][opencollective-image]][opencollective-url]
[![Build status][actions-image]][actions-url]
[![NPM package][npm-image]][npm-url]

Bindings to the native [Argon2](https://github.com/P-H-C/phc-winner-argon2)
implementation available in `node:crypto`.

## Usage

It's possible to hash using either Argon2i, Argon2d or Argon2id (default), and
verify if a password matches a hash.

To hash a password:

```js
import * as argon2 from "argon2";

try {
  const hash = await argon2.hash("password");
} catch (err) {
  //...
}
```

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

> [!NOTE]
> By default, argon2.hash will generate secure hashes according to the security recommendations by the team that develops Argon2.
> **For password hashing, there is no need to modify them.**

node-argon2 requires Node.js 24.7.0 or newer.

To see how you can modify the output (hash length, encoding) and parameters
(time cost, memory cost and parallelism),
[read the wiki](https://github.com/ranisalt/node-argon2/wiki/Options)

### Comparison with the node:crypto native implementation

node-argon2 delegates to the native Argon2 implementation in `node:crypto` and
keeps the password-hashing-friendly API, PHC formatting, and rehash checks that
the native API does not provide.

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
