#!/usr/bin/env bash
set -ex

# TODO FIXME convert to makefile

cd argon2
make
cd ..
# 

# npx node-gyp rebuild --verbose
# and then steal the commands
mkdir -p build

# TODO let argon2 build its library
# https://packages.debian.org/unstable/libargon2-0

cd build
g++ -o Release/obj.target/argon2/src/argon2_node.o ../src/argon2_node.cpp '-D_FORTIFY_SOURCE=2' '-DNDEBUG' '-DNODE_GYP_MODULE_NAME=argon2' '-DUSING_UV_SHARED=1' '-DUSING_V8_SHARED=1' '-DV8_DEPRECATION_WARNINGS=1' '-DV8_DEPRECATION_WARNINGS' '-DV8_IMMINENT_DEPRECATION_WARNINGS' '-D_GLIBCXX_USE_CXX11_ABI=1' '-D_LARGEFILE_SOURCE' '-D_FILE_OFFSET_BITS=64' '-D__STDC_FORMAT_MACROS' '-DNAPI_VERSION=8' '-DBUILDING_NODE_EXTENSION' -I../argon2/include -I/home/moritz/.cache/node-gyp/16.14.0/include/node -I/home/moritz/.cache/node-gyp/16.14.0/src -I/home/moritz/.cache/node-gyp/16.14.0/deps/openssl/config -I/home/moritz/.cache/node-gyp/16.14.0/deps/openssl/openssl/include -I/home/moritz/.cache/node-gyp/16.14.0/deps/uv/include -I/home/moritz/.cache/node-gyp/16.14.0/deps/zlib -I/home/moritz/.cache/node-gyp/16.14.0/deps/v8/include -I/home/moritz/Documents/node-argon2/node_modules/node-addon-api  -fPIC -pthread -Wall -Wextra -Wno-unused-parameter -m64 -fdata-sections -ffunction-sections -fvisibility=hidden -O3 -fno-omit-frame-pointer -fno-rtti -std=gnu++14 -std=c++17 -MMD -MF ./Release/.deps/Release/obj.target/argon2/src/argon2_node.o.d.raw   -c


g++ -o Release/obj.target/argon2.node -shared -pthread -rdynamic -m64 -Wl,--gc-sections  -Wl,-soname=argon2.node -Wl,--start-group Release/obj.target/argon2/src/argon2_node.o ../argon2/libargon2.a -Wl,--end-group