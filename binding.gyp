{
  "target_defaults": {
    "include_dirs": ["argon2/include"],
    "target_conditions": [
      ["OS == 'mac'", {
        "xcode_settings": {
          "CLANG_CXX_LIBRARY": "libc++",
          "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
          "MACOSX_DEPLOYMENT_TARGET": "10.7"
        }
      }],
      ["OS == 'win'", {
        "defines+": ["_HAS_EXCEPTIONS=1"],
        "msvs_settings": {
          "VCCLCompilerTool": { "ExceptionHandling": 1 }
        }
      }]
    ],
    "configurations": {
      "Release": {
        "target_conditions": [
          ["OS != 'win'", {
            "cflags+": ["-fdata-sections", "-ffunction-sections", "-flto", "-fvisibility=hidden"],
            "ldflags+": ["-Wl,--gc-sections"]
          }]
        ],
        "defines+": ["_FORTIFY_SOURCE=2", "NDEBUG"]
      }
    }
  },
  "targets": [
    {
      "target_name": "libargon2",
      "sources": [
        "argon2/src/argon2.c",
        "argon2/src/blake2/blake2b.c",
        "argon2/src/core.c",
        "argon2/src/encoding.c",
        "argon2/src/thread.c"
      ],
      "cflags+": ["-Wno-type-limits"],
      "conditions": [
        ["target_arch == 'ia32' or target_arch == 'x64'", {
          "cflags+": ["-msse", "-msse2"],
          "sources+": ["argon2/src/opt.c"]
        }, {
          "sources+": ["argon2/src/ref.c"]
        }]
      ],
      "type": "static_library"
    }, {
      "target_name": "argon2",
      "defines+": [
        "NAPI_VERSION=<(napi_build_version)",
        "NODE_ADDON_API_DISABLE_DEPRECATED",
        "NODE_API_NO_EXTERNAL_BUFFERS_ALLOWED"
      ],
      "sources": [
        "argon2_node.cpp"
      ],
      "cflags_cc+": ["-Wall", "-Wextra", "-Wconversion", "-Wformat", "-Wnon-virtual-dtor", "-pedantic", "-Werror"],
      "cflags_cc!": ["-fno-exceptions"],
      "include_dirs": ["<!(node -p \"require('node-addon-api').include_dir\")"],
      "dependencies": ["libargon2"],
      "configurations": {
        "Debug": {
          "conditions": [
            ["OS == 'linux'", {
              "cflags": ["--coverage"],
              "ldflags": ["-fprofile-arcs", "-ftest-coverage"]
            }]
          ]
        }
      }
    }
  ]
}
