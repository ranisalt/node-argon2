{
  "variables": {
    "fortify_source_defined": "<!(node -p \"/-D\\s*_FORTIFY_SOURCE=/.test((process.env.CFLAGS || '') + (process.env.CPPFLAGS || '') + (process.env.CXXFLAGS || ''))\")",
  },
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
          # Define _FORTIFY_SOURCE on non-Darwin, but avoid overriding it if already set
          ["OS not in 'ios mac'", {
            "conditions": [
              ["fortify_source_defined=='false'", {"defines+": ["_FORTIFY_SOURCE=2"]}]
            ]
          }],
          ["OS not in 'win ios mac aix'", {
            # On Darwin with Xcode CLT/LLVM, "-fvisibility=hidden" hide all symbols that
            # not explicitly marked with __attribute__((visibility("default")))
            # Flags for sections are specific to ELF binaries
            "cflags+": ["-fdata-sections", "-ffunction-sections", "-fvisibility=hidden"],
            "ldflags+": ["-Wl,--gc-sections"]
          }]
        ],
        "defines+": ["NDEBUG"]
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
        "argon2.cpp"
      ],
      "cflags_cc+": ["-Wall", "-Wextra", "-Wformat", "-Wnon-virtual-dtor", "-pedantic", "-Werror", "-fexceptions"],
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
          ],
          "defines+": ["NODE_ADDON_API_ENABLE_TYPE_CHECK_ON_AS"]
        }
      }
    }
  ]
}
