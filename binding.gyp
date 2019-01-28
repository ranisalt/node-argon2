{
  "target_defaults": {
    "include_dirs": ["argon2/include"],
    "target_conditions": [
      ["OS == 'mac'", {
        "xcode_settings": {
          "CLANG_CXX_LIBRARY": "libc++",
          "MACOSX_DEPLOYMENT_TARGET": "10.7",
        }
      }]
    ],
    "configurations": {
      "Release": {
        "target_conditions": [
          ["OS != 'win'", {
            "cflags+": ["-fdata-sections", "-ffunction-sections", "-fvisibility=hidden"],
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
        "argon2/src/core.c",
        "argon2/src/blake2/blake2b.c",
        "argon2/src/thread.c",
        "argon2/src/encoding.c",
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
      "xcode_settings": {
        "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
      },
      "msvs_settings": {
        "VCCLCompilerTool": { "ExceptionHandling": 1 },
      },
      "sources": [
        "src/argon2_node.cpp"
      ],
      "cflags_cc!": ["-fno-exceptions"],
      "include_dirs": ["<!@(node -p \"require('node-addon-api').include\")"],
      "dependencies": ["libargon2"],
      "configurations": {
        "Debug": {
          "conditions": [
            ["OS == 'linux'", {
              "cflags": ["--coverage"],
              "ldflags": ["-fprofile-arcs", "-ftest-coverage"],
            }]
          ]
        }
      }
    }
  ]
}
