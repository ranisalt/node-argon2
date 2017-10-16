{
  "target_defaults": {
    "target_conditions": [
      ["OS != 'win'", {
        "cflags+": ["-fdata-sections", "-ffunction-sections", "-fvisibility=hidden", "-march=native"],
        "ldflags+": ["-Wl,--gc-sections"]
      }],
      ["OS == 'mac'", {
        "xcode_settings": {
          "MACOSX_DEPLOYMENT_TARGET": "10.9",
        }
      }]
    ],
    "target_configurations": [
      [{
        "Release": {
          "defines+": ["NDEBUG"]
        }
      }]
    ]
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
      "include_dirs": ["argon2/include"],
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
      "sources": [
        "src/argon2_node.cpp"
      ],
      "include_dirs": [
        "<!(node -e \"require('nan')\")",
        "argon2/include"
      ],
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
