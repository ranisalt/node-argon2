{
  "target_defaults": {
    "target_conditions": [
      ["OS != 'win'", {
        "cflags": ["-fvisibility=hidden"]
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
      "cflags": ["-march=native", "-pthread", "-Wno-type-limits"],
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
      "cflags": ["-std=c++11", "-stdlib=libc++"],
      "conditions": [
        [ "OS != 'win'", {
          "cflags+": [ "-std=c++11" ],
          "cflags_c+": [ "-std=c++11" ],
          "cflags_cc+": [ "-std=c++11" ],
        }],
        [ "OS == 'mac'", {
          "xcode_settings": {
            "OTHER_CPLUSPLUSFLAGS" : [ "-std=c++11", "-stdlib=libc++" ],
            "OTHER_LDFLAGS": [ "-stdlib=libc++" ]
          }
        }]
      ],
      "configurations": {
        "Debug": {
          "conditions": [
            ["OS == 'linux'", {
              "cflags": ["--coverage", "-Wall", "-Wextra"],
              "ldflags": ["-fprofile-arcs", "-ftest-coverage"],
            }]
          ]
        },
        "Release": {
          "defines+": ["NDEBUG"]
        }
      }
    }
  ]
}
