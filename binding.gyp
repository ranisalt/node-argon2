{
  "target_defaults": {
    "target_conditions": [
      ["OS != 'win'", {"cflags": ["-msse","-msse2"]}]
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
        "argon2/src/opt.c"
      ],
      "include_dirs": ["argon2/include"],
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
