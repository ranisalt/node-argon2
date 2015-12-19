{
  "targets": [
    {
      "target_name": "argon2_lib",
      "sources": [
        "argon2/src/argon2.c",
        "argon2/src/core.c",
        "argon2/src/encoding.c",
        "argon2/src/ref.c",
        "argon2/src/thread.c",
        "argon2/src/blake2/blake2b.c",
        "argon2_node.cpp"
      ],
      "include_dirs": [
        "<!(node -e \"require('nan')\")"
      ]
    }
  ]
}
