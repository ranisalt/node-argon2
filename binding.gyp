{
  "targets": [
    {
      "target_name": "argon2",
      "sources": [
        "argon2_node.cpp"
      ],
      "include_dirs": [
        "<!(node -e \"require('nan')\")"
      ],
      "libraries": ["<(module_root_dir)/argon2/libargon2.so"],
      "configurations": {
        "Debug": {
          "conditions": [
            ["OS == 'linux'", {
              "cflags": ["--coverage"],
              "ldflags": ["-fprofile-arcs"],
            }]
          ]
        }
      }
    }
  ]
}
