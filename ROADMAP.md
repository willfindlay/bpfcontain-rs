BPFContain is a research prototype and is very much a work in progress. This file
documents some major (and minor) goals for the project. In particular, discussions,
issues, and/or new pull requests related to any of the items listed here would be
appreciated.

# Major Items

1. Add API documentation
2. Clean up eBPF code and separate helper functions out of the main `bpfcontain.bpf.c` file
3. Integration with container runtimes like Docker and OpenShift
4. More testing
  - Full code coverage with unit tests
  - Integration tests that exercise all policy rules
  - Unit/integration tests that exercise the jsonrpc API
5. Implement additional state tracking for smarter policies
6. Identify and address usability concerns in the policy language
7. Move toward label-based file/filesystem policy instead of using inode resolution
8. Fix issues with hard coded device numbers in device policy (resolve device numbers by pathname at policy load time)
