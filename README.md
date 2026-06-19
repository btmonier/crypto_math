Repo for holding answers to the programming exercises found in
[Cryptological Mathematics](https://bookstore.ams.org/CLRM/16) by Robert Edward Lewand.


## Build

```bash
# Build everything
cargo build

# Run all tests across the workspace
cargo test

# Run tests for a single chapter
cargo test -p chapter1-monoalphabetic

# Run tests for the shared library
cargo test -p crypto-core
```
