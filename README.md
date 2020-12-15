# RLBOX Segments SFI Sandbox Integration

Integration with RLBox sandboxing API to leverage the sandboxing provided by Intel Segmented memory model available on Intel 32-bit.

**Note:**  This repo is only meant to simulate the performance costs and is not production ready.

For details about the RLBox sandboxing APIs, see [here](https://github.com/PLSysSec/rlbox_api_cpp17).

## Building/Running the tests

You can build and run the tests using cmake with the following commands.

```bash
cmake -S . -B ./build
cmake --build ./build --target all
cmake --build ./build --target test
```


