# examples/kuwo

命令行程序示例。

代码清单：

* `examples/kuwo/src/kuwo-cli.cpp`

Linux 下编译/运行：

```bash
# Configure & Build
cmake --preset ninja
cmake --build --preset "ninja-release" --target kuwo

# View usage
./out/build/ninja/examples/kuwo/Release/kuwo -h
```

使用参数:

```text
usage: 

KwmV1 decryption config
  --key <key>            static key used for v1 encryption

KwmV2 decryption config
  --seed <seed>          ekey seed
  --mix-key-1 <key>      [EncV2] mix key 1
  --mix-key-2 <key>      [EncV2] mix key 2
  --ekey [ekey]          EKey of the file (encrypted)

IO parameters
  -i | --input <path>    Path to input file
  -o | --output <path>   Path to output file
  -h | --help            Display this usage information
```

## 说明

该项目是 [LibParakeet][main_project] 的一部分。

[main_project]: https://github.com/parakeet-rs/libparakeet
