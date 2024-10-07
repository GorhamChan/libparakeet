# examples/migu3d

命令行程序示例。

代码清单：

* `examples/migu3d/src/migu3d-cli.cpp`

Linux 下编译/运行：

```bash
# Configure & Build
cmake --preset ninja
cmake --build --preset "ninja-release" --target migu3d

# View usage
./out/build/ninja/examples/migu3d/Release/migu3d -h
```

使用参数:

```text
usage: 
  --salt <salt>          Application salt
  --file-key <key>       File specific key 
  -i | --input <path>    Path to input file
  -o | --output <path>   Path to output file
  -h | --help            Display this usage information

When --salt and --file-key are both omitted, it will attempt to recover the key by performing frequency analysis attack.
```

## 说明

该项目是 [LibParakeet][main_project] 的一部分。

[main_project]: https://github.com/parakeet-rs/libparakeet
