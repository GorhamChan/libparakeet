# examples/qingting-fm

命令行程序示例。

代码清单：

* `examples/qingting-fm/src/qingting-fm-cli.cpp`

Linux 下编译/运行：

```bash
# Configure & Build
cmake --preset ninja
cmake --build --preset "ninja-release" --target qingting-fm

# View usage
./out/build/ninja/examples/qingting-fm/Release/qingting-fm -h
```

使用参数:

```text
usage: 

Secret key derivation from `android.os.Build` constants
  --product              value of `android.os.Build.PRODUCT`
  --device               value of `android.os.Build.DEVICE`
  --manufacturer         value of `android.os.Build.MANUFACTURER`
  --brand                value of `android.os.Build.BRAND`
  --board                value of `android.os.Build.BOARD`
  --model                value of `android.os.Build.MODEL`

Secret key
  -k | --secret-key <path>    Path to input file

IO parameters
  -i | --input <path>    Path to input file
  -o | --output <path>   Path to output file
  -h | --help            Display this usage information
```

## 说明

该项目是 [LibParakeet][main_project] 的一部分。

[main_project]: https://github.com/parakeet-rs/libparakeet
