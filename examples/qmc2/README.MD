# examples/QMC2

命令行程序示例；传入 `<输入路径> <输出路径>` 这两个参数运行。

代码清单：

* `examples/qmc2/src/qmc2-example.cpp`
* `examples/qmc2/src/qmc2-key.local.h` (可选)

Linux 下编译/运行：

```bash
# Configure & Build
cmake --preset ninja
cmake --build --preset "ninja-release" --target qmc2

# Run
./out/build/ninja/examples/qmc2/Release/qmc2 "test.mflac" "test.flac"
```

## 说明

该项目是 [LibParakeet][main_project] 的一部分。

[main_project]: https://github.com/parakeet-rs/libparakeet
