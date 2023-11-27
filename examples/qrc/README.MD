# examples/qrc-decode

命令行程序示例；传入 `<输入路径> <输出路径>` 这两个参数运行。

代码清单：

* `examples/qrc/src/qrc-example.cpp`
* `examples/qrc/src/qrc-key.local.h` (可选)

Linux 下编译/运行：

```bash
# Configure & Build
cmake --preset ninja
cmake --build --preset "ninja-release" --target qrc-decode

# Run
./out/build/ninja/examples/qrc/Release/qrc-decode "test.qrc" "test.qrc.xml"
```

## 说明

该项目是 [LibParakeet][main_project] 的一部分。

[main_project]: https://github.com/parakeet-rs/libparakeet
