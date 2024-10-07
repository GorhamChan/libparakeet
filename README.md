# LibParakeet

使用 C++ 实现的小鹦鹉流媒体解密操作库。

克隆仓库后使用 CMake 进行构建即可。

## 构建

请参考 [GitHub Actions 配置文件](./github/workflows/)以及 [CMake Preset 配置文件](./CMakePresets.json)。

### Linux

使用 Ninja 构建。

```bash
cmake --preset ninja
cmake --build --preset "ninja-release" 
```

### Windows (Visual Studio 2022)

- 可选构建预设 [`msvc-2022-debug`, `msvc-2022-release`, `msvc-2022-win32-debug`, `msvc-2022-win32-release`]

```ps1
cmake --preset msvc-2022
cmake --build --preset "msvc-2022-release" 
```

## 用例

参考 `examples` 目录下的子项目。

💡 内置的默认密钥不能用于解密生产版本的文件。

- [qmc2](./examples/qmc2/README.MD) - QMC2 加密格式支持
- [qrc-decode](./examples/qrc/README.MD) - QRC 歌词格式支持
- [qingting-fm](./examples/qingting-fm/README.MD) - 「蜻蜓 FM」加密格式支持
- [migu3d](./examples/migu3d/README.MD) - 「咪咕」的「臻 3D」加密格式支持
- [kuwo](./examples/kuwo/README.MD) - 「酷我」加密格式支持

## 发布新版本

1. 更新 `CHANGELOG.md`
2. 更新 `CMakeLists.txt` 声明的版本号
3. 合并到主分支，然后打上 `git tag`

## 致谢

- [Unlock Music](https://unlock-music.dev/) - 万物之始。
- 匿名用户 `咦我的昵称呢` - 「蜻蜓 FM」相关算法。

## License

Licensed under the [MIT License](LICENSE.txt).
