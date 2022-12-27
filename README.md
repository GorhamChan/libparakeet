# LibParakeet

使用 C++ 实现的小鹦鹉流媒体解密操作库。

## 用例

具体调用与用例还需要调整。

```cpp
#include <fstream>
#include <iostream>

void main() {
  std::ifstream input_file("./test.bin", input_file.binary);
  // FIXME: Add example code of DecryptionFactory.
  auto detection = manager.DetectDecryptor(input_file);
  if (detection) {
    std::cout << "detected " << detection->decryptor->GetName() << std::endl;
  } else {
    std::cout << "unsupported file" << std::endl;
  }
}
```

## License

Licensed under the [MIT License](LICENSE.txt).
