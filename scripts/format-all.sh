#!/bin/sh -ex

(
  cd "$(git rev-parse --show-toplevel)" \
    && find src include -type f -exec clang-format -i {} \;
)
