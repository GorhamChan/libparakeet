#!/bin/env python3

from hashlib import md5
import os

fixture_dir = os.path.join(os.path.dirname(__file__), '../fixture')

def encrypt_migu3d(buf: bytearray, key: bytes|bytearray) -> None:
    for i in range(0, len(buf)):
        buf[i] = (buf[i] + key[i % 32]) & 0xff

if __name__ == '__main__':
    mg3d_salt = b'libparakeet/test'
    file_keys = b'0000111122223333'
    key = md5(mg3d_salt + file_keys).hexdigest().upper().encode('ascii')
    print(f'mg3d_salt is: {mg3d_salt}')
    print(f'file_keys is: {file_keys}')
    print(f'final key is: {key}')
    with open(os.path.join(fixture_dir, 'sample_test_121529_32kbps.ogg'), 'rb') as f:
        content = bytearray(f.read())
    encrypt_migu3d(content, key)
    with open(os.path.join(fixture_dir, 'test.mg3d'), 'wb') as f:
        f.write(content)
