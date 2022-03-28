#!/bin/bash
# Copyright 2016 Google Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");

set -x
set -e
set -o pipefail

mkdir /testdata && cp runtime/* testdata
cd openssl_src && CC="clang $CFLAGS" ./config && make clean && make
cd ..
clang++ $CXXFLAGS ./target.cc openssl_src/libssl.a openssl_src/libcrypto.a -fsanitize=fuzzer -I openssl_src/include -o ./target
