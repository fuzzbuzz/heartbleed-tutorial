#!/bin/bash
# Copyright 2016 Google Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");

set -x
set -e
set -o pipefail

cd openssl_src && CC="$FUZZ_CC $CFLAGS" ./config && make clean && make
cd ..
$FUZZ_CXX $CXXFLAGS ./target.cc -DCERT_PATH=\"$PWD/runtime\"  openssl_src/libssl.a openssl_src/libcrypto.a $FUZZ_ENGINE -I openssl_src/include -o ./target
