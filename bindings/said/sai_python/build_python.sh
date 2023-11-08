#!/bin/bash

BASE_DIR=$(realpath $(dirname "$0")/..)"/sai_python"
echo $BASE_DIR
LIB_NAME="sai_python"

cd $BASE_DIR
cargo build --release

mkdir -p "$BASE_DIR/python/libs/"

cp $BASE_DIR"/target/release/lib${LIB_NAME}.so" "$BASE_DIR/python/libs/lib${LIB_NAME}.so"