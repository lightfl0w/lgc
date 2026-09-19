#!/bin/sh
set -e
cd "$(dirname "$0")"
mkdir -p build

echo "== 编译器 =="
gcc -Os -o build/my_compiler src/main.c
x86_64-w64-mingw32-gcc -Os -s -o build/my_compiler.exe src/main.c

echo "== 自举三级链 =="
./build/my_compiler src/lgc.lg build/lgc1
./build/lgc1 src/lgc.lg build/lgc2
./build/lgc2 src/lgc.lg build/lgc
cmp build/lgc2 build/lgc && echo "自举收敛"

echo "== 回归 =="
for t in tests/*.lg; do
    ./build/my_compiler "$t" build/t.out
    printf '%-14s ' "$(basename "$t")"
    ./build/t.out || printf '(exit %d)' $?
    printf '\n'
done

echo "== 多文件 =="
printf '%-14s ' "@import"
./build/my_compiler tests/multi/main.lg build/tm1 && ./build/tm1
printf '%-14s ' "cli"
./build/my_compiler tests/multi/a.lg tests/multi/b.lg build/tm2 && ./build/tm2

echo "== 引导 =="
./build/my_compiler examples/boot.lg build/boot.bin
cmp build/boot.bin reference/boot.bin && echo "boot 与参照一致"
./build/my_compiler examples/hello.lg build/hello.img
echo "hello.img 已生成（qemu-system-x86_64 -drive format=raw,file=build/hello.img -nographic）"