#!/bin/sh
set -e
cd "$(dirname "$0")"
mkdir -p build

gcc -Os -o build/my_compiler src/main.c
x86_64-w64-mingw32-gcc -Os -s -o build/my_compiler.exe src/main.c

./build/my_compiler src/lgc.lg build/lgc1
./build/lgc1 src/lgc.lg build/lgc2
./build/lgc2 src/lgc.lg build/lgc
cmp build/lgc2 build/lgc

for t in tests/*.lg; do
    ./build/my_compiler "$t" build/t.out
    printf '%-14s ' "$(basename "$t")"
    ./build/t.out || printf '(exit %d)' $?
    printf '\n'
done

set +e
pass=0; gap=0; fail=0
for t in tests/*.lg; do
    name=$(basename "$t")
    e0=0; ./build/my_compiler "$t" build/d0.bin >/dev/null 2>&1 || e0=$?
    o0=""
    if [ "$e0" = 0 ]; then ./build/d0.bin > build/d0.txt 2>&1 || e0=$?; o0=$(tr -d '\0' < build/d0.txt); fi
    e3=0; ./build/lgc "$t" build/d3.bin >/dev/null 2>&1 || e3=$?
    o3=""
    if [ "$e3" = 0 ]; then ./build/d3.bin > build/d3.txt 2>&1 || e3=$?; o3=$(tr -d '\0' < build/d3.txt); fi
    if [ "$e0" = 0 ] && [ "$e3" != 0 ]; then
        echo "GAP  $name"; gap=$((gap+1))
    elif [ "$e0" = "$e3" ] && [ "$o0" = "$o3" ]; then
        pass=$((pass+1))
    else
        echo "FAIL $name（exit $e0 vs $e3）"; fail=$((fail+1))
    fi
done
set -e
echo "$pass 通过, $gap 待移植, $fail 失败"

printf '%-14s ' "@import"
./build/my_compiler tests/multi/main.lg build/tm1 && ./build/tm1
printf '%-14s ' "cli"
./build/my_compiler tests/multi/a.lg tests/multi/b.lg build/tm2 && ./build/tm2

./build/my_compiler examples/boot.lg build/boot.bin
cmp build/boot.bin reference/boot.bin && echo "ok"
./build/my_compiler examples/hello.lg build/hello.img
qemu-system-x86_64 -drive format=raw,file=build/hello.img