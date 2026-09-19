# lgc — 极简 x86-64 编译器

单文件、零依赖的微型编译器用于教学：把一门类 C 小语言直接编译成**原生 x86-64 机器码**。

- 编译器本体只有 **~1140 行 C**（`src/main.c`），只用标准 C 库
- **自举编译器** `src/lgc.lg`：用 lgc 语言写的 lgc 编译器（见下文"自举"）
- 生成的文件可以直接执行：
  - Linux：**ELF** 可执行文件，单 RWX 段布局，最小 **313 字节**
  - Windows：**PE32+** (.exe)，最小 **768 字节**
- 同一个二进制，按输出文件名自动选择格式：以 `.exe` 结尾输出 PE，否则输出 ELF

## 目录结构

```
src/       编译器源码：main.c（C 版）、lgc.lg（自举版）
tests/     回归用例（fac / feat / type / bits / global / maintest；multi/ 多文件用例）
examples/  引导 demo（boot.lg @raw 引导器、hello.lg @boot 内核、kern.lg 特权指令）
reference/ boot.bin：gas 汇编出的权威引导扇区参照
build/     全部编译产物（不入版本库）
build.sh   构建 + 自举 + 回归
```

## 快速开始

```sh
./build.sh                        # 构建编译器、跑三级自举、跑回归

./build/my_compiler tests/fac.lg              # 生成 Linux ELF
./build/my_compiler tests/fac.lg fac.exe      # 生成 Windows PE
```

`tests/fac.lg` 计算 `5!` 并打印：

```
func fac(n) {
    if (n <= 1) {
        return 1;
    } else {
        return n * fac(n - 1);
    }
}
print fac(5);
```

```sh
$ ./a.out
120
```

## 语言特性

| 语法 | 说明 |
|------|------|
| `let x = 表达式;` | 变量赋值 |
| `const 名字 = 数字;` | 命名常量（编译期替换，需先定义后使用） |
| `// 注释` | 行注释 |
| `+ - * / %` | 四则与取模（乘除优先，括号可改变结合） |
| `&& \|\| !` | 逻辑与/或（短路求值）/非 |
| `+= -= *= /= %=` | 复合赋值 |
| `'A'` | 字符字面量（支持 `\n \t \0 \\ \'`） |
| `print 表达式;` | 打印整数 |
| `if (条件) { } else { }` | 条件分支 |
| `while (条件) { }` | 循环 |
| `func 名字(参数) { return 表达式; }` | 函数定义与调用（递归支持） |
| `== != < > <= >=` | 比较运算 |
| `( 表达式 )` | 括号 |
| `extern func f(a, b);` | 声明外部函数（名字 + 元数），须在合并后的程序中有定义 |
| `extern let g;` | 声明外部全局变量，须有定义 |
| `@import "其他.lg";` | 引入其他源文件（相对当前文件目录，递归展开） |

## 多文件与 extern

程序可以拆到多个 `.lg` 文件。命令行里**最后一个位置参数是输出文件，其余全是源文件**（只给一个参数时输出 `a.out`）：

```sh
./build/my_compiler tests/multi/a.lg tests/multi/b.lg out
```

也可以在源码里用 `@import` 引入，路径相对当前文件所在目录；重复引入会自动跳过，循环引入安全：

```
@import "lib.lg";

extern func add(a, b);
extern let BASE;

func main() {
    print add(BASE, 2);
    return 0;
}
```

所有文件合并成一个程序后再编译，因此顶层 `let` / `func` 跨文件可见、前向引用天然成立。`extern` 只做**声明与校验**：函数校验存在性与参数个数，全局校验存在性；找不到定义就报错。它不分配存储、不产生代码。

## 全局变量常驻寄存器

顶层 `let` 是全局变量，默认每次读写都是 `mov rax, [rip+off]` / `mov [rip+off], rax`——一条指令一次内存访问。编译器会挑出最热的少数全局，让它们**常驻寄存器**：

```sh
LGC_DUMP_GREG=1 ./build/my_compiler src/lgc.lg lgc1   # 打印本次选择
# [greg] SRCI  -> r12 weight=256  off=1498824
# [greg] PST   -> r13 weight=211  off=1498808
```

规则：

| 项 | 做法 |
|----|------|
| 候选 | 标量全局（8 字节），数组与 `char` 标量留给内存 |
| 热度 | 遍历 AST 统计加权引用次数，循环体内的引用按 8 倍计 |
| 寄存器 | `r12~r15`，最多 4 个 |
| 映射 | 全程序唯一，寄存器即变量的权威副本 |
| 排除 | 被取址（`&g`）的全局不常驻——地址一旦逸出，内存必须保持权威 |
| 入口 | 常驻寄存器在入口显式清零（内核补零只作用于数据内存） |

因为 `r12~r15` 在生成代码的其余部分从不使用，且在两套 ABI 下都是非易失寄存器，所以函数之间**无需保存/恢复、也无需在调用点回写内存**——调用边界天然保持寄存器里的值。

## 自举

`src/lgc.lg` 是用 lgc 语言写成的 lgc 编译器（ELF 后端），全部裸机器码收敛到带注释的指令 helper 中，语义常量（token / AST 节点 / 运算符 / 系统调用号 / ELF 字段）均有命名。

三级自举链：

```sh
gcc -Os -o build/my_compiler src/main.c   # stage 0：C 版编译器
./build/my_compiler src/lgc.lg lgc1       # stage 1：C 版编译出第 1 级自举编译器
./lgc1 src/lgc.lg lgc2                    # stage 2：第 1 级编译出第 2 级
./lgc2 src/lgc.lg lgc3                    # stage 3：第 2 级编译自己
cmp lgc2 lgc3                             # 应完全一致（自举收敛）
```

## 验证

```sh
# Linux
./build/my_compiler tests/fac.lg && ./a.out    # 输出 120

# Windows
./build/my_compiler tests/fac.lg fac.exe && wine fac.exe   # 输出 120
```

`examples/` 下的引导 demo：

```sh
./build/my_compiler examples/boot.lg boot.bin     # @raw 引导器
cmp boot.bin reference/boot.bin                   # 与 gas 参照逐字节一致

./build/my_compiler examples/hello.lg hello.img   # @boot 内核镜像
qemu-system-x86_64 -drive format=raw,file=hello.img -nographic   # 输出 42 42
```
