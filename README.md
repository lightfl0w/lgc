# lgc — 极简 x86-64 编译器

单文件、零依赖的微型编译器用于教学：把一门类 C 小语言直接编译成**原生 x86-64 机器码**。

- 编译器本体只有 **~1140 行 C**（`main.c`），只用标准 C 库
- **自举编译器** `lgc.lg`：用 lgc 语言写的 lgc 编译器（见下文"自举"）
- 生成的文件可以直接执行：
  - Linux：**ELF** 可执行文件，单 RWX 段布局，最小 **313 字节**
  - Windows：**PE32+** (.exe)，最小 **768 字节**
- 同一个二进制，按输出文件名自动选择格式：以 `.exe` 结尾输出 PE，否则输出 ELF

## 快速开始

```sh
gcc -Os -o my_compiler main.c     # 构建编译器

./my_compiler fac.lg              # 生成 Linux ELF 
./my_compiler fac.lg fac.exe      # 生成 Windows PE
```

`fac.lg` 计算 `5!` 并打印：

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

## 全局变量常驻寄存器

顶层 `let` 是全局变量，默认每次读写都是 `mov rax, [rip+off]` / `mov [rip+off], rax`——一条指令一次内存访问。编译器会挑出最热的少数全局，让它们**常驻寄存器**：

```sh
LGC_DUMP_GREG=1 ./my_compiler lgc.lg lgc1   # 打印本次选择
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

`lgc.lg` 是用 lgc 语言写成的 lgc 编译器（ELF 后端），全部裸机器码收敛到带注释的指令 helper 中，语义常量（token / AST 节点 / 运算符 / 系统调用号 / ELF 字段）均有命名。

三级自举链：

```sh
gcc -Os -o my_compiler main.c     # stage 0：C 版编译器
./my_compiler lgc.lg lgc1         # stage 1：C 版编译出第 1 级自举编译器
./lgc1 lgc.lg lgc2                # stage 2：第 1 级编译出第 2 级
./lgc2 lgc.lg lgc3                # stage 3：第 2 级编译自己
cmp lgc2 lgc3                     # 应完全一致（自举收敛）
```

## 验证

```sh
# Linux
./my_compiler fac.lg && ./a.out        # 输出 120

# Windows
./my_compiler fac.lg fac.exe && wine fac.exe   # 输出 120
```
