# lgc — 极简 x86-64 编译器

单文件、零依赖的微型编译器用于教学：把一门类 C 小语言直接编译成原生 x86-64 机器码。

- 生成的文件可以直接执行：
  - Linux：ELF 可执行文件，单 RWX 段布局，最小 259 字节
  - Windows：PE32 (.exe)，最小 768 字节
- 同一个二进制，按输出文件名自动选择格式：以 `.exe` 结尾输出 PE，否则输出 ELF
- **内存安全**：`own T` 线性类型由编译器在编译期保证"恰好消费一次"，不需要 GC、也不需要 `unsafe` 逃逸口

## 目录结构

```
src/       编译器源码：main.c（C 版）、lgc.lg（待迁移）
tests/     回归用例（err/ 下为必须编译失败的反例）
examples/  引导 demo
reference/ boot.bin：gas 汇编出的权威引导扇区参照
```

## 快速开始

```sh
xmake run
```

## 语言特性

类型语法是前缀式：`own`? `*`* 基类型，基类型为 `int` / `char` / 结构体名 / `[N]` 类型。

| 语法 | 说明 |
|------|------|
| `let x = 表达式;` | 变量声明，类型自动推断 |
| `let x: int = 表达式;` | 带类型声明；`let x: int;` 允许先声明后赋值（使用前必须已赋值） |
| `let a: [5]int;` | 数组；可用 `= {1, 2, 3}` 初始化 |
| `let p: *int = &x;` | 指针（前缀 `*`，可嵌套 `**int`） |
| `let p: own T = new T;` | 堆所有权值（见"线性类型"一节） |
| `const 名字 = 数字;` | 命名常量（编译期替换，需先定义后使用） |
| `// 注释` | 行注释 |
| `+ - * / %` | 四则与取模（乘除优先，括号可改变结合） |
| `& \| ^ ~ << >>` | 位运算 |
| `&& \|\| !` | 逻辑与/或（短路求值）/非 |
| `+= -= *= /= %=` | 复合赋值 |
| `'A'` | 字符字面量（支持 `\n \t \0 \\ \'`） |
| `if (条件) { } else { }` | 条件分支 |
| `while (条件) { }` | 循环 |
| `for (init; cond; inc) { }` | for 循环（init 可为 `let`；`break`/`continue` 适用） |
| `switch (x) { case n: … default: … }` | 分支跳转（`break` 跳出） |
| `type Point = { x: int, y: int };` | 结构体（可嵌套，`a.b.c` 成员访问，支持数组） |
| `enum { A, B = 5, C };` | 枚举常量 |
| `print 表达式, "文本", …;` | 依次打印：整数按十进制、字符串原样输出（不自动加换行） |
| `fn 名字(a: int, b: *char) -> int { … }` | 函数定义与调用（递归支持）；返回类型可省略，默认 `int` |
| `fn add(a: int, b: int) -> int { a + b }` | 块内单个表达式作为返回值 |
| `== != < > <= >=` | 比较运算 |
| `( 表达式 )` | 括号 |
| `drop x;` | 释放 `own` 值 |
| `extern fn f(a: int) -> int;` | 声明外部函数（参数类型 + 返回类型），须在合并后的程序中有定义 |
| `extern let g: int;` | 声明外部全局变量，须有定义 |
| `import "其他.lg";` | 引入其他源文件（相对当前文件目录，递归展开） |

## 线性类型与内存安全

lgc v2 的堆值用 `own T` 表示。编译器在编译期强制每个堆值**恰好被消费一次**，规则很少但完整：

| 操作 | 语义 |
|------|------|
| `new T` | 分配一块零初始化的 `T`，返回 `own T`（Linux ELF 下用 `mmap` 实现） |
| `drop x;` | 释放 `own` 值 |
| 赋值 / 传参 / `return` | 发生 **move**：源变量立即失效，再使用会报 use-after-move |
| `&x`（x 是 `own` 值） | 借用，得到一个普通 `*T`；**只在当前语句内有效**，且只允许直接作为调用实参 |
| `*x` / `x.field` | 通过 `own` 值读写内容（成员访问自动解引用），不消费所有权 |

编译期检查（`src/main.c` 中的 `chk_run`）：

- 作用域结束时仍存活的 `own` 值 = 编译错误（必须 drop / move / return）；
- `if`/`else` 两个分支对同一 `own` 值的消费状态必须一致；
- 循环/`switch` 内不允许消费外部定义的 `own` 值（会执行多次）；
- 借用期间不能 move / drop 该值；借用不能存进变量；
- 结构体暂不允许 `own` 字段，全局变量不能是 `own`；
- `own` 仅支持 ELF 用户态输出（PE / 裸机模式使用 `new` 会报错）。

示例：

```
type Point = { x: int, y: int };

fn make() -> own Point {
    let p: own Point = new Point;
    p.x = 1;
    return p;              // move 出函数
}

fn main() -> int {
    let a = make();
    print a.x, "\n";       // 自动解引用
    let b = a;             // move：a 之后不可再用
    drop b;
    return 0;
}
```

## 堆分配实现

编译器只在程序真正用到 `new`/`drop` 时才内嵌两个小例程（与 print 例程同样的按需生成策略）：

- `__lgc_alloc(size)`：`mmap(NULL, size + 16, RW, PRIVATE|ANONYMOUS)`，头部存长度，返回 `+16`；
- `__lgc_drop(ptr)`：读头部长度，`munmap` 整块。

因此不使用 `own` 的程序二进制大小不受影响。

## 多文件与 extern

程序可以拆到多个 `.lg` 文件。命令行里**最后一个位置参数是输出文件，其余全是源文件**（只给一个参数时输出 `a.out`）：

```sh
lgc tests/multi/a.lg tests/multi/b.lg out
```

也可以在源码里用 `import` 引入，路径相对当前文件所在目录；重复引入会自动跳过，循环引入安全：

```
import "lib.lg";

extern fn add(a: int, b: int) -> int;
extern let BASE: int;

fn main() -> int {
    print add(BASE, 2);
    return 0;
}
```

## 全局变量常驻寄存器

顶层 `let` 是全局变量，默认每次读写都是 `mov rax, [rip+off]` / `mov [rip+off], rax`——一条指令一次内存访问。编译器会挑出最热的少数全局，让它们常驻寄存器：

```sh
LGC_DUMP_GREG=1 lgc src/lgc.lg lgc1   # 打印本次选择
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

## 验证

```sh
xmake test
```

测试分三部分：

1. **差分**：每个 `tests/*.lg` 分别用 `--backend=legacy` 与 `--backend=ssa` 编译运行，退出码与输出必须一致；
2. **反例**：`tests/err/*.lg` 必须编译失败，且 stderr 含文件首行 `// EXPECT: 片段`；
3. **多文件**：`@import` 与命令行多源文件各一组。

`examples/` 下的引导 demo：

```sh
xmake run-examples
```

其中 `examples/boot.lg` 必须与 `reference/boot.bin` 字节完全一致。

## 安装到系统
```sh
xmake install
```
