# lgc — 极简 x86-64 编译器

单文件、零依赖的微型编译器用于教学：把一门类 C 小语言直接编译成**原生 x86-64 机器码**。

- 编译器本体只有 **724 行 C**（`main.c`），只用标准 C 库
- 生成的文件可以直接执行：
  - Linux：**ELF** 可执行文件，最小 **324 字节**
  - Windows：**PE32+** (.exe)，最小 **784 字节**
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
| `print 表达式;` | 打印整数 |
| `if (条件) { } else { }` | 条件分支 |
| `while (条件) { }` | 循环 |
| `func 名字(参数) { return 表达式; }` | 函数定义与调用（递归支持） |
| `+ - * /` | 四则运算（乘除优先，括号可改变结合） |
| `== != < > <= >=` | 比较运算 |
| `( 表达式 )` | 括号 |

## 验证

```sh
# Linux
./my_compiler fac.lg && ./a.out        # 输出 120

# Windows
./my_compiler fac.lg fac.exe && wine fac.exe   # 输出 120
```
