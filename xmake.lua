set_project("lgc")
set_version("0.1.0")

add_rules("mode.release", "mode.debug")

target("lgc")
    set_kind("binary")
    add_files("src/main.c")
    add_cxflags("-O3", "-flto", "-funroll-loops", "-march=native")
    add_ldflags("-flto")
    set_targetdir("build")

local function files_equal(f1, f2)
    local c1 = io.readfile(f1)
    local c2 = io.readfile(f2)
    if not c1 or not c2 then return false end
    return c1 == c2
end

local function run_capture(cmd, outfile, errfile, rcfile)
    os.exec(string.format("sh -c '%s > %s 2> %s; echo $? > %s'", cmd, outfile, errfile, rcfile))
    local rc = tonumber(io.readfile(rcfile) or "") or -1
    return rc, (io.readfile(outfile) or ""), (io.readfile(errfile) or "")
end

task("bootstrap")
    set_menu({
        usage = "xmake bootstrap",
        description = "执行编译器自举并验证"
    })
    on_run(function ()
        os.exec("xmake build lgc")

        print("注意：src/lgc.lg 尚未迁移到 v2 语法（阶段二），当前自举预计失败")
        os.exec("./build/lgc src/lgc.lg build/lgc1")
        os.exec("./build/lgc1 src/lgc.lg build/lgc2")
        os.exec("./build/lgc2 src/lgc.lg build/lgc")

        if files_equal("build/lgc2", "build/lgc") then
            print("自举验证成功：lgc2 与 lgc 一致")
        else
            print("自举验证失败：lgc2 与 lgc 不一致")
            os.raise("Bootstrap mismatch")
        end
    end)

task("test")
    set_menu({
        usage = "xmake test",
        description = "运行测试套件并统计结果"
    })
    on_run(function ()
        os.exec("xmake build lgc")

        local function run_capture(cmd, outfile, errfile, rcfile)
            os.exec(string.format("sh -c '%s > %s 2> %s; echo $? > %s'", cmd, outfile, errfile, rcfile))
            local rc = tonumber(io.readfile(rcfile) or "") or -1
            return rc, (io.readfile(outfile) or ""), (io.readfile(errfile) or "")
        end

        local tests = os.files("tests/*.lg")
        print(string.format("找到 %d 个测试文件", #tests))
        if #tests == 0 then
            print("警告：tests/*.lg 没有匹配到文件")
            return
        end

        local pass, gap, fail = 0, 0, 0
        local function run_backend(t, backend, tag)
            local bin = "build/" .. tag .. ".bin"
            local rc, _, err = run_capture(
                string.format("./build/lgc --backend=%s %s %s", backend, t, bin),
                "build/c.log", "build/c.err", "build/c.rc")
            if rc ~= 0 then return false, rc, err end
            local rrc, out = run_capture(bin, "build/" .. tag .. ".txt", "build/r.err", "build/r.rc")
            return true, rrc, (out:gsub("\0", ""))
        end
        for _, t in ipairs(tests) do
            local name = path.basename(t)
            local ok0, e0, o0 = run_backend(t, "legacy", "d0")
            local ok3, e3, o3 = run_backend(t, "ssa", "d3")
            if ok0 and not ok3 then
                print(string.format("GAP  %s（SSA 后端编译失败）", name))
                gap = gap + 1
            elseif ok0 and ok3 and e0 == e3 and o0 == o3 then
                print(string.format("PASS %-14s exit=%d", name, e0))
                pass = pass + 1
            else
                print(string.format("FAIL %s（exit %s vs %s）", name, tostring(e0), tostring(e3)))
                fail = fail + 1
            end
        end

        local errs = os.files("tests/err/*.lg")
        local epass, efail = 0, 0
        for _, t in ipairs(errs) do
            local name = path.basename(t)
            local src = io.readfile(t) or ""
            local want = src:match("// EXPECT:%s*([^\r\n]+)") or ""
            local rc, _, err = run_capture(string.format("./build/lgc %s build/err.out", t),
                "build/e.out", "build/e.err", "build/e.rc")
            if rc == 0 then
                print(string.format("FAIL err/%s（本应编译失败）", name))
                efail = efail + 1
            elseif want ~= "" and not err:find(want, 1, true) then
                print(string.format("FAIL err/%s（错误信息未包含 %q，实际：%s）", name, want, err:gsub("\n", " ")))
                efail = efail + 1
            else
                print(string.format("PASS err/%-10s %s", name, want))
                epass = epass + 1
            end
        end

        print(string.format("%d 通过, %d 待移植, %d 失败; 反例 %d 通过, %d 失败",
            pass, gap, fail, epass, efail))

        io.write(string.format("%-14s ", "@import"))
        local rc1, out1 = run_capture("./build/lgc tests/multi/main.lg build/tm1", "build/m1.log", "build/m1.err", "build/m1.rc")
        if rc1 == 0 then
            local rrc, o = run_capture("./build/tm1", "build/m1.txt", "build/m1r.err", "build/m1r.rc")
            print(string.format("exit=%d out=%s", rrc, (o:gsub("\n", " "))))
        else
            print("编译失败")
            fail = fail + 1
        end

        io.write(string.format("%-14s ", "cli"))
        local rc2, out2 = run_capture("./build/lgc tests/multi/a.lg tests/multi/b.lg build/tm2", "build/m2.log", "build/m2.err", "build/m2.rc")
        if rc2 == 0 then
            local rrc, o = run_capture("./build/tm2", "build/m2.txt", "build/m2r.err", "build/m2r.rc")
            print(string.format("exit=%d out=%s", rrc, (o:gsub("\n", " "))))
        else
            print("编译失败")
            fail = fail + 1
        end

        if fail > 0 or gap > 0 or efail > 0 then
            os.raise("测试失败")
        end
    end)

task("run-examples")
    set_menu({
        usage = "xmake run-examples",
        description = "生成示例镜像并运行 QEMU"
    })
    on_run(function ()
        os.exec("xmake build lgc")

        os.exec("./build/lgc examples/boot.lg build/boot.bin")
        if files_equal("build/boot.bin", "reference/boot.bin") then
            print("ok")
        else
            print("boot.bin 与参考文件不一致")
        end

        os.exec("./build/lgc examples/hello.lg build/hello.img")
        os.exec("qemu-system-x86_64 -drive format=raw,file=build/hello.img")
    end)
