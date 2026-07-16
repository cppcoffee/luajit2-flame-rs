-- cpu-burn.lua : a deterministic CPU-burning LuaJIT workload for profiling.
-- Driven by harness.c, which calls lua_resume (C API) repeatedly -- exactly
-- the nginx/OpenResty execution model the eBPF profiler hooks into.
--
-- The hot operations below live on distinct source lines so we can verify the
-- flame graph resolves to exact file:line locations.

-- Disable JIT: profile the interpreter, where the eBPF walker can read the
-- bytecode PC -> source line mapping. JIT traces don't carry the same frame
-- layout and would show as native code.
jit.off()
jit.flush()

local work_iters = tonumber(os.getenv("LUA_FLAME_WORK_ITERS")) or 200000
local fib_n = tonumber(os.getenv("LUA_FLAME_FIB_N")) or 15
local sum_n = tonumber(os.getenv("LUA_FLAME_SUM_N")) or 40

-- Recursive fibonacci (call-heavy, shows nested Lua frames).
local function fib(n)
    if n < 2 then return n end
    return fib(n - 1) + fib(n - 2)   -- deep recursion
end

-- Arithmetic-heavy hot loop.
local function sum_squares(n)
    local s = 0
    for i = 1, n do                  -- hot inner loop
        s = s + i * i
    end
    return s
end

-- The "request handler" -- this is what harness.c resumes as a coroutine. It
-- does a chunk of CPU work then yields.
function handler()
    local total = 0
    for i = 1, work_iters do         -- outer hot loop
        total = total + fib(fib_n) + sum_squares(sum_n)
        if i % 1000 == 0 then
            coroutine.yield()        -- yield back to harness
        end
    end
    return total
end

-- This file is loaded via luaL_dofile from harness.c, so the top-level code
-- just defines `handler` and returns. The actual work happens when harness.c
-- resumes the coroutine.
