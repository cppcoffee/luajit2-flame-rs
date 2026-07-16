-- cpu-burn.lua : a deterministic CPU-burning LuaJIT workload for profiling.
-- Driven by harness.c, which calls lua_resume (C API) repeatedly -- exactly
-- the nginx/OpenResty execution model the eBPF profiler hooks into.
--
-- The hot operations below fan out through several helper stages so the flame
-- graph shows more than one Lua source line and a few nested call chains.

-- Disable JIT: profile the interpreter, where the eBPF walker can read the
-- bytecode PC -> source line mapping. JIT traces don't carry the same frame
-- layout and would show as native code.
jit.off()
jit.flush()

local work_iters = tonumber(os.getenv("LUA_FLAME_WORK_ITERS")) or 200000
local fib_n = tonumber(os.getenv("LUA_FLAME_FIB_N")) or 15
local sum_n = tonumber(os.getenv("LUA_FLAME_SUM_N")) or 40
local scan_n = tonumber(os.getenv("LUA_FLAME_SCAN_N")) or 24
local round_n = tonumber(os.getenv("LUA_FLAME_ROUND_N")) or 6

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

-- Deterministic request-shaping pass: a small arithmetic mixer that mutates
-- the seed across a fixed number of rounds.
local function rotate_seed(seed, rounds)
    local x = seed
    for i = 1, rounds do
        x = (x * 33 + i * 17 + seed) % 1000003
    end
    return x
end

-- A slightly deeper stage that calls the mixer twice, which gives the flame
-- graph an intermediate frame to show under the request handler.
local function scan_record(seed)
    local x = rotate_seed(seed, scan_n)
    local y = 0
    for i = 1, round_n do
        y = y + rotate_seed(x + i, round_n)
    end
    return x + y
end

-- Combine the scan with the recursive and arithmetic hot spots above.
local function enrich_record(seed)
    local total = scan_record(seed)
    total = total + fib(fib_n)
    total = total + sum_squares(sum_n)
    return total
end

-- Batch a few records together so the flame graph gets multiple branches that
-- all share the same top-level handler.
local function aggregate_batch(seed)
    local total = 0
    for i = 1, 4 do
        total = total + enrich_record(seed + i)
    end
    return total
end

-- Final request-shaped stage: take one larger batch and one follow-up pass.
local function render_response(seed)
    local left = aggregate_batch(seed)
    local right = enrich_record(seed + left)
    return left + right
end

-- The "request handler" -- this is what harness.c resumes as a coroutine. It
-- does a chunk of CPU work then yields.
function handler()
    local total = 0
    for i = 1, work_iters do         -- outer hot loop
        local seed = rotate_seed(i, round_n)
        total = total + scan_record(seed)
        total = total + enrich_record(seed + total)
        total = total + aggregate_batch(seed + i)
        total = total + render_response(seed + total)
        if i % 1000 == 0 then
            coroutine.yield()        -- yield back to harness
        end
    end
    return total
end

-- This file is loaded via luaL_dofile from harness.c, so the top-level code
-- just defines `handler` and returns. The actual work happens when harness.c
-- resumes the coroutine.
