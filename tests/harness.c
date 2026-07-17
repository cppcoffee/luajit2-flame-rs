/* harness.c : embeds LuaJIT and repeatedly calls lua_resume on a coroutine,
 * mimicking the nginx/OpenResty "one request = one lua_resume" execution
 * model that the eBPF profiler is designed to hook.
 *
 * Build:
 *   cc -O2 harness.c -o /tmp/lua-harness \
 *      -I/usr/local/include/luajit-2.1 \
 *      -L/usr/local/lib -lluajit-5.1 -lm -ldl -Wl,-rpath=/usr/local/lib
 */
#include <stdio.h>
#include <stdlib.h>
#include <lauxlib.h>
#include <lualib.h>

static long env_long(const char *name, long default_value) {
    const char *value = getenv(name);
    if (!value || !*value) {
        return default_value;
    }
    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    if (end == value || parsed <= 0) {
        return default_value;
    }
    return parsed;
}

int main(int argc, char **argv) {
    const char *script = (argc > 1) ? argv[1] : "cpu-burn.lua";
    long max_iters = env_long("LUAJIT2_FLAME_RS_HARNESS_ITERS", 1000000000L);

    lua_State *L = luaL_newstate();
    luaL_openlibs(L);

    /* load (compile) the script -- this defines `handler` etc. but does
     * NOT run them yet (we wrap the whole thing in a coroutine). */
    if (luaL_dofile(L, script) != 0) {
        fprintf(stderr, "load error: %s\n", lua_tostring(L, -1));
        return 1;
    }

    /* the script registers a global `make_handler()` that returns a
     * coroutine factory; here we just repeatedly resume a fresh coroutine
     * to drive cpu work via lua_resume (the C API entry point). */
    for (long iter = 0; iter < max_iters; iter++) {
        /* create a fresh coroutine running `handler` each "request" */
        lua_getglobal(L, "coroutine");
        lua_getfield(L, -1, "create");
        lua_getglobal(L, "handler");
        if (lua_pcall(L, 1, 1, 0) != 0) {
            fprintf(stderr, "create error: %s\n", lua_tostring(L, -1));
            break;
        }
        lua_State *co = lua_tothread(L, -1);

        /* drive the coroutine to completion with lua_resume -- this is the
         * call the uprobe attaches to. */
        int nres;
        int status;
        while ((status = lua_resume(co, 0)) == LUA_YIELD) {
            /* yielded (coroutine.yield) -- resume again */
        }
        if (status != LUA_OK) {
            fprintf(stderr, "resume error: %s\n", lua_tostring(co, -1));
            break;
        }
        lua_pop(L, 2); /* pop coroutine + coroutine table */
    }

    lua_close(L);
    return 0;
}
