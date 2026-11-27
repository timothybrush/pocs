/* Mirrors widget-sandbox's QuickJS setup:
 * JS_NewContext, 8 MB memory limit, 6 MB max stack, no module loader, no libc,
 * and an interrupt deadline (cpuLimitMs = 500). Adds only `print`.
 * usage: sbx [-m] [-t ms] [-M bytes] file.js */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "quickjs.h"

static double deadline;
static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}
static int interrupt(JSContext *ctx, void *opaque) {
    (void)ctx;
    (void)opaque;
    return now() > deadline;
}

static JSValue js_print(JSContext *ctx, JSValueConst this_val,
                        int argc, JSValueConst *argv) {
    (void)this_val;
    for (int i = 0; i < argc; i++) {
        const char *s = JS_ToCString(ctx, argv[i]);
        if (!s) return JS_EXCEPTION;
        printf("%s%s", i ? " " : "", s);
        JS_FreeCString(ctx, s);
    }
    printf("\n");
    fflush(stdout);
    return JS_UNDEFINED;
}

static void dump_exc(JSContext *ctx) {
    JSValue e = JS_GetException(ctx);
    const char *s = JS_ToCString(ctx, e);
    printf("EXCEPTION: %s\n", s ? s : "?");
    if (s) JS_FreeCString(ctx, s);
    JS_FreeValue(ctx, e);
}

int main(int argc, char **argv) {
    int module = 0;
    double ms = 500;
    size_t mem = (size_t)8 << 20;
    int i = 1;
    for (; i < argc && argv[i][0] == '-'; i++) {
        if (!strcmp(argv[i], "-m")) module = 1;
        else if (!strcmp(argv[i], "-t")) ms = atof(argv[++i]);
        else if (!strcmp(argv[i], "-M")) mem = strtoull(argv[++i], NULL, 0);
    }
    if (i >= argc) {
        fprintf(stderr, "usage: sbx [-m] [-t ms] [-M bytes] file.js\n");
        return 2;
    }
    FILE *f = fopen(argv[i], "rb");
    if (!f) {
        perror(argv[i]);
        return 2;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *src = malloc((size_t)n + 1);
    if (!src || fread(src, 1, (size_t)n, f) != (size_t)n) {
        fprintf(stderr, "failed to read input\n");
        fclose(f);
        free(src);
        return 2;
    }
    src[n] = 0;
    fclose(f);

    JSRuntime *rt = JS_NewRuntime();
    JS_SetMemoryLimit(rt, mem);
    JS_SetMaxStackSize(rt, (size_t)6 << 20);
    JSContext *ctx = JS_NewContext(rt);
    JS_SetInterruptHandler(rt, interrupt, NULL);
    JSValue g = JS_GetGlobalObject(ctx);
    JS_SetPropertyStr(ctx, g, "print", JS_NewCFunction(ctx, js_print, "print", 1));
    JS_FreeValue(ctx, g);

    double t0 = now();
    deadline = t0 + ms / 1000;
    JSValue v = JS_Eval(ctx, src, (size_t)n, argv[i],
                        module ? JS_EVAL_TYPE_MODULE : JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(v)) dump_exc(ctx);
    JS_FreeValue(ctx, v);
    for (;;) {
        JSContext *job_ctx;
        deadline = now() + ms / 1000;
        int result = JS_ExecutePendingJob(rt, &job_ctx);
        if (result == 0) break;
        if (result < 0) dump_exc(job_ctx);
    }
    printf("ELAPSED_MS: %.0f\n", (now() - t0) * 1000);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
    free(src);
    return 0;
}
