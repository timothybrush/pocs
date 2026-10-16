#include <pspdisplay.h>
#include <pspkernel.h>
#include <string.h>

#include "visual.h"
#include "logo_data.h"


#define SCREEN_W 480
#define SCREEN_H 272
#define FB_STRIDE 512
#define LOGO_LEFT ((SCREEN_W - LOGO_WIDTH) / 2)
#define LOGO_TOP 31
#define CLIMAX_PHASE_FRAMES 15u
#define CLIMAX_FRAMES 60u
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define RGBA(r, g, b) ((u32)(r) | ((u32)(g) << 8) | ((u32)(b) << 16) | 0xff000000u)

static volatile u32 *const g_fb = (volatile u32 *)0x44000000u;
enum {
    VISUAL_INTRO,
    VISUAL_STAGE,
    VISUAL_CLIMAX,
    VISUAL_FAILURE,
};

static volatile unsigned int g_visual_mode;
static volatile unsigned int g_intro_frame;
static volatile unsigned int g_render_frame;
static volatile unsigned int g_climax_frame;
static volatile unsigned int g_climax_done;
static volatile unsigned int g_stage_progress;
static const char *volatile g_stage_headline = "PRIMING MEDIA ENGINE";
static const char *volatile g_stage_detail = "MPEG AVC LEAK CHANNEL";
static int g_visual_thread = -1;

static const u32 COLOR_BG = RGBA(246, 244, 240);
static const u32 COLOR_GRID = RGBA(231, 227, 221);
static const u32 COLOR_CHARCOAL = RGBA(42, 38, 38);
static const u32 COLOR_MUTED = RGBA(103, 95, 91);
static const u32 COLOR_GOLD = RGBA(224, 172, 65);
static const u32 COLOR_GOLD_SOFT = RGBA(239, 207, 167);
static const u32 COLOR_FAILURE = RGBA(184, 55, 55);

typedef struct {
    char character;
    u8 row[7];
} Glyph;

typedef struct {
    short x;
    short y;
    u8 phase;
} Sparkle;

static const Glyph kGlyphs[] = {
    {' ', {0x00,0x00,0x00,0x00,0x00,0x00,0x00}},
    {'-', {0x00,0x00,0x00,0x1f,0x00,0x00,0x00}},
    {'.', {0x00,0x00,0x00,0x00,0x00,0x0c,0x0c}},
    {'/', {0x01,0x02,0x04,0x08,0x10,0x00,0x00}},
    {'0', {0x0e,0x11,0x13,0x15,0x19,0x11,0x0e}},
    {'1', {0x04,0x0c,0x04,0x04,0x04,0x04,0x0e}},
    {'2', {0x0e,0x11,0x01,0x02,0x04,0x08,0x1f}},
    {'3', {0x1e,0x01,0x01,0x0e,0x01,0x01,0x1e}},
    {'4', {0x02,0x06,0x0a,0x12,0x1f,0x02,0x02}},
    {'5', {0x1f,0x10,0x10,0x1e,0x01,0x01,0x1e}},
    {'6', {0x0e,0x10,0x10,0x1e,0x11,0x11,0x0e}},
    {'7', {0x1f,0x01,0x02,0x04,0x08,0x08,0x08}},
    {'8', {0x0e,0x11,0x11,0x0e,0x11,0x11,0x0e}},
    {'9', {0x0e,0x11,0x11,0x0f,0x01,0x01,0x0e}},
    {'A', {0x0e,0x11,0x11,0x1f,0x11,0x11,0x11}},
    {'B', {0x1e,0x11,0x11,0x1e,0x11,0x11,0x1e}},
    {'C', {0x0f,0x10,0x10,0x10,0x10,0x10,0x0f}},
    {'D', {0x1e,0x11,0x11,0x11,0x11,0x11,0x1e}},
    {'E', {0x1f,0x10,0x10,0x1e,0x10,0x10,0x1f}},
    {'F', {0x1f,0x10,0x10,0x1e,0x10,0x10,0x10}},
    {'G', {0x0f,0x10,0x10,0x17,0x11,0x11,0x0f}},
    {'H', {0x11,0x11,0x11,0x1f,0x11,0x11,0x11}},
    {'I', {0x0e,0x04,0x04,0x04,0x04,0x04,0x0e}},
    {'J', {0x01,0x01,0x01,0x01,0x11,0x11,0x0e}},
    {'K', {0x11,0x12,0x14,0x18,0x14,0x12,0x11}},
    {'L', {0x10,0x10,0x10,0x10,0x10,0x10,0x1f}},
    {'M', {0x11,0x1b,0x15,0x15,0x11,0x11,0x11}},
    {'N', {0x11,0x19,0x19,0x15,0x13,0x13,0x11}},
    {'O', {0x0e,0x11,0x11,0x11,0x11,0x11,0x0e}},
    {'P', {0x1e,0x11,0x11,0x1e,0x10,0x10,0x10}},
    {'Q', {0x0e,0x11,0x11,0x11,0x15,0x12,0x0d}},
    {'R', {0x1e,0x11,0x11,0x1e,0x14,0x12,0x11}},
    {'S', {0x0f,0x10,0x10,0x0e,0x01,0x01,0x1e}},
    {'T', {0x1f,0x04,0x04,0x04,0x04,0x04,0x04}},
    {'U', {0x11,0x11,0x11,0x11,0x11,0x11,0x0e}},
    {'V', {0x11,0x11,0x11,0x11,0x11,0x0a,0x04}},
    {'W', {0x11,0x11,0x11,0x15,0x15,0x1b,0x11}},
    {'X', {0x11,0x11,0x0a,0x04,0x0a,0x11,0x11}},
    {'Y', {0x11,0x11,0x0a,0x04,0x04,0x04,0x04}},
    {'Z', {0x1f,0x01,0x02,0x04,0x08,0x10,0x1f}},
};

static const Sparkle kSparkles[] = {
    {74, 58, 0x08}, {126, 143, 0x39}, {203, 42, 0x77},
    {276, 94, 0xa2}, {385, 58, 0xd0}, {414, 143, 0x1f},
    {101, 124, 0x59}, {247, 168, 0xc1}, {356, 164, 0x88},
    {164, 105, 0xe4}, {437, 111, 0x48}, {54, 101, 0xb0},
};


static void blend_pixel(int x, int y, u32 color, unsigned int alpha)
{
    u32 old;
    unsigned int inv;
    unsigned int r;
    unsigned int g;
    unsigned int b;

    if ((unsigned int)x >= SCREEN_W || (unsigned int)y >= SCREEN_H || alpha == 0)
        return;
    if (alpha > 255)
        alpha = 255;
    old = g_fb[y * FB_STRIDE + x];
    inv = 255 - alpha;
    r = ((old & 0xffu) * inv + (color & 0xffu) * alpha) / 255u;
    g = (((old >> 8) & 0xffu) * inv + ((color >> 8) & 0xffu) * alpha) / 255u;
    b = (((old >> 16) & 0xffu) * inv + ((color >> 16) & 0xffu) * alpha) / 255u;
    g_fb[y * FB_STRIDE + x] = RGBA(r, g, b);
}

static void draw_rect(int x, int y, int width, int height, u32 color)
{
    int x0 = x < 0 ? 0 : x;
    int y0 = y < 0 ? 0 : y;
    int x1 = x + width > SCREEN_W ? SCREEN_W : x + width;
    int y1 = y + height > SCREEN_H ? SCREEN_H : y + height;
    int py;

    for (py = y0; py < y1; ++py) {
        int px;
        for (px = x0; px < x1; ++px)
            g_fb[py * FB_STRIDE + px] = color;
    }
}

static void clear_scene(void)
{
    int y;
    for (y = 0; y < SCREEN_H; ++y) {
        int x;
        for (x = 0; x < FB_STRIDE; ++x)
            g_fb[y * FB_STRIDE + x] = COLOR_BG;
    }
    for (y = 15; y < SCREEN_H; y += 16)
        draw_rect(0, y, SCREEN_W, 1, COLOR_GRID);
    draw_rect(18, 14, 34, 2, COLOR_GOLD);
    draw_rect(18, 14, 2, 16, COLOR_GOLD);
    draw_rect(SCREEN_W - 52, 14, 34, 2, COLOR_GOLD);
    draw_rect(SCREEN_W - 20, 14, 2, 16, COLOR_GOLD);
}

static const u8 *glyph_rows(char character)
{
    unsigned int index;
    for (index = 0; index < ARRAY_SIZE(kGlyphs); ++index) {
        if (kGlyphs[index].character == character)
            return kGlyphs[index].row;
    }
    return kGlyphs[0].row;
}

static int text_width(const char *text, int scale)
{
    int count = 0;
    while (text[count])
        ++count;
    return count ? count * 6 * scale - scale : 0;
}

static void draw_text(int x, int y, int scale, const char *text, u32 color)
{
    int origin = x;
    while (*text) {
        const u8 *rows = glyph_rows(*text++);
        int row;
        for (row = 0; row < 7; ++row) {
            int column;
            for (column = 0; column < 5; ++column) {
                if (rows[row] & (1u << (4 - column)))
                    draw_rect(origin + column * scale, y + row * scale, scale, scale, color);
            }
        }
        origin += 6 * scale;
    }
}

static void draw_centered_text(int y, int scale, const char *text, u32 color)
{
    draw_text((SCREEN_W - text_width(text, scale)) / 2, y, scale, text, color);
}

static void draw_logo(unsigned int rows, u32 color)
{
    unsigned int index;
    if (rows > LOGO_HEIGHT)
        rows = LOGO_HEIGHT;
    for (index = 0; index < LOGO_RUN_COUNT; ++index) {
        const LogoRun *run = &kLogoRuns[index];
        if (run->y >= rows)
            continue;
        draw_rect(LOGO_LEFT + run->x1 + 2, LOGO_TOP + run->y + 2,
                  run->x2 - run->x1, 1, COLOR_GOLD_SOFT);
    }
    for (index = 0; index < LOGO_RUN_COUNT; ++index) {
        const LogoRun *run = &kLogoRuns[index];
        if (run->y >= rows)
            continue;
        draw_rect(LOGO_LEFT + run->x1, LOGO_TOP + run->y,
                  run->x2 - run->x1, 1, color);
    }
}

static void draw_star(int x, int y, int radius, unsigned int alpha)
{
    int offset;
    blend_pixel(x, y, COLOR_GOLD, alpha);
    for (offset = 1; offset <= radius; ++offset) {
        unsigned int arm_alpha = alpha * (unsigned int)(radius - offset + 1) /
                                 (unsigned int)(radius + 1);
        blend_pixel(x - offset, y, COLOR_GOLD, arm_alpha);
        blend_pixel(x + offset, y, COLOR_GOLD, arm_alpha);
        blend_pixel(x, y - offset, COLOR_GOLD, arm_alpha);
        blend_pixel(x, y + offset, COLOR_GOLD, arm_alpha);
    }
    for (offset = 1; offset <= radius / 3; ++offset) {
        unsigned int diag_alpha = alpha / (unsigned int)(offset + 2);
        blend_pixel(x - offset, y - offset, COLOR_GOLD, diag_alpha);
        blend_pixel(x + offset, y - offset, COLOR_GOLD, diag_alpha);
        blend_pixel(x - offset, y + offset, COLOR_GOLD, diag_alpha);
        blend_pixel(x + offset, y + offset, COLOR_GOLD, diag_alpha);
    }
}

static void draw_sparkles(unsigned int frame)
{
    unsigned int index;
    for (index = 0; index < ARRAY_SIZE(kSparkles); ++index) {
        unsigned int phase = (kSparkles[index].phase + frame * 5u) & 0xffu;
        unsigned int wave = phase < 128 ? phase * 2u : (255u - phase) * 2u;
        if (wave > 36)
            draw_star(kSparkles[index].x, kSparkles[index].y,
                      2 + (int)(wave / 32u), wave);
    }
}

static void draw_scan_beam(unsigned int frame)
{
    int x = LOGO_LEFT - 16 + (int)((frame * 4u) % (LOGO_WIDTH + 32u));
    int y;
    for (y = LOGO_TOP; y < LOGO_TOP + LOGO_HEIGHT; ++y) {
        blend_pixel(x, y, COLOR_GOLD, 150);
        blend_pixel(x - 1, y, COLOR_GOLD, 55);
        blend_pixel(x + 1, y, COLOR_GOLD, 55);
    }
}

static void draw_progress(unsigned int progress, u32 accent)
{
    const int left = 60;
    const int top = 246;
    const int width = 360;
    unsigned int node;

    if (progress > 100)
        progress = 100;
    draw_rect(left, top, width, 2, COLOR_GRID);
    draw_rect(left, top, (int)(width * progress / 100u), 2, accent);
    for (node = 0; node <= 4; ++node) {
        int x = left + (int)(width * node / 4u);
        u32 color = progress >= node * 25u ? accent : COLOR_GRID;
        draw_rect(x - 2, top - 2, 5, 6, color);
    }
}

static void draw_scene(unsigned int frame, unsigned int logo_rows,
                       const char *headline, const char *detail,
                       unsigned int progress, u32 accent, int scan)
{
    clear_scene();
    draw_centered_text(8, 1, "V12 SECURITY RESEARCH", COLOR_MUTED);
    draw_logo(logo_rows, COLOR_CHARCOAL);
    if (scan)
        draw_scan_beam(frame);
    draw_sparkles(frame);
    if (logo_rows < LOGO_HEIGHT) {
        int scan_y = LOGO_TOP + (int)logo_rows;
        draw_rect(LOGO_LEFT - 5, scan_y, LOGO_WIDTH + 10, 2, accent);
    }
    draw_centered_text(193, 2, headline, COLOR_CHARCOAL);
    draw_centered_text(219, 1, detail, COLOR_MUTED);
    draw_progress(progress, accent);
    sceDisplayWaitVblankStart();
}

static int visual_thread_main(SceSize args, void *argp)
{
    (void)args;
    (void)argp;

    for (;;) {
        unsigned int mode = g_visual_mode;
        unsigned int frame = g_render_frame++;

        if (mode == VISUAL_INTRO) {
            unsigned int intro = g_intro_frame++;
            unsigned int rows = intro < 9 ? intro * LOGO_HEIGHT / 9u : LOGO_HEIGHT;
            const char *headline;
            const char *detail;

            if (intro < 9) {
                headline = "SIGNAL ACQUISITION";
                detail = "GUEST DISPLAY CHANNEL";
            } else if (intro < 18) {
                headline = "ARMING ESCAPE 03";
                detail = "PPSSPP / SECURITY DEMO";
            } else if (intro < 27) {
                headline = "ARMING ESCAPE 02";
                detail = "ASLR LEAK ONLINE";
            } else if (intro < 36) {
                headline = "ARMING ESCAPE 01";
                detail = "HEAP ORACLE ONLINE";
            } else {
                headline = "PIERCE THE SANDBOX";
                detail = "GUEST TO HOST";
            }
            draw_scene(frame, rows, headline, detail,
                       intro < 45 ? intro * 100u / 44u : 100u,
                       COLOR_GOLD, intro >= 9);
            if (intro >= 44)
                g_visual_mode = VISUAL_STAGE;
        } else if (mode == VISUAL_CLIMAX) {
            unsigned int climax = g_climax_frame;
            const char *headline;
            const char *detail;

            if (climax < CLIMAX_PHASE_FRAMES) {
                headline = "HOST CONTROL IN 03";
                detail = "ROP CHAIN ARMED";
            } else if (climax < 2u * CLIMAX_PHASE_FRAMES) {
                headline = "HOST CONTROL IN 02";
                detail = "VIRTUAL CALL CAPTURED";
            } else if (climax < 3u * CLIMAX_PHASE_FRAMES) {
                headline = "HOST CONTROL IN 01";
                detail = "STACK PIVOT READY";
            } else {
                headline = "BREAK THE SANDBOX";
                detail = "CALCULATOR INCOMING";
            }
            draw_scene(frame, LOGO_HEIGHT, headline, detail,
                       75u + climax * 25u / (CLIMAX_FRAMES - 1u),
                       COLOR_GOLD, 1);
            if (climax + 1u < CLIMAX_FRAMES)
                g_climax_frame = climax + 1u;
            else
                g_climax_done = 1;
        } else if (mode == VISUAL_FAILURE) {
            draw_scene(frame, LOGO_HEIGHT, "ESCAPE DID NOT CONVERGE",
                       "RELAUNCH THE DISC", 100, COLOR_FAILURE, 0);
        } else {
            draw_scene(frame, LOGO_HEIGHT, g_stage_headline, g_stage_detail,
                       g_stage_progress, COLOR_GOLD, 1);
        }
        sceKernelDelayThread(33333);
    }
    return 0;
}

void visual_intro(void)
{
    sceDisplaySetMode(0, SCREEN_W, SCREEN_H);
    draw_rect(0, 0, SCREEN_W, SCREEN_H, COLOR_BG);
    sceDisplaySetFrameBuf((void *)g_fb, FB_STRIDE,
                          PSP_DISPLAY_PIXEL_FORMAT_8888,
                          PSP_DISPLAY_SETBUF_IMMEDIATE);
    g_visual_mode = VISUAL_INTRO;
    g_intro_frame = 0;
    g_render_frame = 0;
    g_climax_frame = 0;
    g_climax_done = 0;
    g_stage_progress = 0;
    draw_scene(0, 1, "SIGNAL ACQUISITION", "GUEST DISPLAY CHANNEL",
               0, COLOR_GOLD, 0);

    g_visual_thread = sceKernelCreateThread(
        "v12-render", visual_thread_main, 0x30, 0x4000, 0, NULL);
    if (g_visual_thread >= 0)
        sceKernelStartThread(g_visual_thread, 0, NULL);
}

void visual_stage(const char *headline, const char *detail, unsigned int progress)
{
    g_stage_headline = headline;
    g_stage_detail = detail;
    g_stage_progress = progress;
    if (g_visual_mode != VISUAL_INTRO && g_visual_mode != VISUAL_CLIMAX)
        g_visual_mode = VISUAL_STAGE;
}

void visual_climax(void)
{
    if (g_visual_thread < 0) {
        draw_scene(g_render_frame, LOGO_HEIGHT, "BREAK THE SANDBOX",
                   "CALCULATOR INCOMING", 100, COLOR_GOLD, 1);
        return;
    }
    while (g_intro_frame < 24)
        sceKernelDelayThread(5000);
    g_climax_frame = 0;
    g_climax_done = 0;
    g_visual_mode = VISUAL_CLIMAX;
    while (!g_climax_done)
        sceKernelDelayThread(5000);
}

void visual_failure(void)
{
    g_visual_mode = VISUAL_FAILURE;
    if (g_visual_thread < 0)
        draw_scene(g_render_frame, LOGO_HEIGHT, "ESCAPE DID NOT CONVERGE",
                   "RELAUNCH THE DISC", 100, COLOR_FAILURE, 0);
}
