/* Desktop simulator: the real UI code in a Win32 window (240x135 scaled up), driven by the PC keyboard.
 *   sim [testdata dir]      works on a COPY of the databases in %TEMP%\cardpass_sim (master password: test)
 * Keys: type normally; arrows = fn+; , . /; Esc = fn+`; Ctrl+letter = fn+letter (Ctrl+L lock, Ctrl+S save);
 * Delete = fn+Backspace. F1: zoom 1x / 2x / 3x / 4x. Runs at 60 fps like the device loop. Typing, Wi-Fi, Bluetooth and the USB drive are fake. Not the device: see docs/qemu.md. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mmsystem.h>
#include <stdio.h>
#include <string.h>
#include "../../components/ui/app_priv.h"

static int SCALE = 4;            /* F1 cycles 1x..4x: 1x is closest to the 243-ppi panel seen from a normal distance */
static app A;

/* ---- the Cardputer's memory, not the PC's: every malloc of CardPass is counted against the device's free heap
 * (linked with --wrap=malloc,calloc,realloc,free). Past it, allocations fail as they would on the ESP32-S3. ---- */
#define DEVICE_HEAP (280 * 1024)   /* QEMU measured ~318 KB free after boot; minus USB stack and 2 display DMA buffers */
#define HDR 16
void *__real_malloc(size_t n);
void *__real_realloc(void *p, size_t n);
void __real_free(void *p);
static size_t heap_used, heap_peak;
void *__wrap_malloc(size_t n)
{
    if (heap_used + n > DEVICE_HEAP) return NULL;
    unsigned char *p = __real_malloc(n + HDR);
    if (!p) return NULL;
    memcpy(p, &n, sizeof n);
    if ((heap_used += n) > heap_peak) heap_peak = heap_used;
    return p + HDR;
}
void *__wrap_calloc(size_t a, size_t b)
{
    if (b && a > (size_t)-1 / b) return NULL;
    void *p = __wrap_malloc(a * b);
    if (p) memset(p, 0, a * b);
    return p;
}
void __wrap_free(void *q)
{
    if (!q) return;
    unsigned char *p = (unsigned char *)q - HDR;
    size_t n;
    memcpy(&n, p, sizeof n);
    heap_used -= n;
    __real_free(p);
}
void *__wrap_realloc(void *q, size_t n)
{
    if (!q) return __wrap_malloc(n);
    unsigned char *p = (unsigned char *)q - HDR;
    size_t old;
    memcpy(&old, p, sizeof old);
    if (heap_used - old + n > DEVICE_HEAP) return NULL;
    unsigned char *r = __real_realloc(p, n + HDR);
    if (!r) return NULL;
    memcpy(r, &n, sizeof n);
    heap_used = heap_used - old + n;
    if (heap_used > heap_peak) heap_peak = heap_used;
    return r + HDR;
}

/* ---- the Cardputer's speed for the slow parts (estimates until docs/first-hardware.md 3j measures them) ----
 * SD card over SPI at 20 MHz: every fread / fwrite of CardPass (the database, the Argon2 swap file) costs a command
 * latency plus its bytes at the card's throughput. CPU: an Argon2 block costs what the 240 MHz ESP32-S3 needs, charged
 * through the idle hook Argon2 calls every 256 blocks. F2 switches between Cardputer and PC speed. */
#define SD_READ_US 400.0          /* per read command */
#define SD_READ_BPS 1800000.0     /* bytes per second */
#define SD_WRITE_US 600.0
#define SD_WRITE_BPS 1200000.0
#define ARGON2_BLOCK_US 150.0     /* one 1 KiB block (BLAKE2b-based compression, 64-bit maths on a 32-bit core) */
static bool device_speed = true;
static double debt_us;            /* time owed to the model, paid in whole milliseconds */
static void pay(double us)
{
    if (!device_speed) return;
    debt_us += us;
    if (debt_us < 2000) return;
    DWORD t0 = timeGetTime();
    Sleep((DWORD)(debt_us / 1000));
    debt_us -= (timeGetTime() - t0) * 1000.0;                  /* what was really slept, overshoot included */
}
size_t __real_fread(void *p, size_t s, size_t n, FILE *f);
size_t __real_fwrite(const void *p, size_t s, size_t n, FILE *f);
size_t __wrap_fread(void *p, size_t s, size_t n, FILE *f)
{
    size_t r = __real_fread(p, s, n, f);
    pay(SD_READ_US + (double)(r * s) * 1e6 / SD_READ_BPS);
    return r;
}
size_t __wrap_fwrite(const void *p, size_t s, size_t n, FILE *f)
{
    size_t r = __real_fwrite(p, s, n, f);
    pay(SD_WRITE_US + (double)(r * s) * 1e6 / SD_WRITE_BPS);
    return r;
}
static void argon2_cpu(void) { pay(256 * ARGON2_BLOCK_US); }

static void heap_title(void)
{
    static size_t shown_used = (size_t)-1, shown_peak;
    static int shown_speed = -1;
    extern HWND hwnd_main;
    if (heap_used == shown_used && heap_peak == shown_peak && shown_speed == device_speed) return;
    shown_used = heap_used, shown_peak = heap_peak, shown_speed = device_speed;
    char t[200];
    snprintf(t, sizeof t, "CardPass simulator (password: test) | %s | heap %u / %u KB, peak %u KB",
             device_speed ? "Cardputer speed (SD + Argon2 estimated), F2: PC speed" : "PC speed, F2: Cardputer speed",
             (unsigned)(heap_used / 1024), DEVICE_HEAP / 1024, (unsigned)(heap_peak / 1024));
    SetWindowTextA(hwnd_main, t);
}
static uint16_t panel[UI_W * UI_H];
static uint32_t bgr[UI_W * UI_H];
static HWND hwnd;
HWND hwnd_main;
static char wdir[MAX_PATH];
static bool quit;

static int list_files(void *c, const char *ext, char names[][64], int max)
{
    (void)c;
    char pat[MAX_PATH + 8];
    snprintf(pat, sizeof pat, "%s\\*%s", wdir, ext);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    int n = 0;
    size_t el = strlen(ext);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        size_t l = strlen(fd.cFileName);
        if (l > el && l < 64 && !_stricmp(fd.cFileName + l - el, ext) && n < max) snprintf(names[n++], 64, "%s", fd.cFileName);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    for (int i = 1; i < n; i++)                          /* sorted like the device */
        for (int j = i; j > 0 && strcmp(names[j - 1], names[j]) > 0; j--) {
            char t[64];
            memcpy(t, names[j], 64); memcpy(names[j], names[j - 1], 64); memcpy(names[j - 1], t, 64);
        }
    return n;
}
static void path_fn(void *c, const char *name, char *out, size_t n) { (void)c; snprintf(out, n, "%s/%s", wdir, name); }
static int list_dir_fn(void *c, const char *rel, app_dirent *out, int max)
{
    (void)c;
    char pat[MAX_PATH + 8];
    snprintf(pat, sizeof pat, rel[0] ? "%s\\%s\\*" : "%s%.0s\\*", wdir, rel);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    int n = 0;
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        size_t l = strlen(fd.cFileName);
        if (fd.cFileName[0] == '.' || l >= 64 || n >= max) continue;
        snprintf(out[n].name, 64, "%s", fd.cFileName);
        out[n].dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        out[n].size = out[n].dir ? 0 : fd.nFileSizeLow;
        n++;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return n;
}
static void root_path_fn(void *c, const char *rel, char *out, size_t n) { (void)c; snprintf(out, n, rel[0] ? "%s/%s" : "%s%.0s", wdir, rel); }
static void start_dir_fn(void *c, char *out, size_t n) { (void)c; if (n) out[0] = 0; }
static bool time_valid = true;
static int64_t time_off;
static int64_t now_fn(void *c, bool *valid)
{
    (void)c;
    *valid = time_valid;
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32 | ft.dwLowDateTime) / 10000000ull - 11644473600ull;
    return (int64_t)t + time_off;
}
static void set_time_fn(void *c, int64_t t) { (void)c; time_off = t - now_fn(NULL, &(bool){0}) + time_off; time_valid = true; }
static uint32_t millis_fn(void *c) { (void)c; return timeGetTime(); }   /* 1 ms steps (GetTickCount moves in 15.6 ms ones) */
static int battery(void *c) { (void)c; return 76; }
static bool hid_ready(void *c) { (void)c; return true; }
static void stroke(void *c, uint8_t k, uint8_t m) { (void)c; (void)k; (void)m; }
static void delay_fn(void *c, int d) { (void)c; Sleep((DWORD)(d > 50 ? 50 : d)); }
static void save_settings(void *c, const char *t) { (void)c; (void)t; }
static void backlight_fn(void *c, int s) { (void)c; (void)s; }
static void shutdown_fn(void *c) { (void)c; quit = true; }
static bool usb_drive(void *c, bool enter) { (void)c; (void)enter; return true; }
static int wifi_scan_fn(void *c, app_ap *out, int max)
{
    (void)c; (void)max;
    snprintf(out[0].ssid, 33, "HomeWiFi"); out[0].secure = true; out[0].rssi = -40;
    snprintf(out[1].ssid, 33, "Neighbour"); out[1].secure = true; out[1].rssi = -70;
    return 2;
}
static int ntp_sync_fn(void *c, const char *ssid, const char *pass, int64_t *t) { (void)c; (void)ssid; (void)pass; (void)t; return NTP_ERR_CONNECT; }
static int bt_st;
static bool bt_start_fn(void *c) { (void)c; bt_st = BT_ADVERTISING; return true; }
static void bt_stop_fn(void *c) { (void)c; bt_st = BT_OFF; }
static int bt_state_fn(void *c, uint32_t *code) { (void)c; if (code) *code = 0; return bt_st; }
static void bt_answer_fn(void *c, bool ok) { (void)c; (void)ok; }
static void bt_forget_fn(void *c) { (void)c; }
static void present(void *c);
static void pump_fn(void *c);
static const app_platform PLAT = {list_files, path_fn, now_fn, millis_fn, battery, hid_ready, stroke, delay_fn,
                                  save_settings, present, pump_fn, usb_drive, backlight_fn, shutdown_fn, set_time_fn, wifi_scan_fn, ntp_sync_fn,
                                  bt_start_fn, bt_stop_fn, bt_state_fn, bt_answer_fn, bt_forget_fn,
                                  list_dir_fn, root_path_fn, start_dir_fn, NULL};

static void present(void *c)
{
    (void)c;
    static uint16_t buf[UI_W * 16];
    int y0, y1;
    bool any = false;
    while (app_dirty(&A, &y0, &y1)) {
        any = true;
        for (int y = y0; y < y1; y += 16) {
            ui_strip s = {buf, y, y1 - y < 16 ? y1 - y : 16};
            app_draw(&A, &s);
            memcpy(panel + y * UI_W, buf, sizeof(uint16_t) * UI_W * (size_t)s.h);
        }
    }
    if (!any) return;
    for (int i = 0; i < UI_W * UI_H; i++) {
        uint16_t p = panel[i];
        uint32_t r = (uint32_t)((p >> 11) << 3 | (p >> 13)), g = (uint32_t)(((p >> 5) & 63) << 2 | ((p >> 9) & 3)), b = (uint32_t)((p & 31) << 3 | ((p >> 2) & 7));
        bgr[i] = r << 16 | g << 8 | b;
    }
    InvalidateRect(hwnd, NULL, FALSE);
    UpdateWindow(hwnd);                                 /* paint now: long work (KDF, Argon2 swap) shows its progress */
    heap_title();
}

static void key(uint32_t k) { app_key(&A, k, true); app_key(&A, k, false); }

static LRESULT CALLBACK proc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    bool ctrl = GetKeyState(VK_CONTROL) & 0x8000;
    switch (m) {
    case WM_CLOSE: quit = true; return 0;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    case WM_KEYDOWN:
        switch (w) {
        case VK_RETURN: key(K_ENTER); break;
        case VK_BACK: key(K_BACKSPACE); break;
        case VK_TAB: key(K_TAB); break;
        case VK_ESCAPE: key(K_ESC); break;
        case VK_UP: key(K_UP); break;
        case VK_DOWN: key(K_DOWN); break;
        case VK_LEFT: key(K_LEFT); break;
        case VK_RIGHT: key(K_RIGHT); break;
        case VK_DELETE: key(K_BACKSPACE | K_FN); break;
        case VK_F2: device_speed = !device_speed; heap_title(); break;
        case VK_F1: {
            SCALE = SCALE % 4 + 1;
            RECT r = {0, 0, UI_W * SCALE, UI_H * SCALE};
            AdjustWindowRect(&r, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, FALSE);
            SetWindowPos(h, NULL, 0, 0, r.right - r.left, r.bottom - r.top, SWP_NOMOVE | SWP_NOZORDER);
            InvalidateRect(h, NULL, TRUE);
            break;
        }
        default:
            if (ctrl && w >= 'A' && w <= 'Z') key((uint32_t)(w - 'A' + 'a') | K_FN);
        }
        return 0;
    case WM_CHAR:
        if (!ctrl && w >= 32 && w != 127) key((uint32_t)w);
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        BITMAPINFO bi = {{sizeof(BITMAPINFOHEADER), UI_W, -UI_H, 1, 32, BI_RGB, 0, 0, 0, 0, 0}, {{0}}};
        StretchDIBits(dc, 0, 0, UI_W * SCALE, UI_H * SCALE, 0, 0, UI_W, UI_H, bgr, &bi, DIB_RGB_COLORS, SRCCOPY);
        EndPaint(h, &ps);
        return 0;
    }
    }
    return DefWindowProcA(h, m, w, l);
}

static void pump_fn(void *c)
{
    (void)c;
    MSG msg;
    while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    app_tick(&A, timeGetTime());
    present(NULL);
    heap_title();
}

int main(int argc, char **argv)
{
    char src[MAX_PATH];
    snprintf(src, sizeof src, "%s", argc > 1 ? argv[1] : "testdata");
    char tmp[MAX_PATH];
    GetTempPathA(sizeof tmp, tmp);
    snprintf(wdir, sizeof wdir, "%scardpass_sim", tmp);
    CreateDirectoryA(wdir, NULL);
    const char *exts[] = {"*.kdbx", "*.keyx"};
    for (int e = 0; e < 2; e++) {
        char pat[MAX_PATH + 8];
        snprintf(pat, sizeof pat, "%s\\%s", src, exts[e]);
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA(pat, &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            char a[MAX_PATH * 2], b[MAX_PATH * 2];
            snprintf(a, sizeof a, "%s\\%s", src, fd.cFileName);
            snprintf(b, sizeof b, "%s\\%s", wdir, fd.cFileName);
            CopyFileA(a, b, FALSE);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }

    {                                                      /* a folder to browse into: keys/ with two key files */
        char kd[MAX_PATH * 2];
        snprintf(kd, sizeof kd, "%s\\keys", wdir);
        CreateDirectoryA(kd, NULL);
        const char *ks[] = {"key_xml1.keyx", "key_xml2.keyx"};
        for (int k = 0; k < 2; k++) {
            char a[MAX_PATH * 2], b[MAX_PATH * 2];
            snprintf(a, sizeof a, "%s\\%s", src, ks[k]);
            snprintf(b, sizeof b, "%s\\keys\\%s", wdir, ks[k]);
            CopyFileA(a, b, FALSE);
        }
    }

    WNDCLASSA wc = {0};
    wc.lpfnWndProc = proc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "cardpass_sim";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassA(&wc);
    RECT r = {0, 0, UI_W * SCALE, UI_H * SCALE};
    AdjustWindowRect(&r, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, FALSE);
    hwnd = CreateWindowA("cardpass_sim", "CardPass simulator (password: test)", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                         CW_USEDEFAULT, CW_USEDEFAULT, r.right - r.left, r.bottom - r.top, NULL, NULL, wc.hInstance, NULL);
    hwnd_main = hwnd;
    /* the firmware's Argon2 rule: at most 128 KiB in RAM, the rest through the encrypted swap file */
    char swp[MAX_PATH + 32];
    snprintf(swp, sizeof swp, "%s/.argon2.swp", wdir);
    kdbx_set_argon2_memory(128 * 1024, swp, 32 * 1024);
    kdbx_set_idle_hook(argon2_cpu);
    cp_settings cfg;
    cp_settings_default(&cfg);
    app_init(&A, &PLAT, &cfg);
    present(NULL);
    timeBeginPeriod(1);                                    /* 1 ms timer: Windows' default 15.6 ms cannot pace 60 fps */
    DWORD next = timeGetTime();
    while (!quit) {
        pump_fn(NULL);
        next += 16;                                         /* 62.5 Hz, like the firmware loop */
        DWORD now = timeGetTime();
        if ((LONG)(next - now) > 0) Sleep(next - now);
        else next = now;
    }
    timeEndPeriod(1);
    return 0;
}
