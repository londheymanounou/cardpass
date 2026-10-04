/* Desktop simulator: the real UI code in a Win32 window (240x135 scaled up), driven by the PC keyboard.
 *   sim [testdata dir]      works on a COPY of the databases in %TEMP%\cardpass_sim (master password: test)
 * Keys: type normally; arrows = fn+; , . /; Esc = fn+`; Ctrl+letter = fn+letter (Ctrl+L lock, Ctrl+S save);
 * Delete = fn+Backspace. Typing, Wi-Fi, Bluetooth and the USB drive are fake. Not the device: see docs/qemu.md. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "../../components/ui/app_priv.h"

#define SCALE 4
static app A;
static uint16_t panel[UI_W * UI_H];
static uint32_t bgr[UI_W * UI_H];
static HWND hwnd;
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
static uint32_t millis_fn(void *c) { (void)c; return GetTickCount(); }
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
    app_tick(&A, GetTickCount());
    present(NULL);
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
    cp_settings cfg;
    cp_settings_default(&cfg);
    app_init(&A, &PLAT, &cfg);
    present(NULL);
    while (!quit) {
        pump_fn(NULL);
        Sleep(10);
    }
    return 0;
}
