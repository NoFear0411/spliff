# TUI Mode Design Document

**Status:** Future Implementation
**Created:** 2026-01-11
**Target Version:** 0.6.0+

## Overview

Add an interactive TUI (Text User Interface) mode to sslsniff that provides:
- Live-updating table of captured requests/responses
- Scrolling and filtering capabilities
- Detailed view for individual request/response pairs
- Inline image/video preview from response bodies

## Library Selection: notcurses

After evaluating options, **notcurses** is the recommended choice.

### Comparison Matrix

| Aspect | ncurses | notcurses |
|--------|---------|-----------|
| Age/Maturity | ~30 years | ~5 years |
| API Design | Dated C conventions | Modern, clean C API |
| Images | No | Yes (Sixel, Kitty, iTerm2) |
| Video | No | Yes (via ffmpeg) |
| True Color | 256 colors max | Full 24-bit RGB |
| Unicode | Basic | Full wide char support |
| Performance | Good | Excellent (damage tracking) |
| Install | Pre-installed | Requires package install |

### Why notcurses

1. **Image rendering** - Display intercepted images directly in terminal
2. **Modern API** - Cleaner code, easier maintenance
3. **True color** - Better syntax highlighting for headers/bodies
4. **Active development** - Regular updates, responsive maintainer

### Terminal Image Protocol Support

| Terminal | Protocol | Quality |
|----------|----------|---------|
| Kitty | Native | Best |
| iTerm2 | Inline images | Good |
| WezTerm | Sixel | Good |
| foot | Sixel | Good |
| xterm | Sixel (if enabled) | OK |
| Fallback | Braille/blocks | Basic |

## UI Design

### Main View: Request Table

```
┌─────────────────────────────────────────────────────────────────────────┐
│ sslsniff v0.6.0 TUI | Captured: 142 | Filter: [________________]  [F1] │
├────┬────────┬──────────────────────┬─────────────────┬───────┬──────────┤
│ #  │ Method │ Host                 │ Path            │ Status│ Size     │
├────┼────────┼──────────────────────┼─────────────────┼───────┼──────────┤
│ 1  │ GET    │ api.example.com      │ /v1/users       │ 200   │ 1.2 KB   │
│ 2  │ POST   │ api.example.com      │ /v1/auth        │ 201   │ 156 B    │
│>3  │ GET    │ cdn.example.com      │ /img/logo.png   │ 200   │ 24.5 KB  │
│ 4  │ GET    │ fonts.googleapis.com │ /css2?family=.. │ 200   │ 892 B    │
│ 5  │ PUT    │ storage.example.io   │ /upload/doc.pdf │ 200   │ 1.4 MB   │
│ 6  │ GET    │ tracker.analytics.co │ /collect        │ 204   │ 0 B      │
│    │        │                      │                 │       │          │
│    │        │                      │                 │       │          │
├────┴────────┴──────────────────────┴─────────────────┴───────┴──────────┤
│ [Enter] Details  [/] Filter  [c] Clear  [p] Pause  [q] Quit  [?] Help   │
└─────────────────────────────────────────────────────────────────────────┘
```

### Detail View: Request/Response

```
┌─ Request ───────────────────────────────────────────────────────────────┐
│ GET https://cdn.example.com/img/logo.png HTTP/2                         │
├─────────────────────────────────────────────────────────────────────────┤
│ :authority: cdn.example.com                                             │
│ :path: /img/logo.png                                                    │
│ accept: image/webp,image/png,*/*                                        │
│ user-agent: Mozilla/5.0 (X11; Linux x86_64)...                         │
│ referer: https://example.com/                                           │
└─────────────────────────────────────────────────────────────────────────┘
┌─ Response ──────────────────────────────────────────────────────────────┐
│ HTTP/2 200 OK                                                           │
├─────────────────────────────────────────────────────────────────────────┤
│ content-type: image/png                                                 │
│ content-length: 25088                                                   │
│ cache-control: max-age=31536000                                         │
├─ Body (image/png, 24.5 KB) ─────────────────────────────────────────────┤
│                                                                         │
│              ┌────────────────────────┐                                 │
│              │                        │                                 │
│              │   [RENDERED IMAGE]     │  ← Actual PNG displayed         │
│              │      256 x 256         │    via notcurses ncvisual       │
│              │                        │                                 │
│              └────────────────────────┘                                 │
│                                                                         │
│ Signature: PNG | Dimensions: 256x256 | Bit depth: 8 | Trailer: valid   │
└─────────────────────────────────────────────────────────────────────────┘
│ [Esc] Back  [h] Hex view  [r] Raw  [s] Save to file  [Tab] Req/Resp    │
└─────────────────────────────────────────────────────────────────────────┘
```

### Hex View (toggled with 'h')

```
┌─ Body Hex View ─────────────────────────────────────────────────────────┐
│ Signature: PNG Image | Size: 24.5 KB | Class: Image                     │
├─────────────────────────────────────────────────────────────────────────┤
│ 00000000  89 50 4e 47 0d 0a 1a 0a  00 00 00 0d 49 48 44 52  │.PNG........IHDR│
│ 00000010  00 00 01 00 00 00 01 00  08 06 00 00 00 5c 72 a8  │.............\r.│
│ 00000020  66 00 00 00 04 73 42 49  54 08 08 08 08 7c 08 64  │f....sBIT....|.d│
│ 00000030  88 00 00 20 00 49 44 41  54 78 9c ec dd 7b 9c 1c  │... .IDATx...{..│
│ ...                                                                     │
└─────────────────────────────────────────────────────────────────────────┘
```

## Architecture

### Components

```
┌──────────────────────────────────────────────────────────────┐
│                        main.c                                 │
│                    (CLI argument parsing)                     │
│                           │                                   │
│              ┌────────────┴────────────┐                     │
│              ▼                         ▼                     │
│    ┌─────────────────┐      ┌─────────────────┐             │
│    │  Stream Mode    │      │    TUI Mode     │             │
│    │  (existing)     │      │    (new)        │             │
│    └─────────────────┘      └────────┬────────┘             │
│                                      │                       │
│                     ┌────────────────┼────────────────┐     │
│                     ▼                ▼                ▼     │
│            ┌──────────────┐ ┌──────────────┐ ┌────────────┐ │
│            │ capture_ring │ │  ui_state    │ │ notcurses  │ │
│            │ (storage)    │ │  (filter,    │ │ (rendering)│ │
│            │              │ │   selection) │ │            │ │
│            └──────────────┘ └──────────────┘ └────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

### New Source Files

```
src/
├── tui/
│   ├── tui.h              # Public TUI interface
│   ├── tui.c              # Main TUI loop, initialization
│   ├── tui_table.c        # Request table rendering
│   ├── tui_detail.c       # Detail view rendering
│   ├── tui_filter.c       # Filter input handling
│   ├── tui_media.c        # Image/video preview via ncvisual
│   └── capture_ring.c     # Ring buffer for captured traffic
```

### Data Structures

```c
// Ring buffer entry for captured request/response pair
typedef struct {
    uint64_t id;                    // Monotonic ID
    uint64_t timestamp_ns;          // Capture time

    // Request
    char method[16];
    char host[256];
    char path[1024];
    uint8_t *request_headers;       // Raw headers
    size_t request_headers_len;
    uint8_t *request_body;
    size_t request_body_len;

    // Response
    int status_code;
    uint8_t *response_headers;
    size_t response_headers_len;
    uint8_t *response_body;
    size_t response_body_len;

    // Detected content info
    signature_result_t sig_result;
    char content_type[128];
} capture_entry_t;

// Ring buffer
typedef struct {
    capture_entry_t *entries;
    size_t capacity;                // Max entries
    size_t max_memory;              // Memory limit
    size_t current_memory;          // Current usage
    size_t head;                    // Next write position
    size_t count;                   // Current entry count
    pthread_mutex_t lock;
} capture_ring_t;

// UI state
typedef struct {
    size_t scroll_offset;           // Table scroll position
    size_t selected_index;          // Currently selected row
    char filter_text[256];          // Active filter
    bool filter_active;             // Filter input mode
    bool paused;                    // Pause capture display
    enum { VIEW_TABLE, VIEW_DETAIL, VIEW_HEX } view;
} ui_state_t;
```

### Event Loop Integration

The TUI mode requires merging two event sources:
1. **BPF perf buffer** - Incoming SSL/TLS data events
2. **notcurses input** - Keyboard/mouse events

```c
// Proposed event loop structure
void tui_run(struct bpf_context *ctx) {
    struct notcurses *nc = notcurses_init(NULL, NULL);
    struct ncplane *stdplane = notcurses_stdplane(nc);

    int bpf_fd = bpf_get_perf_fd(ctx);
    struct pollfd fds[2] = {
        { .fd = bpf_fd, .events = POLLIN },
        { .fd = notcurses_inputready_fd(nc), .events = POLLIN },
    };

    while (running) {
        int ret = poll(fds, 2, 100);  // 100ms timeout for refresh

        if (fds[0].revents & POLLIN) {
            // Process BPF events, add to ring buffer
            bpf_process_events(ctx, capture_ring);
        }

        if (fds[1].revents & POLLIN) {
            // Process keyboard input
            ncinput ni;
            while (notcurses_get_nblock(nc, &ni)) {
                handle_input(&ui_state, &ni);
            }
        }

        // Render current view
        tui_render(nc, stdplane, &ui_state, capture_ring);
        notcurses_render(nc);
    }

    notcurses_stop(nc);
}
```

## CLI Interface

```
Usage: sslsniff [OPTIONS]

Mode selection:
  (default)         Stream mode - print to stdout
  -T, --tui         TUI mode - interactive table view

TUI options:
  --max-entries N   Maximum entries in ring buffer (default: 10000)
  --max-memory N    Maximum memory for bodies in MB (default: 100)
  --no-images       Disable image preview (text fallback)
```

## Build Integration

### CMakeLists.txt additions

```cmake
option(ENABLE_TUI "Enable TUI mode with notcurses" ON)

if(ENABLE_TUI)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(NOTCURSES REQUIRED notcurses>=3.0)

    target_sources(sslsniff PRIVATE
        src/tui/tui.c
        src/tui/tui_table.c
        src/tui/tui_detail.c
        src/tui/tui_filter.c
        src/tui/tui_media.c
        src/tui/capture_ring.c
    )

    target_include_directories(sslsniff PRIVATE ${NOTCURSES_INCLUDE_DIRS})
    target_link_libraries(sslsniff PRIVATE ${NOTCURSES_LIBRARIES})
    target_compile_definitions(sslsniff PRIVATE HAVE_NOTCURSES)
endif()
```

### Package dependencies

```bash
# Fedora
sudo dnf install notcurses-devel

# Ubuntu/Debian (may need PPA or build from source)
sudo apt install libnotcurses-dev

# Arch
sudo pacman -S notcurses

# From source
git clone https://github.com/dankamongmen/notcurses
cd notcurses && mkdir build && cd build
cmake .. && make && sudo make install
```

## Implementation Phases

### Phase 1: Basic TUI
- [ ] Ring buffer implementation
- [ ] Basic table rendering
- [ ] Keyboard navigation (up/down/enter/quit)
- [ ] Event loop integration

### Phase 2: Detail View
- [ ] Request/response detail panel
- [ ] Header display with syntax highlighting
- [ ] Body display (text mode)
- [ ] Hex view toggle

### Phase 3: Filtering
- [ ] Filter input mode
- [ ] Filter by host, method, status, content-type
- [ ] Regex support

### Phase 4: Media Preview
- [ ] Image detection and rendering
- [ ] Fallback for unsupported terminals
- [ ] Optional video frame extraction

### Phase 5: Polish
- [ ] Mouse support
- [ ] Terminal resize handling
- [ ] Save to file functionality
- [ ] Color themes

## References

- notcurses documentation: https://notcurses.com/
- notcurses GitHub: https://github.com/dankamongmen/notcurses
- ncvisual API: https://notcurses.com/ncvisual.html
