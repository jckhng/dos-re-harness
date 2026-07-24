#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "pakupaku/assets.hpp"
#include "pakupaku/game.hpp"
#include "pakupaku/presenter.hpp"
#include "pakupaku/renderer.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

using namespace std::chrono_literals;

constexpr wchar_t window_class_name[] = L"PakuPakuCompatibilityWindow";
constexpr wchar_t window_title[] = L"Paku Paku Compatibility Reimplementation";
constexpr auto update_period = 50ms;
constexpr auto ready_period = 2s;

struct Arguments {
    std::filesystem::path data;
    int scale{6};
    bool smoke_test{};
};

struct WindowState {
    std::array<std::uint32_t,
               pakupaku::screen_width * pakupaku::screen_height>
        pixels{};
};

Arguments parse_arguments(int argc, char** argv) {
    Arguments result;
    for (int index = 1; index < argc; ++index) {
        const std::string option = argv[index];
        if (option == "--smoke-test") {
            result.smoke_test = true;
            continue;
        }
        if (index + 1 >= argc) {
            throw std::runtime_error("missing value after " + option);
        }
        const std::string value = argv[++index];
        if (option == "--data") {
            result.data = value;
        } else if (option == "--scale") {
            result.scale = std::stoi(value);
        } else {
            throw std::runtime_error("unknown option: " + option);
        }
    }
    if (result.data.empty()) {
        throw std::runtime_error(
            "usage: pakupaku_play --data DIR [--scale 1..12] "
            "[--smoke-test]");
    }
    if (result.scale < 1 || result.scale > 12) {
        throw std::runtime_error("scale must be between 1 and 12");
    }
    return result;
}

void copy_pixels(const pakupaku::Renderer& renderer, WindowState& window) {
    const auto indexed = renderer.indexed_pixels();
    for (std::size_t index = 0; index < indexed.size(); ++index) {
        const auto& rgb = pakupaku::cga_palette[indexed[index]];
        window.pixels[index] =
            (static_cast<std::uint32_t>(rgb[0]) << 16U) |
            (static_cast<std::uint32_t>(rgb[1]) << 8U) |
            static_cast<std::uint32_t>(rgb[2]);
    }
}

LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam,
                             LPARAM lparam) {
    auto* state = reinterpret_cast<WindowState*>(
        GetWindowLongPtrW(window, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lparam);
        state = static_cast<WindowState*>(create->lpCreateParams);
        SetWindowLongPtrW(window, GWLP_USERDATA,
                          reinterpret_cast<LONG_PTR>(state));
    }

    switch (message) {
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT paint{};
        const HDC device = BeginPaint(window, &paint);
        if (state != nullptr) {
            RECT client{};
            GetClientRect(window, &client);
            BITMAPINFO bitmap{};
            bitmap.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
            bitmap.bmiHeader.biWidth = pakupaku::screen_width;
            bitmap.bmiHeader.biHeight = -pakupaku::screen_height;
            bitmap.bmiHeader.biPlanes = 1;
            bitmap.bmiHeader.biBitCount = 32;
            bitmap.bmiHeader.biCompression = BI_RGB;
            SetStretchBltMode(device, COLORONCOLOR);
            StretchDIBits(
                device, 0, 0, client.right - client.left,
                client.bottom - client.top, 0, 0, pakupaku::screen_width,
                pakupaku::screen_height, state->pixels.data(), &bitmap,
                DIB_RGB_COLORS, SRCCOPY);
        }
        EndPaint(window, &paint);
        return 0;
    }
    case WM_SIZE:
        InvalidateRect(window, nullptr, FALSE);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(window, message, wparam, lparam);
    }
}

std::optional<pakupaku::Direction> key_direction(WPARAM key) {
    switch (key) {
    case VK_UP:
    case 'W':
        return pakupaku::Direction::up;
    case VK_RIGHT:
    case 'D':
        return pakupaku::Direction::right;
    case VK_DOWN:
    case 'S':
        return pakupaku::Direction::down;
    case VK_LEFT:
    case 'A':
        return pakupaku::Direction::left;
    default:
        return std::nullopt;
    }
}

HWND create_window(HINSTANCE instance, WindowState& state, int scale) {
    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(WNDCLASSEXW);
    window_class.style = CS_HREDRAW | CS_VREDRAW;
    window_class.lpfnWndProc = window_proc;
    window_class.hInstance = instance;
    window_class.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
    window_class.lpszClassName = window_class_name;
    if (RegisterClassExW(&window_class) == 0) {
        throw std::runtime_error("cannot register the game window");
    }

    constexpr DWORD style = WS_OVERLAPPEDWINDOW;
    RECT bounds{0, 0, pakupaku::screen_width * scale,
                pakupaku::screen_height * scale};
    if (AdjustWindowRectEx(&bounds, style, FALSE, 0) == 0) {
        throw std::runtime_error("cannot calculate the game window size");
    }
    const HWND window = CreateWindowExW(
        0, window_class_name, window_title, style, CW_USEDEFAULT,
        CW_USEDEFAULT, bounds.right - bounds.left, bounds.bottom - bounds.top,
        nullptr, nullptr, instance, &state);
    if (window == nullptr) {
        throw std::runtime_error("cannot create the game window");
    }
    return window;
}

int run(const Arguments& arguments) {
    const auto assets = pakupaku::Assets::load_verified(arguments.data);
    auto game = pakupaku::GameState::initial(assets);
    pakupaku::Renderer renderer;
    WindowState window_state;

    pakupaku::render_game_frame(renderer, assets, game, true);
    copy_pixels(renderer, window_state);
    if (arguments.smoke_test) {
        std::cout << "interactive frontend assets and presenter ok\n";
        return 0;
    }

    SetProcessDPIAware();
    const HINSTANCE instance = GetModuleHandleW(nullptr);
    const HWND window = create_window(instance, window_state, arguments.scale);
    ShowWindow(window, SW_SHOWDEFAULT);
    UpdateWindow(window);

    bool running = true;
    bool holding_ready = true;
    auto ready_until = std::chrono::steady_clock::now() + ready_period;
    auto next_update = ready_until;

    while (running) {
        MSG message{};
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE) != 0) {
            if (message.message == WM_QUIT) {
                running = false;
                break;
            }
            if (message.message == WM_KEYDOWN) {
                if (message.wParam == VK_ESCAPE || message.wParam == 'Q') {
                    DestroyWindow(window);
                    running = false;
                    break;
                }
                if (const auto direction = key_direction(message.wParam)) {
                    game.request(*direction);
                }
            }
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        if (!running) {
            break;
        }

        const auto now = std::chrono::steady_clock::now();
        if (holding_ready && now >= ready_until) {
            holding_ready = false;
            next_update = now;
        }

        bool changed = false;
        int catch_up_steps = 0;
        while (!holding_ready && !game.game_over && now >= next_update &&
               catch_up_steps < 5) {
            game.step();
            changed = true;
            ++catch_up_steps;
            next_update += update_period;
            if (game.ready_banner) {
                holding_ready = true;
                ready_until = now + ready_period;
                next_update = ready_until;
            }
        }
        if (catch_up_steps == 5 && now >= next_update) {
            next_update = now + update_period;
        }

        if (changed) {
            pakupaku::render_game_frame(renderer, assets, game,
                                        holding_ready);
            copy_pixels(renderer, window_state);
            InvalidateRect(window, nullptr, FALSE);
        }
        std::this_thread::sleep_for(1ms);
    }
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        return run(parse_arguments(argc, argv));
    } catch (const std::exception& error) {
        std::cerr << "pakupaku_play: " << error.what() << '\n';
        return 1;
    }
}
