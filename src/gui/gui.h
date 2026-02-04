#ifndef HEX_SCAN_GUI_H
#define HEX_SCAN_GUI_H

#include "windows/generic/window.h"
#include <mutex>

#include <list>
#include <string_view>
#include <format>
#include <iomanip>
#include <memory>


namespace Gui {
    extern std::list<std::unique_ptr<Window>> windows;
    extern std::list<std::pair<std::string, int>> logs;

    void mainLoop();

    extern std::mutex logsMutex;

    void log(const std::string_view rt_fmt_str, auto&&... args) {
        std::string str = std::vformat(rt_fmt_str, std::make_format_args(args...));
        std::lock_guard<std::mutex> lock(logsMutex);
        if (!logs.empty() && str == logs.back().first)
            logs.back().second++;
        else
            logs.emplace_back(str, 0);
    }

    void addWindow(Window* window);
    template <typename T>
    std::list<T*> getWindows() {
        std::list<T*> res;
        for (const std::unique_ptr<Window>& window: windows)
            if (const auto tWindow = dynamic_cast<T*>(window.get()))
                res.push_back(tWindow);

        return res;
    }
}


#endif //HEX_SCAN_GUI_H
