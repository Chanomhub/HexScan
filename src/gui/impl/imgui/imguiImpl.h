#ifndef HEX_SCAN_V1_IMGUIIMPL_H
#define HEX_SCAN_V1_IMGUIIMPL_H

#define GLFW_INCLUDE_VULKAN
#include <GLFW/glfw3.h>
#include <imgui.h>
#include <imgui_impl_vulkan.h>
#include <config.h>

namespace ImGuiImpl {
    constexpr char mainWindowName[] = "HexScan " HexScanVersion;
    extern GLFWwindow* window;
    extern ImGui_ImplVulkanH_Window* wd;
    extern ImVec4 clearColor;

    void init();
    void destroy();
    void newFrame();
    void render();

    bool shouldClose();
}


#endif //HEX_SCAN_V1_IMGUIIMPL_H
