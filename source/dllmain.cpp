//  CRICKET 07 WIDESCREEN FIX

#include "stdafx.h"
#include <spdlog/spdlog.h>
#include <psapi.h>

// Include TheLink2012's injector
#include "injector/injector.hpp"
#include "injector/assembly.hpp"
#include "injector/hooking.hpp"
#include "Hooking.Patterns.h"

using namespace injector;

//  GLOBALS

float fNewHUDWidth = 853.33333f;
float fHUDOffsetX = -106.66666f;
float fNewAspect = 1.7777777f;
int   iNewHUDWidthInt = 853;

// Mouse Limits
float fMouseLimitX = 853.33333f;
float fMouseLimitY = 480.0f;

// Video Logic
float fVideoQuadWidth = 853.33333f;
float fVideoUVScale = 0.002083333f;

DWORD jmpBack_2D_Unified = 0;

void __declspec(naked) Hook_HUD_Unified() {
    __asm {
        push[fNewHUDWidth]     // Width (853.33)
        push 0                  // Y (0)
        push[fHUDOffsetX]      // X (Offset)

        jmp[jmpBack_2D_Unified]
    }
}

//  INIT FUNCTION

void Init()
{
    CIniReader iniReader("Cricket07WidescreenFix.ini");
    int ResX = iniReader.ReadInteger("MAIN", "ResX", 0);
    int ResY = iniReader.ReadInteger("MAIN", "ResY", 0);

    // Auto-detect
    if (!ResX || !ResY)
        std::tie(ResX, ResY) = GetDesktopRes();



    // Calculate Aspect Ratio
    float aspectRatio = (float)ResX / (float)ResY;

    // Define Standard 4:3
    if (aspectRatio <= 1.334f) {
        spdlog::info("Standard 4:3 detected. Skipping patches.");
        return;
    }

    // Widescreen HUD Logic
    fNewHUDWidth = 480.0f * aspectRatio;
    fHUDOffsetX = (640.0f - fNewHUDWidth) / 2.0f;
    fNewAspect = aspectRatio;
    iNewHUDWidthInt = (int)fNewHUDWidth;

    fMouseLimitX = fNewHUDWidth;
    fVideoQuadWidth = fNewHUDWidth;

    MODULEINFO modInfo = { 0 };
    GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), &modInfo, sizeof(MODULEINFO));
    uintptr_t start = (uintptr_t)modInfo.lpBaseOfDll;
    uintptr_t end = start + modInfo.SizeOfImage;

    spdlog::info("Widescreen Detected: {:.2f} ({}x{})", aspectRatio, ResX, ResY);

    //  APPLY PATCHES

    // --- 3D Aspect Ratio (Corrected) ---
    auto pattern_ar = hook::pattern("C7 44 24 6C AB AA AA 3F");
    if (!pattern_ar.empty()) {
        uintptr_t address_of_float = (uintptr_t)pattern_ar.get_first(4);
        injector::WriteMemory(address_of_float, fNewAspect, true);
        spdlog::info("Patched Stack Aspect Ratio at: {:X}", address_of_float);
    }
    else {
        spdlog::error("Failed to find 3D Aspect Ratio pattern");
    }

    // --- Mouse Limits ---
    for (uintptr_t i = start; i < end; i += 4) {
        uint32_t val = *(uint32_t*)i;
        if (val == 0x44180000) { // 608.0
            injector::WriteMemory(i, fMouseLimitX, true);
        }
        else if (val == 0x43E00000) { // 448.0
            injector::WriteMemory(i, fMouseLimitY, true);
        }
    }
    spdlog::info("Patched Mouse Limits");

    // --- PIP Frame + Camera Position ---
    // Pattern: BD 00 00 D0 41 (MOV EBP, 26.0)
    auto pattern_pip_cam = hook::pattern("34 00 00 34 42");
    auto pattern_pip_frame = hook::pattern("BD 00 00 D0 41");

    if (!pattern_pip_cam.empty()) {
        // We found the instruction. 
        // Address of the PIP cam
        uintptr_t addrCam = (uintptr_t)pattern_pip_cam.get_first(1);
        // Address of the PIP frame
        uintptr_t addrFrame = (uintptr_t)pattern_pip_frame.get_first(1);

        // Calculate X offset of PIP camera
        float fPiPCam = fHUDOffsetX + 45.0f;
        // Calculate X offset of PIP frame
        float fPiPFrame = fHUDOffsetX + 26.0f;

        injector::WriteMemory<float>(addrCam, fPiPCam, true);
        spdlog::info("Patched PiP Frame Assembly to {:.2f}", fPiPCam);
        injector::WriteMemory<float>(addrFrame, fPiPFrame, true);
        spdlog::info("Patched PiP Frame Assembly to {:.2f}", fPiPFrame);
    }

    if (!pattern_pip_frame.empty()) {
        auto pattern_pip_text = hook::pattern("08 00 00 D8 41");
        uintptr_t addr_text = (uintptr_t)pattern_pip_text.get_first(1);

        // Calculate target X
        float fCorrectedPiPText = fHUDOffsetX + 27.0f;

        injector::WriteMemory<float>(addr_text, fCorrectedPiPText, true);
        spdlog::info("Patched PiP Frame Text Assembly to {:.2f}", fCorrectedPiPText);
    }

    // --- Video Scaler ---
    uint32_t uvHex = 0x3ACCCCCD; // 0.002083333
    for (uintptr_t i = start; i < end; i++) {
        if (*(uint32_t*)i == uvHex) {
            injector::WriteMemory(i, fVideoUVScale, true);
            // Scan backwards for the Quad Width
            for (int k = 0; k < 512; k++) {
                uintptr_t backAddr = i - k;
                if (*(uint32_t*)backAddr == 0x44200000) { // 640.0
                    // Check surrounding values to ensure it's the video quad
                    if (*(uint32_t*)(backAddr + 10) == 0x43F00000 || // 480.0
                        *(uint32_t*)(backAddr - 10) == 0x43F00000) {
                        injector::WriteMemory(backAddr, fVideoQuadWidth, true);
                    }
                }
            }
        }
    }
    spdlog::info("Patched Video Scaler");

    // --- Text Centering ---
    for (uintptr_t i = start; i < end; i++) {
        if (*(uint32_t*)i == 0x00000280) { // 640 int
            uint8_t op = *(uint8_t*)(i - 1);
            // Check for immediate operand instructions (SUB, MOV, CMP)
            if (op == 0x2D || op == 0xB8 || op == 0x3D) {
                injector::WriteMemory(i, iNewHUDWidthInt, true);
            }
        }
    }
    spdlog::info("Patched Text Centering");

    // --- 2D Unified Hook ---
    auto pattern_hud = hook::pattern("68 00 00 F0 43 68 00 00 20 44 6A 00 6A 00");
    if (!pattern_hud.empty()) {
        uintptr_t matchAddr = (uintptr_t)pattern_hud.get_first(0);
        uintptr_t hookAddr = matchAddr + 5; // Skip PUSH 480

        jmpBack_2D_Unified = hookAddr + 9;

        injector::MakeJMP(hookAddr, Hook_HUD_Unified, true);
        injector::MakeNOP(hookAddr + 5, 4, true);

        spdlog::info("Hooked 2D HUD Logic at: {:X}", hookAddr);
    }
    else {
        spdlog::error("2D Hook Failed: Pattern not found.");
    }
}

BOOL APIENTRY DllMain(HMODULE /*hModule*/, DWORD reason, LPVOID /*lpReserved*/)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        Init();
    }
    return TRUE;
}
