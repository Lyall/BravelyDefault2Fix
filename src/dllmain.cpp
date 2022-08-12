#include "stdafx.h"
#include "external/inih/INIReader.h"
#include "helper.hpp"

bool Proxy_Attach();
void Proxy_Detach();

using namespace std;

HMODULE baseModule = GetModuleHandle(NULL);

// INI Variables
bool bResFix;
bool bAspectFix;
bool bHUDFix;
bool bFullscreenBug;
bool bFOVFix;
float fFOVAdjust;
int iCustomResX;
int iCustomResY;
bool bResScale;
float fResScale;

// Variables
float fDesktopRight;
float fDesktopBottom;
float fDesktopAspect;
float fNativeAspect = 1.777777791f;
float fPi = 3.14159265358979323846f;
float fDefaultHUDWidth = 1920;
float fCustomAspect;

// FOV Hook
DWORD64 FOVFixReturnJMP;
float FOVPiDiv;
float FOVNewAspect;
float FOVDivPi;
float FOVFinalValue;
void __declspec(naked) FOVFix_CC()
{
    __asm
    {
        fld dword ptr[rbx + 0x00000218]
        fmul [FOVPiDiv]
        fptan
        fxch st(1)
        fdiv [fNativeAspect]
        fmul [FOVNewAspect]
        fxch st(1)
        fpatan
        fmul [FOVDivPi]
        fstp [FOVFinalValue]
        movss xmm0, [FOVFinalValue]
        addss xmm0, [fFOVAdjust]
        movss [rdi + 0x18], xmm0
        mov eax, [rbx + 0x00000228]
        jmp[FOVFixReturnJMP]
    }
}

// HUD Width Hook
DWORD64 HUDWidthReturnJMP;
void __declspec(naked) HUDWidth_CC()
{
    __asm
    {
        movss xmm9, [fDefaultHUDWidth]
        movss [rsp + 0x30], xmm9
        movss [rsp + 0x34], xmm6
        mov byte ptr [rsp + 0x38], 01
        jmp[HUDWidthReturnJMP]
    }
}

// HUD Offset Hook
DWORD64 HUDOffsetReturnJMP;
float HUDOffsetValue;
void __declspec(naked) HUDOffset_CC()
{
    __asm
    {
        movss xmm7, [HUDOffsetValue]
        movss [rsp + 0x30], xmm7
        movss [rsp + 0x34], xmm8
        mov byte ptr [rsp + 0x38], 01
        jmp[HUDOffsetReturnJMP]
    }
}

// r.ScreenPercentage Hook
DWORD64 ResScaleReturnJMP;
float fResScaleValue = 0.009999999776f;
void __declspec(naked) ResScale_CC()
{
    __asm
    {
        setne bl
        movss xmm1, [fResScale]
        xorps xmm0, xmm0
        mulss xmm1, [fResScaleValue]
        jmp[ResScaleReturnJMP]
    }
}

void ReadConfig()
{
    INIReader config("BravelyDefault2Fix.ini");

    bResFix = config.GetBoolean("Fix Resolution", "Enabled", true);
    bAspectFix = config.GetBoolean("Fix Aspect Ratio", "Enabled", true);
    bHUDFix = config.GetBoolean("Fix HUD", "Enabled", true);
    bFullscreenBug = config.GetBoolean("Fix Fullscreen Bug", "Enabled", true);
    bFOVFix = config.GetBoolean("Fix FOV", "Enabled", true);
    fFOVAdjust = config.GetFloat("Fix FOV", "AdditionalFOV", 0);
    iCustomResX = config.GetInteger("Custom Resolution", "Width", -1);
    iCustomResY = config.GetInteger("Custom Resolution", "Height", -1);
    bResScale = config.GetBoolean("r.ScreenPercentage", "Enabled", true);
    fResScale = config.GetFloat("r.ScreenPercentage", "Value", 0);

    RECT desktop;
    GetWindowRect(GetDesktopWindow(), &desktop);
    fDesktopRight = (float)desktop.right;
    fDesktopBottom = (float)desktop.bottom;
    fDesktopAspect = (float)desktop.right / (float)desktop.bottom;
    fCustomAspect = (float)iCustomResX / (float)iCustomResY;
}

void ResolutionFix()
{
    if (bResFix)
    {
        //Address of signature = Bravely_Default_II - Win64 - Shipping.exe + 0x009F3D0B
        uint8_t* ResScanResult = Memory::PatternScan(baseModule, "C7 02 ? ? ? ? 48 8B ? C7 42 04 ? ? ? ? C3 CC CC CC CC 66 0F");

        if (ResScanResult)
        {
            if (iCustomResX == 0 && iCustomResY == 0)
            {
                Memory::Write((uintptr_t)(ResScanResult + 0x2), (int)fDesktopRight);
                Memory::Write((uintptr_t)(ResScanResult + 0xC), (int)fDesktopBottom);
                #if _DEBUG
                std::cout << "1280x720 changed to: " << (int)fDesktopRight << "x" << (int)fDesktopBottom << std::endl;
                #endif
            }
            else
            {
                Memory::Write((uintptr_t)(ResScanResult + 0x2), (int)iCustomResX);
                Memory::Write((uintptr_t)(ResScanResult + 0xC), (int)iCustomResY);
                #if _DEBUG
                std::cout << "1280x720 changed to: " << iCustomResX << "x" << iCustomResY << std::endl;
                #endif
            }
        }

        if (bResScale)
        {
            // Bravely_Default_II-Win64-Shipping.exe+1FEA46F 
            uint8_t* ResScaleScanResult = Memory::PatternScan(baseModule, "F3 0F 10 ?? ?? 0F ?? ?? F3 0F 59 ?? ?? ?? ?? ?? 0F ?? ?? 77 ?? F3 0F 10");

            if (ResScaleScanResult)
            {
                int ResScaleHookLength = 19;
                DWORD64 ResScaleAddress = (uintptr_t)(ResScaleScanResult - 0x3);
                ResScaleReturnJMP = ResScaleAddress + ResScaleHookLength;
                Memory::DetourFunction64((void*)ResScaleAddress, ResScale_CC, ResScaleHookLength);

                #if _DEBUG
                std::cout << "r.ScreenPercentage forced to " << fResScale << std::endl;
                #endif
            }
        }
    }   
}

void AspectFix()
{
    if (bAspectFix)
    {
        // UE4 Pillarboxing
        // Credit: killer-m (WSGF Discord)
        // Address of signature = Bravely_Default_II - Win64 - Shipping.exe + 0x01BDC79A
        uint8_t* AspectFixScanResult = Memory::PatternScan(baseModule, "49 ? ? ? ? ? ? F6 ? ? 01 48 ? ? F3 44");
        if (AspectFixScanResult)
        {
            Memory::PatchBytes((uintptr_t)(AspectFixScanResult + 0xA), "\x00", 1);
            
            #if _DEBUG
            std::cout << "Pillarboxing disabled" << std::endl;
            #endif
        }
    }
}

void FOVFix()
{
    if (bFOVFix)
    {
        // Shoutout to WSGF's FOV calculations. I'm not good with maths.
        // https://www.wsgf.org/article/common-hex-values
        // Arctan(Tan(originalFOV * PI / 360) / (nativeAspect) * (newAspect)) * 360 / PI
        // Writing this in assembly sucked. But it allows for a dynamic FOV.

        // Address of signature = Bravely_Default_II - Win64 - Shipping.exe + 0x01BD9448
        uint8_t* FOVFixScanResult = Memory::PatternScan(baseModule, "F3 0F 10 ?? ?? ?? ?? ?? F3 0F 11 ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? 0F B6 ?? ?? ?? ?? ??");
        if (FOVFixScanResult)
        {
            int FOVFixHookLength = 19;
            DWORD64 FOVFixAddress = (uintptr_t)FOVFixScanResult;
            FOVFixReturnJMP = FOVFixAddress + FOVFixHookLength;
            FOVPiDiv = fPi / 360;
            FOVNewAspect = fDesktopAspect;
            FOVDivPi = 360 / fPi;
            if (iCustomResX > 0 && iCustomResY > 0)
            {
                FOVNewAspect = fCustomAspect;
            }
            Memory::DetourFunction64((void*)FOVFixAddress, FOVFix_CC, FOVFixHookLength);        

            #if _DEBUG
            std::cout << "FOV adjusted to vert+, and added " << fFOVAdjust << std::endl;
            #endif
        }
    }
}

void HUDFix()
{
    if (bHUDFix)
    {
        // Address of signature = Bravely_Default_II - Win64 - Shipping.exe + 0x01E0BD24
        uint8_t* HUDWidthScanResult = Memory::PatternScan(baseModule, "F3 44 ? ? ? ? ? F3 0F ? ? ? ? C6 44 24 38");
        if (HUDWidthScanResult)
        {
            int HUDWidthHookLength = 18;
            DWORD64 HUDWidthAddress = (uintptr_t)HUDWidthScanResult;
            HUDWidthReturnJMP = HUDWidthAddress + HUDWidthHookLength;
            Memory::DetourFunction64((void*)HUDWidthAddress, HUDWidth_CC, HUDWidthHookLength);

            #if _DEBUG
            std::cout << "HUD width set to " << fDefaultHUDWidth << std::endl;
            #endif
        }

        // Address of signature = Bravely_Default_II - Win64 - Shipping.exe + 0x01E0BD6E
        uint8_t* HUDOffsetScanResult = Memory::PatternScan(baseModule, "F3 0F ? ? ? ? F3 44 ? ? ? ? ? C6 44 24 38");
        if (HUDOffsetScanResult)
        {
            int HUDOffsetHookLength = 18;
            DWORD64 HUDOffsetAddress = (uintptr_t)HUDOffsetScanResult;
            HUDOffsetReturnJMP = HUDOffsetAddress + HUDOffsetHookLength;
            float HUDWidth = fDesktopBottom * fNativeAspect;
            HUDOffsetValue = ((1920 * (fDesktopAspect / fNativeAspect) - 1920) / 2);
            if (iCustomResX > 0 && iCustomResY > 0)
            {
                HUDWidth = iCustomResY * fNativeAspect;
                HUDOffsetValue = ((1920 * (fCustomAspect / fNativeAspect) - 1920) / 2);
            }
            Memory::DetourFunction64((void*)HUDOffsetAddress, HUDOffset_CC, HUDOffsetHookLength);

            #if _DEBUG
            std::cout << "HUD offset set to " << HUDOffsetValue << std::endl;
            #endif
        }     
    }
}

DWORD __stdcall Main(void*)
{
    #if _DEBUG
    AllocConsole();
    freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
    std::cout << "Console initiated" << std::endl;
    #endif
    Sleep(100);
    ReadConfig();
    ResolutionFix();
    AspectFix();
    FOVFix();
    HUDFix();

    return true; // end thread
}

HMODULE ourModule; 

void Patch_Uninit()
{

}

BOOL APIENTRY DllMain(HMODULE hModule, int ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        ourModule = hModule;
        Proxy_Attach();

        CreateThread(NULL, 0, Main, 0, NULL, 0);
    }
    if (ul_reason_for_call == DLL_PROCESS_DETACH)
    {
        Patch_Uninit();

        Proxy_Detach();
    }

    return TRUE;
}
