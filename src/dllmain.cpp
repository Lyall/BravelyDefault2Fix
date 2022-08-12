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
bool bFOVFix;
int iCustomResX;
int iCustomResY;
bool bResScale;
float fResScale;

// Variables
float fNewX;
float fNewY;
float fNativeAspect = 1.777777791f;
float fPi = 3.14159265358979323846f;
float fDefaultHUDWidth = 1920;
float fDefaultHUDHeight = 1080;
float fNewAspect;

// FOV Hook
DWORD64 FOVFixReturnJMP;
float FOVPiDiv;
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
        fmul [fNewAspect]
        fxch st(1)
        fpatan
        fmul [FOVDivPi]
        fstp [FOVFinalValue]
        movss xmm0, [FOVFinalValue]
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
        movss xmm6, [fDefaultHUDHeight]
        movss [rsp + 0x30], xmm9
        movss [rsp + 0x34], xmm6
        mov byte ptr [rsp + 0x38], 01
        jmp[HUDWidthReturnJMP]
    }
}

// HUD Offset Hook
DWORD64 HUDOffsetReturnJMP;
float HUDHorOffsetValue;
float HUDVerOffsetValue;
void __declspec(naked) HUDOffset_CC()
{
    __asm
    {
        movss xmm7, [HUDHorOffsetValue]
        movss xmm8, [HUDVerOffsetValue]
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
    bFOVFix = config.GetBoolean("Fix FOV", "Enabled", true);
    iCustomResX = config.GetInteger("Custom Resolution", "Width", -1);
    iCustomResY = config.GetInteger("Custom Resolution", "Height", -1);
    bResScale = config.GetBoolean("r.ScreenPercentage", "Enabled", true);
    fResScale = config.GetFloat("r.ScreenPercentage", "Value", 0);

    // Grab desktop resolution
    RECT desktop;
    GetWindowRect(GetDesktopWindow(), &desktop);
    fNewX = (float)desktop.right;
    fNewY = (float)desktop.bottom;
    fNewAspect = (float)desktop.right / (float)desktop.bottom;

    // Custom resolution enabled
    if (iCustomResX > 0 && iCustomResY > 0)
    {
        fNewX = (float)iCustomResX;
        fNewY = (float)iCustomResY;
        fNewAspect = (float)iCustomResX / (float)iCustomResY;
    }

    #if _DEBUG
    if (config.ParseError() != 0) {
        std::cout << "Can't load config file\n" << std::endl;
        std::cout << "Parse error: " << config.ParseError() << std::endl;
    }

    std::cout << printf("Config parse\nbResFix: %d\nbAspectFix : %d\nbHUDFix : %d\nbFOVFix : %d\niCustomResX : %d\niCustomResY : %d\nbResScale:: %d\nfResScale: %.4f\nfNewX : %.4f\nfNewY: %.4f\nfNewAspect: %.4f\n",
        bResFix, bAspectFix, bHUDFix, bFOVFix, iCustomResX, iCustomResY, bResScale, fResScale, fNewX, fNewY, fNewAspect) << std::endl;
    #endif
}

void ResolutionFix()
{
    if (bResFix)
    {
        //Address of signature = Bravely_Default_II - Win64 - Shipping.exe + 0x009F3D0B
        uint8_t* ResScanResult = Memory::PatternScan(baseModule, "C7 02 ? ? ? ? 48 8B ? C7 42 04 ? ? ? ? C3 CC CC CC CC 66 0F");

        if (ResScanResult)
        {
            Memory::Write((uintptr_t)(ResScanResult + 0x2), (int)fNewX);
            Memory::Write((uintptr_t)(ResScanResult + 0xC), (int)fNewY);
            #if _DEBUG
            std::cout << "1280x720 changed to: " << fNewX << "x" << fNewY << std::endl;
            #endif
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
        if (FOVFixScanResult && fNewAspect > fNativeAspect)
        {
            int FOVFixHookLength = 19;
            DWORD64 FOVFixAddress = (uintptr_t)FOVFixScanResult;
            FOVFixReturnJMP = FOVFixAddress + FOVFixHookLength;
            FOVPiDiv = fPi / 360;
            FOVDivPi = 360 / fPi;
            Memory::DetourFunction64((void*)FOVFixAddress, FOVFix_CC, FOVFixHookLength);        

            #if _DEBUG
            std::cout << "FOV converted to hor+" << std::endl;
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
        uint8_t* HUDOffsetScanResult = Memory::PatternScan(baseModule, "F3 0F 11 ?? ?? ?? F3 44 0F 11 ?? ?? ?? C6 ?? ?? ?? 01 F3 0F 11");
        if (HUDOffsetScanResult)
        {
            int HUDOffsetHookLength = 18;
            DWORD64 HUDOffsetAddress = (uintptr_t)HUDOffsetScanResult;
            HUDOffsetReturnJMP = HUDOffsetAddress + HUDOffsetHookLength;
            if (fNewAspect > fNativeAspect)
            {
                HUDHorOffsetValue = round(((fDefaultHUDWidth * (fNewAspect / fNativeAspect) - 1920) / 2));
                HUDVerOffsetValue = 0;
            }
            else if (fNewAspect < fNativeAspect)
            {
                HUDHorOffsetValue = 0;
                HUDVerOffsetValue = round(((fDefaultHUDHeight * (fNativeAspect / fNewAspect) - fDefaultHUDHeight) / 2));
            }
            Memory::DetourFunction64((void*)HUDOffsetAddress, HUDOffset_CC, HUDOffsetHookLength);

            #if _DEBUG
            std::cout << "HUD horizontal offset set to " << HUDHorOffsetValue << std::endl;
            std::cout << "HUD vertical offset set to " << HUDVerOffsetValue << std::endl;
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
    Sleep(500);
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
