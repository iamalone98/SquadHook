#include "SDK.hpp"
#include "MinHook.h"
#include <cstdio>
#include <Windows.h>
#include <vector>
#include <Psapi.h>
#include <iostream>
#include <iomanip>

using namespace SDK;

FILE* Log = NULL;

typedef void(__fastcall* ProcessEventHookType)(UObject* Object, UFunction* Function, void* Params);
ProcessEventHookType OriginalProcessEventHook = nullptr;

void* FindPattern(HANDLE hProcess,
    const std::vector < BYTE >& pattern) {
    MODULEINFO moduleInfo = {
      0
    };
    GetModuleInformation(hProcess, GetModuleHandle(nullptr), &moduleInfo, sizeof(moduleInfo));

    BYTE* buffer = new BYTE[moduleInfo.SizeOfImage];
    SIZE_T bytesRead = 0;
    ReadProcessMemory(hProcess, moduleInfo.lpBaseOfDll, buffer, moduleInfo.SizeOfImage, &bytesRead);

    for (size_t i = 0; i < bytesRead - pattern.size(); ++i) {
        bool found = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (pattern[j] != 0x00 && pattern[j] != buffer[i + j]) {
                found = false;
                break;
            }
        }
        if (found) {
            delete[] buffer;
            return (void*)((DWORD_PTR)moduleInfo.lpBaseOfDll + i);
        }
    }

    delete[] buffer;
    return nullptr;
}

bool isFindStr(std::string text, std::string search) {
    if (text.find(search) == std::string::npos) {
        return false;
    }

    return true;
}

void __fastcall HookedFunction(UObject* Object, UFunction* Function, void* Params) {

    if (Object && Function) {

        auto fullName = Function->GetFullName();
        auto text = "Squad.SQPlayerController.ServerChat";

        //if (!isFindStr(fullName, "BP_") && !isFindStr(fullName, "Engine.")) {
        if (Log) {
            fprintf(Log, "%s\n", fullName.c_str());
        }
        //}

        if (fullName.find(text) != std::string::npos) {

            Params::SQPlayerController_ServerChat* myParams = static_cast <Params::SQPlayerController_ServerChat*> (Params);
            ASQPlayerController* PlayerController = static_cast <ASQPlayerController*> (Object);

            if (PlayerController) {
                APlayerState* PlayerState = PlayerController->PlayerState;

                if (PlayerState) {
                    //auto cl = reinterpret_cast <USQOnlineServicesOnlineUser*> (Object->FindClassFast("SQOnlineServicesOnlineUser"));
                    auto PlayerID = PlayerState->PlayerId;

                    fprintf(Log, "%s\n", myParams->Msg.ToString());

                    std::cout << "Message: " << myParams->Msg.ToString() << std::endl;
                    std::cout << "PlayerID: " << PlayerID << std::endl;

                    if (myParams->Msg.ToString() == "disband") {
                        PlayerController->ServerDisbandSquad();
                    }

                    if (myParams->Msg.ToString() == "suicide") {
                        PlayerController->ServerSuicide(false);
                    }
                }
            }

            std::cout << "Hooked function" << std::endl;
            std::cout << "Params addr: " << Params << std::endl;
            std::cout << "Function addr:" << Function << std::endl;
            std::cout << "Function Name: " << Function->GetFullName() << std::endl;
            std::cout << "Object   Name: " << Object->GetName() << std::endl;
            std::cout << "Object   Name: " << Object->GetFullName() << std::endl;
        }
    }

    OriginalProcessEventHook(Object, Function, Params);

    //auto text = "Squad.SQBaseGameSubsystem.TickSubsystem";
    // Squad.SQGameRuleSet.PlayerJoined
    // OnlineSubsystemUtils.OnlineBeaconClient.ClientOnConnected
}

// Функция, которая будет вызвана при загрузке DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {

        SetConsoleOutputCP(CP_UTF8);
        MH_Initialize();

        fopen_s(&Log, "log.txt", "w+");

        FILE* pCout;
        freopen_s(&pCout, "CONOUT$", "w", stdout);

        std::cout << "Dll Injected!!!" << "\n";

        std::vector < BYTE > pattern = {
          0x40,
          0x55,
          0x56,
          0x57,
          0x41,
          0x54,
          0x41,
          0x55,
          0x41,
          0x56,
          0x41,
          0x57,
          0x48,
          0x81,
          0xEC,
          0x00,
          0x00,
          0x00,
          0x00,
          0x48,
          0x8D,
          0x6C,
          0x24,
          0x00,
          0x48,
          0x89,
          0x9D,
          0x00,
          0x00,
          0x00,
          0x00,
          0x48,
          0x8B,
          0x05,
          0x00,
          0x00,
          0x00,
          0x00,
          0x48,
          0x33,
          0xC5,
          0x48,
          0x89,
          0x85,
          0x00,
          0x00,
          0x00,
          0x00,
          0x8B,
          0x59
        };
        void* functionAddress = FindPattern(GetCurrentProcess(), pattern);

        std::cout << functionAddress << "\n";

        if (functionAddress) {
            MH_CreateHook(functionAddress, HookedFunction, reinterpret_cast <void**> (&OriginalProcessEventHook));
            std::cout << "Create Hook!!!" << "\n";
            MH_EnableHook(functionAddress);
            std::cout << "Enable Hook!!!" << "\n";
        }
        else {}
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        MH_DisableHook(OriginalProcessEventHook);
        MH_Uninitialize();

        fclose(Log);
    }
    return TRUE;
}