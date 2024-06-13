#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_VoipOwningPlayer

#include "Basic.hpp"

#include "SquadVoice_structs.hpp"
#include "Engine_structs.hpp"
#include "UMG_structs.hpp"
#include "UMG_classes.hpp"
#include "CoreUObject_structs.hpp"
#include "MicrophoneVolume_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_VoipOwningPlayer.W_VoipOwningPlayer_C
// 0x00B8 (0x0318 - 0x0260)
class UW_VoipOwningPlayer_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UBorder*                                Border_0;                                          // 0x0268(0x0008)(ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                Border_command;                                    // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UScaleBox*                              DisabledVoipIconScaleBox;                          // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Channel;                                        // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 VoipIcon;                                          // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UScaleBox*                              VoipIconScaleBox;                                  // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class ASQHUD*                                 REF_HUD;                                           // 0x0298(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESlateVisibility                              Voip_Vis;                                          // 0x02A0(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2675[0x3];                                     // 0x02A1(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FLinearColor                           Voip_Colour;                                       // 0x02A4(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           SquadToAllSquadsRadioColor;                        // 0x02B4(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           SquadToSquadRadioColor;                            // 0x02C4(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2676[0x4];                                     // 0x02D4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   Voip_Channel_Text;                                 // 0x02D8(0x0018)(Edit, BlueprintVisible, DisableEditOnInstance)
	class ASQPlayerController*                    My_PC;                                             // 0x02F0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESQVoiceChannel                               CurrentState;                                      // 0x02F8(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          bIsAudioInputDeviceAvaiable;                       // 0x02F9(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2677[0x6];                                     // 0x02FA(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class FString                                 MicrophoneErrorMessage;                            // 0x0300(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, HasGetValueTypeHash)
	EMicrophoneVolume                             CurrentMicrophoneVolume;                           // 0x0310(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_W_VoipOwningPlayer(int32 EntryPoint);
	void Update_Microphone_Volume();
	void Refresh_Voip();
	void Construct();
	class FText Get_Squad_Leader_Name();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_VoipOwningPlayer_C">();
	}
	static class UW_VoipOwningPlayer_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_VoipOwningPlayer_C>();
	}
};
static_assert(alignof(UW_VoipOwningPlayer_C) == 0x000008, "Wrong alignment on UW_VoipOwningPlayer_C");
static_assert(sizeof(UW_VoipOwningPlayer_C) == 0x000318, "Wrong size on UW_VoipOwningPlayer_C");
static_assert(offsetof(UW_VoipOwningPlayer_C, UberGraphFrame) == 0x000260, "Member 'UW_VoipOwningPlayer_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_VoipOwningPlayer_C, Border_0) == 0x000268, "Member 'UW_VoipOwningPlayer_C::Border_0' has a wrong offset!");
static_assert(offsetof(UW_VoipOwningPlayer_C, Border_command) == 0x000270, "Member 'UW_VoipOwningPlayer_C::Border_command' has a wrong offset!");
static_assert(offsetof(UW_VoipOwningPlayer_C, DisabledVoipIconScaleBox) == 0x000278, "Member 'UW_VoipOwningPlayer_C::DisabledVoipIconScaleBox' has a wrong offset!");
static_assert(offsetof(UW_VoipOwningPlayer_C, TB_Channel) == 0x000280, "Member 'UW_VoipOwningPlayer_C::TB_Channel' has a wrong offset!");
static_assert(offsetof(UW_VoipOwningPlayer_C, VoipIcon) == 0x000288, "Member 'UW_VoipOwningPlayer_C::VoipIcon' has a wrong offset!");
static_assert(offsetof(UW_VoipOwningPlayer_C, VoipIconScaleBox) == 0x000290, "Member 'UW_VoipOwningPlayer_C::VoipIconScaleBox' has a wrong offset!");
static_assert(offsetof(UW_VoipOwningPlayer_C, REF_HUD) == 0x000298, "Member 'UW_VoipOwningPlayer_C::REF_HUD' has a wrong offset!");
static_assert(offsetof(UW_VoipOwningPlayer_C, Voip_Vis) == 0x0002A0, "Member 'UW_VoipOwningPlayer_C::Voip_Vis' has a wrong offset!");
static_assert(offsetof(UW_VoipOwningPlayer_C, Voip_Colour) == 0x0002A4, "Member 'UW_VoipOwningPlayer_C::Voip_Colour' has a wrong offset!");
static_assert(offsetof(UW_VoipOwningPlayer_C, SquadToAllSquadsRadioColor) == 0x0002B4, "Member 'UW_VoipOwningPlayer_C::SquadToAllSquadsRadioColor' has a wrong offset!");
static_assert(offsetof(UW_VoipOwningPlayer_C, SquadToSquadRadioColor) == 0x0002C4, "Member 'UW_VoipOwningPlayer_C::SquadToSquadRadioColor' has a wrong offset!");
static_assert(offsetof(UW_VoipOwningPlayer_C, Voip_Channel_Text) == 0x0002D8, "Member 'UW_VoipOwningPlayer_C::Voip_Channel_Text' has a wrong offset!");
static_assert(offsetof(UW_VoipOwningPlayer_C, My_PC) == 0x0002F0, "Member 'UW_VoipOwningPlayer_C::My_PC' has a wrong offset!");
static_assert(offsetof(UW_VoipOwningPlayer_C, CurrentState) == 0x0002F8, "Member 'UW_VoipOwningPlayer_C::CurrentState' has a wrong offset!");
static_assert(offsetof(UW_VoipOwningPlayer_C, bIsAudioInputDeviceAvaiable) == 0x0002F9, "Member 'UW_VoipOwningPlayer_C::bIsAudioInputDeviceAvaiable' has a wrong offset!");
static_assert(offsetof(UW_VoipOwningPlayer_C, MicrophoneErrorMessage) == 0x000300, "Member 'UW_VoipOwningPlayer_C::MicrophoneErrorMessage' has a wrong offset!");
static_assert(offsetof(UW_VoipOwningPlayer_C, CurrentMicrophoneVolume) == 0x000310, "Member 'UW_VoipOwningPlayer_C::CurrentMicrophoneVolume' has a wrong offset!");

}
