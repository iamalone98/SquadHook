#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_EndRound

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "W_EndRound_Base_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_EndRound.W_EndRound_C
// 0x0078 (0x02E8 - 0x0270)
class UW_EndRound_C final : public UW_EndRound_Base_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0270(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       BounceText;                                        // 0x0278(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UWidgetAnimation*                       Fade;                                              // 0x0280(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UImage*                                 Image_Flag;                                        // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 IMG_T1_Flag;                                       // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 IMG_T2_Flag;                                       // 0x0298(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_State;                                          // 0x02A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Team;                                           // 0x02A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Tickets;                                        // 0x02B0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UHorizontalBox*                         TicketBox;                                         // 0x02B8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UWidgetSwitcher*                        WidgetSwitcher_0;                                  // 0x02C0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class ASQPlayerController*                    My_PC;                                             // 0x02C8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         On_Screen_Time;                                    // 0x02D0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_351D[0x4];                                     // 0x02D4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQTeamState*                           Winning_Team_0_0;                                  // 0x02D8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAudioComponent*                        Draw_Sound_0;                                      // 0x02E0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_W_EndRound(int32 EntryPoint);
	void Event_Play_Team_Sounds();
	void HUD_Scoreboard();
	void Construct();
	void OnLoaded_4D00979747334CD613094AA5E0E4B4C2(class UObject* Loaded);
	void Init_End_Round_Screen();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_EndRound_C">();
	}
	static class UW_EndRound_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_EndRound_C>();
	}
};
static_assert(alignof(UW_EndRound_C) == 0x000008, "Wrong alignment on UW_EndRound_C");
static_assert(sizeof(UW_EndRound_C) == 0x0002E8, "Wrong size on UW_EndRound_C");
static_assert(offsetof(UW_EndRound_C, UberGraphFrame) == 0x000270, "Member 'UW_EndRound_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_EndRound_C, BounceText) == 0x000278, "Member 'UW_EndRound_C::BounceText' has a wrong offset!");
static_assert(offsetof(UW_EndRound_C, Fade) == 0x000280, "Member 'UW_EndRound_C::Fade' has a wrong offset!");
static_assert(offsetof(UW_EndRound_C, Image_Flag) == 0x000288, "Member 'UW_EndRound_C::Image_Flag' has a wrong offset!");
static_assert(offsetof(UW_EndRound_C, IMG_T1_Flag) == 0x000290, "Member 'UW_EndRound_C::IMG_T1_Flag' has a wrong offset!");
static_assert(offsetof(UW_EndRound_C, IMG_T2_Flag) == 0x000298, "Member 'UW_EndRound_C::IMG_T2_Flag' has a wrong offset!");
static_assert(offsetof(UW_EndRound_C, TB_State) == 0x0002A0, "Member 'UW_EndRound_C::TB_State' has a wrong offset!");
static_assert(offsetof(UW_EndRound_C, TB_Team) == 0x0002A8, "Member 'UW_EndRound_C::TB_Team' has a wrong offset!");
static_assert(offsetof(UW_EndRound_C, TB_Tickets) == 0x0002B0, "Member 'UW_EndRound_C::TB_Tickets' has a wrong offset!");
static_assert(offsetof(UW_EndRound_C, TicketBox) == 0x0002B8, "Member 'UW_EndRound_C::TicketBox' has a wrong offset!");
static_assert(offsetof(UW_EndRound_C, WidgetSwitcher_0) == 0x0002C0, "Member 'UW_EndRound_C::WidgetSwitcher_0' has a wrong offset!");
static_assert(offsetof(UW_EndRound_C, My_PC) == 0x0002C8, "Member 'UW_EndRound_C::My_PC' has a wrong offset!");
static_assert(offsetof(UW_EndRound_C, On_Screen_Time) == 0x0002D0, "Member 'UW_EndRound_C::On_Screen_Time' has a wrong offset!");
static_assert(offsetof(UW_EndRound_C, Winning_Team_0_0) == 0x0002D8, "Member 'UW_EndRound_C::Winning_Team_0_0' has a wrong offset!");
static_assert(offsetof(UW_EndRound_C, Draw_Sound_0) == 0x0002E0, "Member 'UW_EndRound_C::Draw_Sound_0' has a wrong offset!");

}
