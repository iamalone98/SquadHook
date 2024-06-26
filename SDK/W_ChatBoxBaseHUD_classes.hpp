#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_ChatBoxBaseHUD

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_structs.hpp"
#include "UMG_classes.hpp"
#include "EChatChannels_structs.hpp"
#include "Squad_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_ChatBoxBaseHUD.W_ChatBoxBaseHUD_C
// 0x0038 (0x0298 - 0x0260)
class UW_ChatBoxBaseHUD_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       FadeIn;                                            // 0x0268(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UBorder*                                Border_MainChat;                                   // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UVerticalBox*                           MessageList;                                       // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UScrollBox*                             ScrollBox_0;                                       // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	EChatChannels                                 Current_Channel;                                   // 0x0288(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Auto_Scroll;                                       // 0x0289(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          Is_Onscreen_Chat;                                  // 0x028A(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          Fading;                                            // 0x028B(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_46E3[0x4];                                     // 0x028C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTimerHandle                           Close_Chat_Timer;                                  // 0x0290(0x0008)(Edit, BlueprintVisible, DisableEditOnInstance, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_W_ChatBoxBaseHUD(int32 EntryPoint);
	void Open_Chat();
	void Close_Chat();
	void Construct();
	void Finished_8FB2F968497A05C82620F1A59FD40BE1();
	void Update_Save_Visibility();
	void Add_New_Chat(const class FString& PlayerName, const class FString& Message, ESQChat Channel, const struct FLinearColor& Color, ESQNotificationTypes NotificationType);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_ChatBoxBaseHUD_C">();
	}
	static class UW_ChatBoxBaseHUD_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_ChatBoxBaseHUD_C>();
	}
};
static_assert(alignof(UW_ChatBoxBaseHUD_C) == 0x000008, "Wrong alignment on UW_ChatBoxBaseHUD_C");
static_assert(sizeof(UW_ChatBoxBaseHUD_C) == 0x000298, "Wrong size on UW_ChatBoxBaseHUD_C");
static_assert(offsetof(UW_ChatBoxBaseHUD_C, UberGraphFrame) == 0x000260, "Member 'UW_ChatBoxBaseHUD_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_ChatBoxBaseHUD_C, FadeIn) == 0x000268, "Member 'UW_ChatBoxBaseHUD_C::FadeIn' has a wrong offset!");
static_assert(offsetof(UW_ChatBoxBaseHUD_C, Border_MainChat) == 0x000270, "Member 'UW_ChatBoxBaseHUD_C::Border_MainChat' has a wrong offset!");
static_assert(offsetof(UW_ChatBoxBaseHUD_C, MessageList) == 0x000278, "Member 'UW_ChatBoxBaseHUD_C::MessageList' has a wrong offset!");
static_assert(offsetof(UW_ChatBoxBaseHUD_C, ScrollBox_0) == 0x000280, "Member 'UW_ChatBoxBaseHUD_C::ScrollBox_0' has a wrong offset!");
static_assert(offsetof(UW_ChatBoxBaseHUD_C, Current_Channel) == 0x000288, "Member 'UW_ChatBoxBaseHUD_C::Current_Channel' has a wrong offset!");
static_assert(offsetof(UW_ChatBoxBaseHUD_C, Auto_Scroll) == 0x000289, "Member 'UW_ChatBoxBaseHUD_C::Auto_Scroll' has a wrong offset!");
static_assert(offsetof(UW_ChatBoxBaseHUD_C, Is_Onscreen_Chat) == 0x00028A, "Member 'UW_ChatBoxBaseHUD_C::Is_Onscreen_Chat' has a wrong offset!");
static_assert(offsetof(UW_ChatBoxBaseHUD_C, Fading) == 0x00028B, "Member 'UW_ChatBoxBaseHUD_C::Fading' has a wrong offset!");
static_assert(offsetof(UW_ChatBoxBaseHUD_C, Close_Chat_Timer) == 0x000290, "Member 'UW_ChatBoxBaseHUD_C::Close_Chat_Timer' has a wrong offset!");

}

