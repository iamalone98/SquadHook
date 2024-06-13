#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_CommandActionItem

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "UMG_classes.hpp"
#include "Squad_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_CommandActionItem.W_CommandActionItem_C
// 0x0110 (0x0370 - 0x0260)
class UW_CommandActionItem_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UBorder*                                Border;                                            // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UButton*                                Button_Main;                                       // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Icon;                                              // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             Name_W_CommandActionItem_C;                        // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_State;                                          // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Time;                                           // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Timer;                                             // 0x0298(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UClass*                                 SQCommand_Data;                                    // 0x02A0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	class UMaterialInstanceDynamic*               MI_Timer;                                          // 0x02A8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           Current_State_Color;                               // 0x02B0(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           Active_Color;                                      // 0x02C0(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           Cooldown_Color;                                    // 0x02D0(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           Enroute_Color;                                     // 0x02E0(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           Ready_Color;                                       // 0x02F0(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Interval_Index;                                    // 0x0300(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Time_Remaining;                                    // 0x0304(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerController*                    My_PC;                                             // 0x0308(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Can_Execute_Command;                               // 0x0310(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          Use_Pre_Placement;                                 // 0x0311(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn)
	uint8                                         Pad_4418[0x6];                                     // 0x0312(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class FString                                 Description;                                       // 0x0318(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, HasGetValueTypeHash)
	bool                                          Force_Allowed;                                     // 0x0328(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4419[0x3];                                     // 0x0329(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FVector                                Zero_Based_World_Location;                         // 0x032C(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UW_CommandPrePlacement_C*               Pre_Placement_Widget;                              // 0x0338(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	FMulticastInlineDelegateProperty_             Clicked;                                           // 0x0340(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	class UBP_CommanderActionCondition_C*         Command_Condition;                                 // 0x0350(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	FMulticastInlineDelegateProperty_             Created_Control_Widget;                            // 0x0358(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	bool                                          Category_Enabled;                                  // 0x0368(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn)
	bool                                          Button_Cooldown;                                   // 0x0369(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)

public:
	void Clicked__DelegateSignature();
	void Created_Control_Widget__DelegateSignature(class UW_Command_ActionControl_C* Widget);
	void ExecuteUbergraph_W_CommandActionItem(int32 EntryPoint);
	void Fail_Message();
	void Start_Button_Cooldown();
	void Event_Control_Widget(class UW_Command_ActionControl_C* Widget);
	void Construct();
	void BndEvt__Button_Main_K2Node_ComponentBoundEvent_0_OnButtonClickedEvent__DelegateSignature();
	void Tick(const struct FGeometry& MyGeometry, float InDeltaTime);
	void Update_State();
	void Update_Color(bool Faded);
	void Get_State(ESQCommandOptionState* State, float* State_Time, float* State_Percent, bool* Locked, float* Category_Time, float* Category_Percent);
	void Get_Category_Cooldown(bool* Locked, float* Remaining);
	class UWidget* Get_Tooltip_Widget();
	void Get_Traced_Map_Location(struct FVector* Zero, struct FVector* Local);
	void Auto_Spawn_Action();
	void Get_Pre_Placement_Widget(class UW_CommandPrePlacement_C** Widget);
	void Remove_Other_Pending_Actions();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_CommandActionItem_C">();
	}
	static class UW_CommandActionItem_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_CommandActionItem_C>();
	}
};
static_assert(alignof(UW_CommandActionItem_C) == 0x000008, "Wrong alignment on UW_CommandActionItem_C");
static_assert(sizeof(UW_CommandActionItem_C) == 0x000370, "Wrong size on UW_CommandActionItem_C");
static_assert(offsetof(UW_CommandActionItem_C, UberGraphFrame) == 0x000260, "Member 'UW_CommandActionItem_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, Border) == 0x000268, "Member 'UW_CommandActionItem_C::Border' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, Button_Main) == 0x000270, "Member 'UW_CommandActionItem_C::Button_Main' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, Icon) == 0x000278, "Member 'UW_CommandActionItem_C::Icon' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, Name_W_CommandActionItem_C) == 0x000280, "Member 'UW_CommandActionItem_C::Name_W_CommandActionItem_C' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, TB_State) == 0x000288, "Member 'UW_CommandActionItem_C::TB_State' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, TB_Time) == 0x000290, "Member 'UW_CommandActionItem_C::TB_Time' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, Timer) == 0x000298, "Member 'UW_CommandActionItem_C::Timer' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, SQCommand_Data) == 0x0002A0, "Member 'UW_CommandActionItem_C::SQCommand_Data' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, MI_Timer) == 0x0002A8, "Member 'UW_CommandActionItem_C::MI_Timer' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, Current_State_Color) == 0x0002B0, "Member 'UW_CommandActionItem_C::Current_State_Color' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, Active_Color) == 0x0002C0, "Member 'UW_CommandActionItem_C::Active_Color' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, Cooldown_Color) == 0x0002D0, "Member 'UW_CommandActionItem_C::Cooldown_Color' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, Enroute_Color) == 0x0002E0, "Member 'UW_CommandActionItem_C::Enroute_Color' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, Ready_Color) == 0x0002F0, "Member 'UW_CommandActionItem_C::Ready_Color' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, Interval_Index) == 0x000300, "Member 'UW_CommandActionItem_C::Interval_Index' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, Time_Remaining) == 0x000304, "Member 'UW_CommandActionItem_C::Time_Remaining' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, My_PC) == 0x000308, "Member 'UW_CommandActionItem_C::My_PC' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, Can_Execute_Command) == 0x000310, "Member 'UW_CommandActionItem_C::Can_Execute_Command' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, Use_Pre_Placement) == 0x000311, "Member 'UW_CommandActionItem_C::Use_Pre_Placement' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, Description) == 0x000318, "Member 'UW_CommandActionItem_C::Description' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, Force_Allowed) == 0x000328, "Member 'UW_CommandActionItem_C::Force_Allowed' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, Zero_Based_World_Location) == 0x00032C, "Member 'UW_CommandActionItem_C::Zero_Based_World_Location' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, Pre_Placement_Widget) == 0x000338, "Member 'UW_CommandActionItem_C::Pre_Placement_Widget' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, Clicked) == 0x000340, "Member 'UW_CommandActionItem_C::Clicked' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, Command_Condition) == 0x000350, "Member 'UW_CommandActionItem_C::Command_Condition' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, Created_Control_Widget) == 0x000358, "Member 'UW_CommandActionItem_C::Created_Control_Widget' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, Category_Enabled) == 0x000368, "Member 'UW_CommandActionItem_C::Category_Enabled' has a wrong offset!");
static_assert(offsetof(UW_CommandActionItem_C, Button_Cooldown) == 0x000369, "Member 'UW_CommandActionItem_C::Button_Cooldown' has a wrong offset!");

}

