#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_IED_Dialling

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_IED_Dialling.W_IED_Dialling_C
// 0x00A0 (0x0300 - 0x0260)
class UW_IED_Dialling_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UImage*                                 Image_1;                                           // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_2;                                           // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_3;                                           // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_4;                                           // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_5;                                           // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Dialing;                                        // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_State;                                          // 0x0298(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Time;                                           // 0x02A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TextBlock_3;                                       // 0x02A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UWidgetSwitcher*                        WidgetSwitcher_0;                                  // 0x02B0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class FText                                   Dots;                                              // 0x02B8(0x0018)(Edit, BlueprintVisible, DisableEditOnInstance)
	class ASQPlayerState*                         Sq_PlayerState;                                    // 0x02D0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ABP_Phone_Detonator_C*                  Detonator;                                         // 0x02D8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FText                                   Unique_Name;                                       // 0x02E0(0x0018)(Edit, BlueprintVisible, DisableEditOnInstance)
	class UDataTable*                             Names;                                             // 0x02F8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_W_IED_Dialling(int32 EntryPoint);
	void Fail_Dial();
	void Randomise_Name();
	void Set_Detonator(class ABP_Phone_Detonator_C* Param_Detonator);
	void Dial();
	void Update_IED_State();
	void Tick(const struct FGeometry& MyGeometry, float InDeltaTime);
	void PreConstruct(bool IsDesignTime);
	void Set_State_Text();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_IED_Dialling_C">();
	}
	static class UW_IED_Dialling_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_IED_Dialling_C>();
	}
};
static_assert(alignof(UW_IED_Dialling_C) == 0x000008, "Wrong alignment on UW_IED_Dialling_C");
static_assert(sizeof(UW_IED_Dialling_C) == 0x000300, "Wrong size on UW_IED_Dialling_C");
static_assert(offsetof(UW_IED_Dialling_C, UberGraphFrame) == 0x000260, "Member 'UW_IED_Dialling_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_IED_Dialling_C, Image_1) == 0x000268, "Member 'UW_IED_Dialling_C::Image_1' has a wrong offset!");
static_assert(offsetof(UW_IED_Dialling_C, Image_2) == 0x000270, "Member 'UW_IED_Dialling_C::Image_2' has a wrong offset!");
static_assert(offsetof(UW_IED_Dialling_C, Image_3) == 0x000278, "Member 'UW_IED_Dialling_C::Image_3' has a wrong offset!");
static_assert(offsetof(UW_IED_Dialling_C, Image_4) == 0x000280, "Member 'UW_IED_Dialling_C::Image_4' has a wrong offset!");
static_assert(offsetof(UW_IED_Dialling_C, Image_5) == 0x000288, "Member 'UW_IED_Dialling_C::Image_5' has a wrong offset!");
static_assert(offsetof(UW_IED_Dialling_C, TB_Dialing) == 0x000290, "Member 'UW_IED_Dialling_C::TB_Dialing' has a wrong offset!");
static_assert(offsetof(UW_IED_Dialling_C, TB_State) == 0x000298, "Member 'UW_IED_Dialling_C::TB_State' has a wrong offset!");
static_assert(offsetof(UW_IED_Dialling_C, TB_Time) == 0x0002A0, "Member 'UW_IED_Dialling_C::TB_Time' has a wrong offset!");
static_assert(offsetof(UW_IED_Dialling_C, TextBlock_3) == 0x0002A8, "Member 'UW_IED_Dialling_C::TextBlock_3' has a wrong offset!");
static_assert(offsetof(UW_IED_Dialling_C, WidgetSwitcher_0) == 0x0002B0, "Member 'UW_IED_Dialling_C::WidgetSwitcher_0' has a wrong offset!");
static_assert(offsetof(UW_IED_Dialling_C, Dots) == 0x0002B8, "Member 'UW_IED_Dialling_C::Dots' has a wrong offset!");
static_assert(offsetof(UW_IED_Dialling_C, Sq_PlayerState) == 0x0002D0, "Member 'UW_IED_Dialling_C::Sq_PlayerState' has a wrong offset!");
static_assert(offsetof(UW_IED_Dialling_C, Detonator) == 0x0002D8, "Member 'UW_IED_Dialling_C::Detonator' has a wrong offset!");
static_assert(offsetof(UW_IED_Dialling_C, Unique_Name) == 0x0002E0, "Member 'UW_IED_Dialling_C::Unique_Name' has a wrong offset!");
static_assert(offsetof(UW_IED_Dialling_C, Names) == 0x0002F8, "Member 'UW_IED_Dialling_C::Names' has a wrong offset!");

}

