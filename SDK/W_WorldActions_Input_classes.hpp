#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_WorldActions_Input

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_WorldActions_Input.W_WorldActions_Input_C
// 0x0050 (0x02B0 - 0x0260)
class UW_WorldActions_Input_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UButton*                                ExecuteButton;                                     // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_ActionName;                                     // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USpinBox*                               ValueSpinBox;                                      // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class FText                                   Name_W_WorldActions_Input_C;                       // 0x0280(0x0018)(Edit, BlueprintVisible)
	class FString                                 ConsoleCommand;                                    // 0x0298(0x0010)(Edit, BlueprintVisible, ZeroConstructor, HasGetValueTypeHash)
	bool                                          IntegerInput;                                      // 0x02A8(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn)

public:
	void ExecuteUbergraph_W_WorldActions_Input(int32 EntryPoint);
	void BndEvt__W_WorldActions_EntryWithInput_Button_76_K2Node_ComponentBoundEvent_1_OnButtonClickedEvent__DelegateSignature();
	void PreConstruct(bool IsDesignTime);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_WorldActions_Input_C">();
	}
	static class UW_WorldActions_Input_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_WorldActions_Input_C>();
	}
};
static_assert(alignof(UW_WorldActions_Input_C) == 0x000008, "Wrong alignment on UW_WorldActions_Input_C");
static_assert(sizeof(UW_WorldActions_Input_C) == 0x0002B0, "Wrong size on UW_WorldActions_Input_C");
static_assert(offsetof(UW_WorldActions_Input_C, UberGraphFrame) == 0x000260, "Member 'UW_WorldActions_Input_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_WorldActions_Input_C, ExecuteButton) == 0x000268, "Member 'UW_WorldActions_Input_C::ExecuteButton' has a wrong offset!");
static_assert(offsetof(UW_WorldActions_Input_C, TB_ActionName) == 0x000270, "Member 'UW_WorldActions_Input_C::TB_ActionName' has a wrong offset!");
static_assert(offsetof(UW_WorldActions_Input_C, ValueSpinBox) == 0x000278, "Member 'UW_WorldActions_Input_C::ValueSpinBox' has a wrong offset!");
static_assert(offsetof(UW_WorldActions_Input_C, Name_W_WorldActions_Input_C) == 0x000280, "Member 'UW_WorldActions_Input_C::Name_W_WorldActions_Input_C' has a wrong offset!");
static_assert(offsetof(UW_WorldActions_Input_C, ConsoleCommand) == 0x000298, "Member 'UW_WorldActions_Input_C::ConsoleCommand' has a wrong offset!");
static_assert(offsetof(UW_WorldActions_Input_C, IntegerInput) == 0x0002A8, "Member 'UW_WorldActions_Input_C::IntegerInput' has a wrong offset!");

}

