#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_RadialCenterPopulatorButton

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BPRadialPopulatorIcon_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_RadialCenterPopulatorButton.BP_RadialCenterPopulatorButton_C
// 0x0008 (0x0038 - 0x0030)
class UBP_RadialCenterPopulatorButton_C final : public UBPRadialPopulatorIcon_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0030(0x0008)(ZeroConstructor, Transient, DuplicateTransient)

public:
	void ExecuteUbergraph_BP_RadialCenterPopulatorButton(int32 EntryPoint);
	void FinishWidgetSetup(class USQUserWidget* Widget, class UBaseRadialMenu_C* RadialMenu, class UBP_RadialItemModel_C* ActionModel);
	void InitialSetup(class USQUserWidget* Widget, class UBP_RadialItemModel_C* Model, class UBaseRadialMenu_C* RadialMenu);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_RadialCenterPopulatorButton_C">();
	}
	static class UBP_RadialCenterPopulatorButton_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_RadialCenterPopulatorButton_C>();
	}
};
static_assert(alignof(UBP_RadialCenterPopulatorButton_C) == 0x000008, "Wrong alignment on UBP_RadialCenterPopulatorButton_C");
static_assert(sizeof(UBP_RadialCenterPopulatorButton_C) == 0x000038, "Wrong size on UBP_RadialCenterPopulatorButton_C");
static_assert(offsetof(UBP_RadialCenterPopulatorButton_C, UberGraphFrame) == 0x000030, "Member 'UBP_RadialCenterPopulatorButton_C::UberGraphFrame' has a wrong offset!");

}

