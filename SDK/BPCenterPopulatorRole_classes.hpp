#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BPCenterPopulatorRole

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BPRadialPopulatorIcon_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BPCenterPopulatorRole.BPCenterPopulatorRole_C
// 0x0008 (0x0038 - 0x0030)
class UBPCenterPopulatorRole_C final : public UBPRadialPopulatorIcon_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0030(0x0008)(ZeroConstructor, Transient, DuplicateTransient)

public:
	void ExecuteUbergraph_BPCenterPopulatorRole(int32 EntryPoint);
	void FinishWidgetSetup(class USQUserWidget* Widget, class UBaseRadialMenu_C* RadialMenu, class UBP_RadialItemModel_C* ActionModel);
	void InitialSetup(class USQUserWidget* Widget, class UBP_RadialItemModel_C* Model, class UBaseRadialMenu_C* RadialMenu);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BPCenterPopulatorRole_C">();
	}
	static class UBPCenterPopulatorRole_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBPCenterPopulatorRole_C>();
	}
};
static_assert(alignof(UBPCenterPopulatorRole_C) == 0x000008, "Wrong alignment on UBPCenterPopulatorRole_C");
static_assert(sizeof(UBPCenterPopulatorRole_C) == 0x000038, "Wrong size on UBPCenterPopulatorRole_C");
static_assert(offsetof(UBPCenterPopulatorRole_C, UberGraphFrame) == 0x000030, "Member 'UBPCenterPopulatorRole_C::UberGraphFrame' has a wrong offset!");

}

