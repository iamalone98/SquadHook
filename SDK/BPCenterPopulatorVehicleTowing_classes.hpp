#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BPCenterPopulatorVehicleTowing

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BPRadialPopulatorIcon_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BPCenterPopulatorVehicleTowing.BPCenterPopulatorVehicleTowing_C
// 0x0008 (0x0038 - 0x0030)
class UBPCenterPopulatorVehicleTowing_C final : public UBPRadialPopulatorIcon_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0030(0x0008)(ZeroConstructor, Transient, DuplicateTransient)

public:
	void ExecuteUbergraph_BPCenterPopulatorVehicleTowing(int32 EntryPoint);
	void FinishWidgetSetup(class USQUserWidget* Widget, class UBaseRadialMenu_C* RadialMenu, class UBP_RadialItemModel_C* ActionModel);
	void InitialSetup(class USQUserWidget* Widget, class UBP_RadialItemModel_C* Model, class UBaseRadialMenu_C* RadialMenu);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BPCenterPopulatorVehicleTowing_C">();
	}
	static class UBPCenterPopulatorVehicleTowing_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBPCenterPopulatorVehicleTowing_C>();
	}
};
static_assert(alignof(UBPCenterPopulatorVehicleTowing_C) == 0x000008, "Wrong alignment on UBPCenterPopulatorVehicleTowing_C");
static_assert(sizeof(UBPCenterPopulatorVehicleTowing_C) == 0x000038, "Wrong size on UBPCenterPopulatorVehicleTowing_C");
static_assert(offsetof(UBPCenterPopulatorVehicleTowing_C, UberGraphFrame) == 0x000030, "Member 'UBPCenterPopulatorVehicleTowing_C::UberGraphFrame' has a wrong offset!");

}
