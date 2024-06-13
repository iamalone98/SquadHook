#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BPCenterPopulatorVehicle

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BPRadialPopulatorIcon_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BPCenterPopulatorVehicle.BPCenterPopulatorVehicle_C
// 0x0008 (0x0038 - 0x0030)
class UBPCenterPopulatorVehicle_C final : public UBPRadialPopulatorIcon_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0030(0x0008)(ZeroConstructor, Transient, DuplicateTransient)

public:
	void ExecuteUbergraph_BPCenterPopulatorVehicle(int32 EntryPoint);
	void FinishWidgetSetup(class USQUserWidget* Widget, class UBaseRadialMenu_C* RadialMenu, class UBP_RadialItemModel_C* ActionModel);
	void InitialSetup(class USQUserWidget* Widget, class UBP_RadialItemModel_C* Model, class UBaseRadialMenu_C* RadialMenu);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BPCenterPopulatorVehicle_C">();
	}
	static class UBPCenterPopulatorVehicle_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBPCenterPopulatorVehicle_C>();
	}
};
static_assert(alignof(UBPCenterPopulatorVehicle_C) == 0x000008, "Wrong alignment on UBPCenterPopulatorVehicle_C");
static_assert(sizeof(UBPCenterPopulatorVehicle_C) == 0x000038, "Wrong size on UBPCenterPopulatorVehicle_C");
static_assert(offsetof(UBPCenterPopulatorVehicle_C, UberGraphFrame) == 0x000030, "Member 'UBPCenterPopulatorVehicle_C::UberGraphFrame' has a wrong offset!");

}

