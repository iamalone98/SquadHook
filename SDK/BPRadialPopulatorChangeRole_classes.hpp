#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BPRadialPopulatorChangeRole

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BPRadialPopulatorIcon_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BPRadialPopulatorChangeRole.BPRadialPopulatorChangeRole_C
// 0x0008 (0x0038 - 0x0030)
class UBPRadialPopulatorChangeRole_C final : public UBPRadialPopulatorIcon_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0030(0x0008)(ZeroConstructor, Transient, DuplicateTransient)

public:
	void ExecuteUbergraph_BPRadialPopulatorChangeRole(int32 EntryPoint);
	void InitialSetup(class USQUserWidget* Widget, class UBP_RadialItemModel_C* Model, class UBaseRadialMenu_C* RadialMenu);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BPRadialPopulatorChangeRole_C">();
	}
	static class UBPRadialPopulatorChangeRole_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBPRadialPopulatorChangeRole_C>();
	}
};
static_assert(alignof(UBPRadialPopulatorChangeRole_C) == 0x000008, "Wrong alignment on UBPRadialPopulatorChangeRole_C");
static_assert(sizeof(UBPRadialPopulatorChangeRole_C) == 0x000038, "Wrong size on UBPRadialPopulatorChangeRole_C");
static_assert(offsetof(UBPRadialPopulatorChangeRole_C, UberGraphFrame) == 0x000030, "Member 'UBPRadialPopulatorChangeRole_C::UberGraphFrame' has a wrong offset!");

}

