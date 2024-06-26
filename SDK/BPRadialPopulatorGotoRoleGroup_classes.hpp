#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BPRadialPopulatorGotoRoleGroup

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BPRadialPopulatorIcon_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BPRadialPopulatorGotoRoleGroup.BPRadialPopulatorGotoRoleGroup_C
// 0x0008 (0x0038 - 0x0030)
class UBPRadialPopulatorGotoRoleGroup_C final : public UBPRadialPopulatorIcon_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0030(0x0008)(ZeroConstructor, Transient, DuplicateTransient)

public:
	void ExecuteUbergraph_BPRadialPopulatorGotoRoleGroup(int32 EntryPoint);
	void InitialSetup(class USQUserWidget* Widget, class UBP_RadialItemModel_C* Model, class UBaseRadialMenu_C* RadialMenu);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BPRadialPopulatorGotoRoleGroup_C">();
	}
	static class UBPRadialPopulatorGotoRoleGroup_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBPRadialPopulatorGotoRoleGroup_C>();
	}
};
static_assert(alignof(UBPRadialPopulatorGotoRoleGroup_C) == 0x000008, "Wrong alignment on UBPRadialPopulatorGotoRoleGroup_C");
static_assert(sizeof(UBPRadialPopulatorGotoRoleGroup_C) == 0x000038, "Wrong size on UBPRadialPopulatorGotoRoleGroup_C");
static_assert(offsetof(UBPRadialPopulatorGotoRoleGroup_C, UberGraphFrame) == 0x000030, "Member 'UBPRadialPopulatorGotoRoleGroup_C::UberGraphFrame' has a wrong offset!");

}

