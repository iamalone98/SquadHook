#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Populator_Deployable

#include "Basic.hpp"

#include "BPRadialPopulatorText_classes.hpp"
#include "Engine_structs.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_Populator_Deployable.BP_Populator_Deployable_C
// 0x0008 (0x0040 - 0x0038)
class UBP_Populator_Deployable_C final : public UBPRadialPopulatorText_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_Populator_Deployable_C;          // 0x0038(0x0008)(ZeroConstructor, Transient, DuplicateTransient)

public:
	void ExecuteUbergraph_BP_Populator_Deployable(int32 EntryPoint);
	void InitialSetup(class USQUserWidget* Widget, class UBP_RadialItemModel_C* Model, class UBaseRadialMenu_C* RadialMenu);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Populator_Deployable_C">();
	}
	static class UBP_Populator_Deployable_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_Populator_Deployable_C>();
	}
};
static_assert(alignof(UBP_Populator_Deployable_C) == 0x000008, "Wrong alignment on UBP_Populator_Deployable_C");
static_assert(sizeof(UBP_Populator_Deployable_C) == 0x000040, "Wrong size on UBP_Populator_Deployable_C");
static_assert(offsetof(UBP_Populator_Deployable_C, UberGraphFrame_BP_Populator_Deployable_C) == 0x000038, "Member 'UBP_Populator_Deployable_C::UberGraphFrame_BP_Populator_Deployable_C' has a wrong offset!");

}

