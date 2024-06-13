#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_BoatWaterMovement

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_BaseWaterMovement_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_BoatWaterMovement.BP_BoatWaterMovement_C
// 0x0008 (0x0150 - 0x0148)
class UBP_BoatWaterMovement_C final : public UBP_BaseWaterMovement_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_BoatWaterMovement_C;             // 0x0148(0x0008)(ZeroConstructor, Transient, DuplicateTransient)

public:
	void ExecuteUbergraph_BP_BoatWaterMovement(int32 EntryPoint);
	void ApplyMovement();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_BoatWaterMovement_C">();
	}
	static class UBP_BoatWaterMovement_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_BoatWaterMovement_C>();
	}
};
static_assert(alignof(UBP_BoatWaterMovement_C) == 0x000008, "Wrong alignment on UBP_BoatWaterMovement_C");
static_assert(sizeof(UBP_BoatWaterMovement_C) == 0x000150, "Wrong size on UBP_BoatWaterMovement_C");
static_assert(offsetof(UBP_BoatWaterMovement_C, UberGraphFrame_BP_BoatWaterMovement_C) == 0x000148, "Member 'UBP_BoatWaterMovement_C::UberGraphFrame_BP_BoatWaterMovement_C' has a wrong offset!");

}

