#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_BaseWaterMovement

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_BaseWaterMovement.BP_BaseWaterMovement_C
// 0x0008 (0x0148 - 0x0140)
class UBP_BaseWaterMovement_C : public USQWaterMovementComponent
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0140(0x0008)(ZeroConstructor, Transient, DuplicateTransient)

public:
	void ExecuteUbergraph_BP_BaseWaterMovement(int32 EntryPoint);
	void OnMechanismAdded(class UODKWaterMechanismComponent* InMechanismComponent);
	void ApplyMovement();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_BaseWaterMovement_C">();
	}
	static class UBP_BaseWaterMovement_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_BaseWaterMovement_C>();
	}
};
static_assert(alignof(UBP_BaseWaterMovement_C) == 0x000008, "Wrong alignment on UBP_BaseWaterMovement_C");
static_assert(sizeof(UBP_BaseWaterMovement_C) == 0x000148, "Wrong size on UBP_BaseWaterMovement_C");
static_assert(offsetof(UBP_BaseWaterMovement_C, UberGraphFrame) == 0x000140, "Member 'UBP_BaseWaterMovement_C::UberGraphFrame' has a wrong offset!");

}

