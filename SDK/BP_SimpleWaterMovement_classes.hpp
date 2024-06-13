#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_SimpleWaterMovement

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_BaseWaterMovement_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_SimpleWaterMovement.BP_SimpleWaterMovement_C
// 0x0008 (0x0150 - 0x0148)
class UBP_SimpleWaterMovement_C final : public UBP_BaseWaterMovement_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_SimpleWaterMovement_C;           // 0x0148(0x0008)(ZeroConstructor, Transient, DuplicateTransient)

public:
	void ExecuteUbergraph_BP_SimpleWaterMovement(int32 EntryPoint);
	void ApplyMovement();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_SimpleWaterMovement_C">();
	}
	static class UBP_SimpleWaterMovement_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_SimpleWaterMovement_C>();
	}
};
static_assert(alignof(UBP_SimpleWaterMovement_C) == 0x000008, "Wrong alignment on UBP_SimpleWaterMovement_C");
static_assert(sizeof(UBP_SimpleWaterMovement_C) == 0x000150, "Wrong size on UBP_SimpleWaterMovement_C");
static_assert(offsetof(UBP_SimpleWaterMovement_C, UberGraphFrame_BP_SimpleWaterMovement_C) == 0x000148, "Member 'UBP_SimpleWaterMovement_C::UberGraphFrame_BP_SimpleWaterMovement_C' has a wrong offset!");

}
