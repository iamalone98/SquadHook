#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_AKS74_1P29

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_AKS74_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_AKS74_1P29.BP_AKS74_1P29_C
// 0x0020 (0x09C0 - 0x09A0)
class ABP_AKS74_1P29_C final : public ABP_AKS74_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_AKS74_1P29_C;                    // 0x09A0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UBP_Pip_C*                              BP_Pip;                                            // 0x09A8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   LensMesh;                                          // 0x09B0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_AKS74_1P29(int32 EntryPoint);
	void StopModifyZeroing();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_AKS74_1P29_C">();
	}
	static class ABP_AKS74_1P29_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_AKS74_1P29_C>();
	}
};
static_assert(alignof(ABP_AKS74_1P29_C) == 0x000010, "Wrong alignment on ABP_AKS74_1P29_C");
static_assert(sizeof(ABP_AKS74_1P29_C) == 0x0009C0, "Wrong size on ABP_AKS74_1P29_C");
static_assert(offsetof(ABP_AKS74_1P29_C, UberGraphFrame_BP_AKS74_1P29_C) == 0x0009A0, "Member 'ABP_AKS74_1P29_C::UberGraphFrame_BP_AKS74_1P29_C' has a wrong offset!");
static_assert(offsetof(ABP_AKS74_1P29_C, BP_Pip) == 0x0009A8, "Member 'ABP_AKS74_1P29_C::BP_Pip' has a wrong offset!");
static_assert(offsetof(ABP_AKS74_1P29_C, LensMesh) == 0x0009B0, "Member 'ABP_AKS74_1P29_C::LensMesh' has a wrong offset!");

}
