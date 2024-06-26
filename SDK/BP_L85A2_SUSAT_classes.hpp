#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_L85A2_SUSAT

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_L85A2_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_L85A2_SUSAT.BP_L85A2_SUSAT_C
// 0x0020 (0x09C0 - 0x09A0)
#pragma pack(push, 0x1)
class alignas(0x10) ABP_L85A2_SUSAT_C : public ABP_L85A2_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_L85A2_SUSAT_C;                   // 0x09A0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UBP_Pip_C*                              BP_Pip;                                            // 0x09A8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   LensMesh;                                          // 0x09B0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_L85A2_SUSAT(int32 EntryPoint);
	void StopModifyZeroing();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_L85A2_SUSAT_C">();
	}
	static class ABP_L85A2_SUSAT_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_L85A2_SUSAT_C>();
	}
};
#pragma pack(pop)
static_assert(alignof(ABP_L85A2_SUSAT_C) == 0x000010, "Wrong alignment on ABP_L85A2_SUSAT_C");
static_assert(sizeof(ABP_L85A2_SUSAT_C) == 0x0009C0, "Wrong size on ABP_L85A2_SUSAT_C");
static_assert(offsetof(ABP_L85A2_SUSAT_C, UberGraphFrame_BP_L85A2_SUSAT_C) == 0x0009A0, "Member 'ABP_L85A2_SUSAT_C::UberGraphFrame_BP_L85A2_SUSAT_C' has a wrong offset!");
static_assert(offsetof(ABP_L85A2_SUSAT_C, BP_Pip) == 0x0009A8, "Member 'ABP_L85A2_SUSAT_C::BP_Pip' has a wrong offset!");
static_assert(offsetof(ABP_L85A2_SUSAT_C, LensMesh) == 0x0009B0, "Member 'ABP_L85A2_SUSAT_C::LensMesh' has a wrong offset!");

}

