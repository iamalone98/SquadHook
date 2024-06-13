#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_TestLadder_Wood

#include "Basic.hpp"

#include "BP_Deployable_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_TestLadder_Wood.BP_TestLadder_Wood_C
// 0x0060 (0x04A0 - 0x0440)
class ABP_TestLadder_Wood_C : public ABP_Deployable_C
{
public:
	class UBoxComponent*                          InteractZone;                                      // 0x0440(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh2;                                       // 0x0448(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh8;                                       // 0x0450(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh7;                                       // 0x0458(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh3;                                       // 0x0460(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh6;                                       // 0x0468(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh5;                                       // 0x0470(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh4;                                       // 0x0478(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Ladder_2;                                          // 0x0480(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UBoxComponent*                          ConstructionBox;                                   // 0x0488(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh1;                                       // 0x0490(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh;                                        // 0x0498(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_TestLadder_Wood_C">();
	}
	static class ABP_TestLadder_Wood_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_TestLadder_Wood_C>();
	}
};
static_assert(alignof(ABP_TestLadder_Wood_C) == 0x000008, "Wrong alignment on ABP_TestLadder_Wood_C");
static_assert(sizeof(ABP_TestLadder_Wood_C) == 0x0004A0, "Wrong size on ABP_TestLadder_Wood_C");
static_assert(offsetof(ABP_TestLadder_Wood_C, InteractZone) == 0x000440, "Member 'ABP_TestLadder_Wood_C::InteractZone' has a wrong offset!");
static_assert(offsetof(ABP_TestLadder_Wood_C, StaticMesh2) == 0x000448, "Member 'ABP_TestLadder_Wood_C::StaticMesh2' has a wrong offset!");
static_assert(offsetof(ABP_TestLadder_Wood_C, StaticMesh8) == 0x000450, "Member 'ABP_TestLadder_Wood_C::StaticMesh8' has a wrong offset!");
static_assert(offsetof(ABP_TestLadder_Wood_C, StaticMesh7) == 0x000458, "Member 'ABP_TestLadder_Wood_C::StaticMesh7' has a wrong offset!");
static_assert(offsetof(ABP_TestLadder_Wood_C, StaticMesh3) == 0x000460, "Member 'ABP_TestLadder_Wood_C::StaticMesh3' has a wrong offset!");
static_assert(offsetof(ABP_TestLadder_Wood_C, StaticMesh6) == 0x000468, "Member 'ABP_TestLadder_Wood_C::StaticMesh6' has a wrong offset!");
static_assert(offsetof(ABP_TestLadder_Wood_C, StaticMesh5) == 0x000470, "Member 'ABP_TestLadder_Wood_C::StaticMesh5' has a wrong offset!");
static_assert(offsetof(ABP_TestLadder_Wood_C, StaticMesh4) == 0x000478, "Member 'ABP_TestLadder_Wood_C::StaticMesh4' has a wrong offset!");
static_assert(offsetof(ABP_TestLadder_Wood_C, Ladder_2) == 0x000480, "Member 'ABP_TestLadder_Wood_C::Ladder_2' has a wrong offset!");
static_assert(offsetof(ABP_TestLadder_Wood_C, ConstructionBox) == 0x000488, "Member 'ABP_TestLadder_Wood_C::ConstructionBox' has a wrong offset!");
static_assert(offsetof(ABP_TestLadder_Wood_C, StaticMesh1) == 0x000490, "Member 'ABP_TestLadder_Wood_C::StaticMesh1' has a wrong offset!");
static_assert(offsetof(ABP_TestLadder_Wood_C, StaticMesh) == 0x000498, "Member 'ABP_TestLadder_Wood_C::StaticMesh' has a wrong offset!");

}
