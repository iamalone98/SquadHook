#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_AASGraph

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_AASGraph.BP_AASGraph_C
// 0x0028 (0x02A0 - 0x0278)
class ABP_AASGraph_C final : public ASQAASGraph
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0278(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UGraphNodeBasedBleedComponent_C*        GraphNodeBasedBleedComponent;                      // 0x0280(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UGraphTicketComponent_C*                GraphTicketComponent;                              // 0x0288(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQGraphAASVisualizerComponent*         SQGraphAASVisualizer;                              // 0x0290(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQGraphAASInitializerComponent*        SQGraphAASInitializer;                             // 0x0298(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_AASGraph(int32 EntryPoint);
	void Toggle_Visualizer();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_AASGraph_C">();
	}
	static class ABP_AASGraph_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_AASGraph_C>();
	}
};
static_assert(alignof(ABP_AASGraph_C) == 0x000008, "Wrong alignment on ABP_AASGraph_C");
static_assert(sizeof(ABP_AASGraph_C) == 0x0002A0, "Wrong size on ABP_AASGraph_C");
static_assert(offsetof(ABP_AASGraph_C, UberGraphFrame) == 0x000278, "Member 'ABP_AASGraph_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ABP_AASGraph_C, GraphNodeBasedBleedComponent) == 0x000280, "Member 'ABP_AASGraph_C::GraphNodeBasedBleedComponent' has a wrong offset!");
static_assert(offsetof(ABP_AASGraph_C, GraphTicketComponent) == 0x000288, "Member 'ABP_AASGraph_C::GraphTicketComponent' has a wrong offset!");
static_assert(offsetof(ABP_AASGraph_C, SQGraphAASVisualizer) == 0x000290, "Member 'ABP_AASGraph_C::SQGraphAASVisualizer' has a wrong offset!");
static_assert(offsetof(ABP_AASGraph_C, SQGraphAASInitializer) == 0x000298, "Member 'ABP_AASGraph_C::SQGraphAASInitializer' has a wrong offset!");

}

