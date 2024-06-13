#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GenericMapMarker

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "Squad_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_GenericMapMarker.BP_GenericMapMarker_C
// 0x0020 (0x0280 - 0x0260)
class ABP_GenericMapMarker_C : public ASQMapMarker
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class USceneComponent*                        DefaultSceneRoot;                                  // 0x0268(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           DefaultTint;                                       // 0x0270(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_GenericMapMarker(int32 EntryPoint);
	void ReceiveDestroyed();
	void ReceiveBeginPlay();
	void SetTexture(class UTexture2D* Texture);
	void UserConstructionScript();
	void MarkerIsRelevant(class AController* Controller, bool* Success);
	void Tint();
	void Remove_FT_Markers();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_GenericMapMarker_C">();
	}
	static class ABP_GenericMapMarker_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_GenericMapMarker_C>();
	}
};
static_assert(alignof(ABP_GenericMapMarker_C) == 0x000008, "Wrong alignment on ABP_GenericMapMarker_C");
static_assert(sizeof(ABP_GenericMapMarker_C) == 0x000280, "Wrong size on ABP_GenericMapMarker_C");
static_assert(offsetof(ABP_GenericMapMarker_C, UberGraphFrame) == 0x000260, "Member 'ABP_GenericMapMarker_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ABP_GenericMapMarker_C, DefaultSceneRoot) == 0x000268, "Member 'ABP_GenericMapMarker_C::DefaultSceneRoot' has a wrong offset!");
static_assert(offsetof(ABP_GenericMapMarker_C, DefaultTint) == 0x000270, "Member 'ABP_GenericMapMarker_C::DefaultTint' has a wrong offset!");

}

