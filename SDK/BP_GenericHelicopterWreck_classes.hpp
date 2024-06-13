#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GenericHelicopterWreck

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_GenericDestroyedVehicleWreck_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_GenericHelicopterWreck.BP_GenericHelicopterWreck_C
// 0x0008 (0x03C8 - 0x03C0)
class ABP_GenericHelicopterWreck_C : public ABP_GenericDestroyedVehicleWreck_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x03C0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)

public:
	void ExecuteUbergraph_BP_GenericHelicopterWreck(int32 EntryPoint);
	void ReceiveBeginPlay();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_GenericHelicopterWreck_C">();
	}
	static class ABP_GenericHelicopterWreck_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_GenericHelicopterWreck_C>();
	}
};
static_assert(alignof(ABP_GenericHelicopterWreck_C) == 0x000008, "Wrong alignment on ABP_GenericHelicopterWreck_C");
static_assert(sizeof(ABP_GenericHelicopterWreck_C) == 0x0003C8, "Wrong size on ABP_GenericHelicopterWreck_C");
static_assert(offsetof(ABP_GenericHelicopterWreck_C, UberGraphFrame) == 0x0003C0, "Member 'ABP_GenericHelicopterWreck_C::UberGraphFrame' has a wrong offset!");

}

