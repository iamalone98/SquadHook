#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Technical4Seater_Generic

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_Technical2Seater_Generic_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_Technical4Seater_Generic.BP_Technical4Seater_Generic_C
// 0x0020 (0x0C20 - 0x0C00)
class ABP_Technical4Seater_Generic_C : public ABP_Technical2Seater_Generic_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_Technical4Seater_Generic_C;      // 0x0C00(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UStaticMeshComponent*                   InteriorDeco;                                      // 0x0C08(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Supplies;                                          // 0x0C10(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_Technical4Seater_Generic(int32 EntryPoint);
	void ReceiveBeginPlay();
	void DrivetrainComponentDestroyed(class USQDriveTrainComponent* DriveTrainComponent);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Technical4Seater_Generic_C">();
	}
	static class ABP_Technical4Seater_Generic_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_Technical4Seater_Generic_C>();
	}
};
static_assert(alignof(ABP_Technical4Seater_Generic_C) == 0x000010, "Wrong alignment on ABP_Technical4Seater_Generic_C");
static_assert(sizeof(ABP_Technical4Seater_Generic_C) == 0x000C20, "Wrong size on ABP_Technical4Seater_Generic_C");
static_assert(offsetof(ABP_Technical4Seater_Generic_C, UberGraphFrame_BP_Technical4Seater_Generic_C) == 0x000C00, "Member 'ABP_Technical4Seater_Generic_C::UberGraphFrame_BP_Technical4Seater_Generic_C' has a wrong offset!");
static_assert(offsetof(ABP_Technical4Seater_Generic_C, InteriorDeco) == 0x000C08, "Member 'ABP_Technical4Seater_Generic_C::InteriorDeco' has a wrong offset!");
static_assert(offsetof(ABP_Technical4Seater_Generic_C, Supplies) == 0x000C10, "Member 'ABP_Technical4Seater_Generic_C::Supplies' has a wrong offset!");

}

