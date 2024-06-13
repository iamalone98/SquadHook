#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_SpawnableRoleItem

#include "Basic.hpp"

#include "BP_SpawnableItemBase_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_SpawnableRoleItem.BP_SpawnableRoleItem_C
// 0x0030 (0x0098 - 0x0068)
class UBP_SpawnableRoleItem_C final : public UBP_SpawnableItemBase_C
{
public:
	class UBP_SQRoleSettings_C*                   RoleSetting;                                       // 0x0068(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	TSoftClassPtr<class UClass>                   SoldierClass;                                      // 0x0070(0x0028)(Edit, BlueprintVisible, DisableEditOnInstance, HasGetValueTypeHash)

public:
	void Setup(class UObject* Data, bool* Success, class FText* FailReason);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_SpawnableRoleItem_C">();
	}
	static class UBP_SpawnableRoleItem_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_SpawnableRoleItem_C>();
	}
};
static_assert(alignof(UBP_SpawnableRoleItem_C) == 0x000008, "Wrong alignment on UBP_SpawnableRoleItem_C");
static_assert(sizeof(UBP_SpawnableRoleItem_C) == 0x000098, "Wrong size on UBP_SpawnableRoleItem_C");
static_assert(offsetof(UBP_SpawnableRoleItem_C, RoleSetting) == 0x000068, "Member 'UBP_SpawnableRoleItem_C::RoleSetting' has a wrong offset!");
static_assert(offsetof(UBP_SpawnableRoleItem_C, SoldierClass) == 0x000070, "Member 'UBP_SpawnableRoleItem_C::SoldierClass' has a wrong offset!");

}

