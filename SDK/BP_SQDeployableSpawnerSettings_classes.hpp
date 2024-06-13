#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_SQDeployableSpawnerSettings

#include "Basic.hpp"

#include "ESQDeployable_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_SQDeployableSpawnerSettings.BP_SQDeployableSpawnerSettings_C
// 0x0008 (0x0068 - 0x0060)
class UBP_SQDeployableSpawnerSettings_C final : public USQDeployableSpawnerSettings
{
public:
	ESQDeployable                                 Type;                                              // 0x0060(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	bool IsDeployableMatching(const class USQDeployableSettings* InAvailableDeployable) const;
	void GetDeployableSpawnerEntry(bool* Success, struct FSQDeployableSpawnerEntry* DeployableSpawnerEntry) const;

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_SQDeployableSpawnerSettings_C">();
	}
	static class UBP_SQDeployableSpawnerSettings_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_SQDeployableSpawnerSettings_C>();
	}
};
static_assert(alignof(UBP_SQDeployableSpawnerSettings_C) == 0x000008, "Wrong alignment on UBP_SQDeployableSpawnerSettings_C");
static_assert(sizeof(UBP_SQDeployableSpawnerSettings_C) == 0x000068, "Wrong size on UBP_SQDeployableSpawnerSettings_C");
static_assert(offsetof(UBP_SQDeployableSpawnerSettings_C, Type) == 0x000060, "Member 'UBP_SQDeployableSpawnerSettings_C::Type' has a wrong offset!");

}

