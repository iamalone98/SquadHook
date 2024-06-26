#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_SpawnableItemBase

#include "Basic.hpp"

#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_SpawnableItemBase.BP_SpawnableItemBase_C
// 0x0038 (0x0068 - 0x0030)
class UBP_SpawnableItemBase_C : public USQSpawnableItemBase
{
public:
	class FText                                   Object_Name;                                       // 0x0030(0x0018)(Edit, BlueprintVisible, DisableEditOnInstance)
	class FText                                   ObjectPath;                                        // 0x0048(0x0018)(Edit, BlueprintVisible, DisableEditOnInstance)
	class UBP_SQLayer_C*                          CurrentLayer;                                      // 0x0060(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)

public:
	void Setup(class UObject* Data, bool* Success, class FText* FailReason);

	class FString GetSearchableName() const;

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_SpawnableItemBase_C">();
	}
	static class UBP_SpawnableItemBase_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_SpawnableItemBase_C>();
	}
};
static_assert(alignof(UBP_SpawnableItemBase_C) == 0x000008, "Wrong alignment on UBP_SpawnableItemBase_C");
static_assert(sizeof(UBP_SpawnableItemBase_C) == 0x000068, "Wrong size on UBP_SpawnableItemBase_C");
static_assert(offsetof(UBP_SpawnableItemBase_C, Object_Name) == 0x000030, "Member 'UBP_SpawnableItemBase_C::Object_Name' has a wrong offset!");
static_assert(offsetof(UBP_SpawnableItemBase_C, ObjectPath) == 0x000048, "Member 'UBP_SpawnableItemBase_C::ObjectPath' has a wrong offset!");
static_assert(offsetof(UBP_SpawnableItemBase_C, CurrentLayer) == 0x000060, "Member 'UBP_SpawnableItemBase_C::CurrentLayer' has a wrong offset!");

}

