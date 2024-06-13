#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_SQActionSettings

#include "Basic.hpp"

#include "SQActionVersion_structs.hpp"
#include "ESQAction_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_SQActionSettings.BP_SQActionSettings_C
// 0x0018 (0x0080 - 0x0068)
class UBP_SQActionSettings_C : public USQActionSettings
{
public:
	ESQAction                                     Type;                                              // 0x0068(0x0001)(Edit, BlueprintVisible, BlueprintReadOnly, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4379[0x7];                                     // 0x0069(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<struct FSQActionVersion>               ActionVersions;                                    // 0x0070(0x0010)(Edit, BlueprintVisible, BlueprintReadOnly, DisableEditOnInstance)

public:
	void GetActionEntry(bool* Success, struct FSQActionEntry* ActionEntry) const;
	void GetAction(class UBP_SQLevel_C* Level, TSoftClassPtr<class UClass>* Action) const;

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_SQActionSettings_C">();
	}
	static class UBP_SQActionSettings_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_SQActionSettings_C>();
	}
};
static_assert(alignof(UBP_SQActionSettings_C) == 0x000008, "Wrong alignment on UBP_SQActionSettings_C");
static_assert(sizeof(UBP_SQActionSettings_C) == 0x000080, "Wrong size on UBP_SQActionSettings_C");
static_assert(offsetof(UBP_SQActionSettings_C, Type) == 0x000068, "Member 'UBP_SQActionSettings_C::Type' has a wrong offset!");
static_assert(offsetof(UBP_SQActionSettings_C, ActionVersions) == 0x000070, "Member 'UBP_SQActionSettings_C::ActionVersions' has a wrong offset!");

}
