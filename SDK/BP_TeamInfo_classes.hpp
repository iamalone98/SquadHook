#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_TeamInfo

#include "Basic.hpp"

#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_TeamInfo.BP_TeamInfo_C
// 0x0018 (0x0398 - 0x0380)
class UBP_TeamInfo_C final : public USQTeamInfo
{
public:
	class UClass*                                 SLCommandMenu;                                     // 0x0380(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 NonBuildSLCommandMenu;                             // 0x0388(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 FTLCommandMenu;                                    // 0x0390(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_TeamInfo_C">();
	}
	static class UBP_TeamInfo_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_TeamInfo_C>();
	}
};
static_assert(alignof(UBP_TeamInfo_C) == 0x000008, "Wrong alignment on UBP_TeamInfo_C");
static_assert(sizeof(UBP_TeamInfo_C) == 0x000398, "Wrong size on UBP_TeamInfo_C");
static_assert(offsetof(UBP_TeamInfo_C, SLCommandMenu) == 0x000380, "Member 'UBP_TeamInfo_C::SLCommandMenu' has a wrong offset!");
static_assert(offsetof(UBP_TeamInfo_C, NonBuildSLCommandMenu) == 0x000388, "Member 'UBP_TeamInfo_C::NonBuildSLCommandMenu' has a wrong offset!");
static_assert(offsetof(UBP_TeamInfo_C, FTLCommandMenu) == 0x000390, "Member 'UBP_TeamInfo_C::FTLCommandMenu' has a wrong offset!");

}
