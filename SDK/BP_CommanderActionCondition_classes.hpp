#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_CommanderActionCondition

#include "Basic.hpp"

#include "CoreUObject_classes.hpp"
#include "Squad_structs.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_CommanderActionCondition.BP_CommanderActionCondition_C
// 0x0008 (0x0030 - 0x0028)
class UBP_CommanderActionCondition_C final : public UObject
{
public:
	class ASQGameState*                           GameState;                                         // 0x0028(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)

public:
	void Can_Use_Actions(class ASQPlayerController* Player, class UClass* Command_Option, bool Require_Active, bool* Valid, class FText* Out_Reason);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_CommanderActionCondition_C">();
	}
	static class UBP_CommanderActionCondition_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_CommanderActionCondition_C>();
	}
};
static_assert(alignof(UBP_CommanderActionCondition_C) == 0x000008, "Wrong alignment on UBP_CommanderActionCondition_C");
static_assert(sizeof(UBP_CommanderActionCondition_C) == 0x000030, "Wrong size on UBP_CommanderActionCondition_C");
static_assert(offsetof(UBP_CommanderActionCondition_C, GameState) == 0x000028, "Member 'UBP_CommanderActionCondition_C::GameState' has a wrong offset!");

}

