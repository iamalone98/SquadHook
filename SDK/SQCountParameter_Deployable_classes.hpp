#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SQCountParameter_Deployable

#include "Basic.hpp"

#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass SQCountParameter_Deployable.SQCountParameter_Deployable_C
// 0x0000 (0x0080 - 0x0080)
class USQCountParameter_Deployable_C final : public USQCountParameter
{
public:
	bool TryGetValueForPlayer(const class ASQPlayerController* InPlayer, int32* OutValue) const;

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"SQCountParameter_Deployable_C">();
	}
	static class USQCountParameter_Deployable_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<USQCountParameter_Deployable_C>();
	}
};
static_assert(alignof(USQCountParameter_Deployable_C) == 0x000008, "Wrong alignment on USQCountParameter_Deployable_C");
static_assert(sizeof(USQCountParameter_Deployable_C) == 0x000080, "Wrong size on USQCountParameter_Deployable_C");

}
