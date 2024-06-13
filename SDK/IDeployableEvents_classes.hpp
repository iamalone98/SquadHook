#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: IDeployableEvents

#include "Basic.hpp"

#include "CoreUObject_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass IDeployableEvents.IDeployableEvents_C
// 0x0000 (0x0028 - 0x0028)
class IIDeployableEvents_C final : public IInterface
{
public:
	void OnServerValidatedItemPlacement(class ASQDeployableItem* Deployable);
	void OnClientInvalidatedItemPlacement();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"IDeployableEvents_C">();
	}
	static class IIDeployableEvents_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<IIDeployableEvents_C>();
	}
};
static_assert(alignof(IIDeployableEvents_C) == 0x000008, "Wrong alignment on IIDeployableEvents_C");
static_assert(sizeof(IIDeployableEvents_C) == 0x000028, "Wrong size on IIDeployableEvents_C");

}
