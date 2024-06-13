#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GenericBinoculars

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_Weapon2_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_GenericBinoculars.BP_GenericBinoculars_C
// 0x0010 (0x09B0 - 0x09A0)
class ABP_GenericBinoculars_C : public ABP_Weapon2_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_GenericBinoculars_C;             // 0x09A0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)

public:
	void ExecuteUbergraph_BP_GenericBinoculars(int32 EntryPoint);
	void BlueprintOnZoom(bool bNewZoom);
	void BlueprintOnUnequip();
	void BlueprintOnEquip();
	struct FVector Get_Marker_Location(bool* Valid);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_GenericBinoculars_C">();
	}
	static class ABP_GenericBinoculars_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_GenericBinoculars_C>();
	}
};
static_assert(alignof(ABP_GenericBinoculars_C) == 0x000010, "Wrong alignment on ABP_GenericBinoculars_C");
static_assert(sizeof(ABP_GenericBinoculars_C) == 0x0009B0, "Wrong size on ABP_GenericBinoculars_C");
static_assert(offsetof(ABP_GenericBinoculars_C, UberGraphFrame_BP_GenericBinoculars_C) == 0x0009A0, "Member 'ABP_GenericBinoculars_C::UberGraphFrame_BP_GenericBinoculars_C' has a wrong offset!");

}

