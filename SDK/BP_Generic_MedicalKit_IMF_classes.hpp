#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Generic_MedicalKit_IMF

#include "Basic.hpp"

#include "BP_Generic_MedicalKit_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_Generic_MedicalKit_IMF.BP_Generic_MedicalKit_IMF_C
// 0x0000 (0x0530 - 0x0530)
class ABP_Generic_MedicalKit_IMF_C final : public ABP_Generic_MedicalKit_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Generic_MedicalKit_IMF_C">();
	}
	static class ABP_Generic_MedicalKit_IMF_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_Generic_MedicalKit_IMF_C>();
	}
};
static_assert(alignof(ABP_Generic_MedicalKit_IMF_C) == 0x000008, "Wrong alignment on ABP_Generic_MedicalKit_IMF_C");
static_assert(sizeof(ABP_Generic_MedicalKit_IMF_C) == 0x000530, "Wrong size on ABP_Generic_MedicalKit_IMF_C");

}
