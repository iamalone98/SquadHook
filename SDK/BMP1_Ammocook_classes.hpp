#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BMP1_Ammocook

#include "Basic.hpp"

#include "BMP1_MEA_Ammocook_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BMP1_Ammocook.BMP1_Ammocook_C
// 0x0000 (0x03E0 - 0x03E0)
class ABMP1_Ammocook_C final : public ABMP1_MEA_Ammocook_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BMP1_Ammocook_C">();
	}
	static class ABMP1_Ammocook_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABMP1_Ammocook_C>();
	}
};
static_assert(alignof(ABMP1_Ammocook_C) == 0x000008, "Wrong alignment on ABMP1_Ammocook_C");
static_assert(sizeof(ABMP1_Ammocook_C) == 0x0003E0, "Wrong size on ABMP1_Ammocook_C");

}
