#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_GridButton_OrderDirectors

#include "Basic.hpp"

#include "W_GridButton_classes.hpp"
#include "Engine_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_GridButton_OrderDirectors.W_GridButton_OrderDirectors_C
// 0x0008 (0x0310 - 0x0308)
class UW_GridButton_OrderDirectors_C final : public UW_GridButton_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_W_GridButton_OrderDirectors_C;      // 0x0308(0x0008)(ZeroConstructor, Transient, DuplicateTransient)

public:
	void ExecuteUbergraph_W_GridButton_OrderDirectors(int32 EntryPoint);
	void Grid_Button_Pressed();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_GridButton_OrderDirectors_C">();
	}
	static class UW_GridButton_OrderDirectors_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_GridButton_OrderDirectors_C>();
	}
};
static_assert(alignof(UW_GridButton_OrderDirectors_C) == 0x000008, "Wrong alignment on UW_GridButton_OrderDirectors_C");
static_assert(sizeof(UW_GridButton_OrderDirectors_C) == 0x000310, "Wrong size on UW_GridButton_OrderDirectors_C");
static_assert(offsetof(UW_GridButton_OrderDirectors_C, UberGraphFrame_W_GridButton_OrderDirectors_C) == 0x000308, "Member 'UW_GridButton_OrderDirectors_C::UberGraphFrame_W_GridButton_OrderDirectors_C' has a wrong offset!");

}

