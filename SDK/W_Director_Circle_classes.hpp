#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_Director_Circle

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "W_Director_ActionControl_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_Director_Circle.W_Director_Circle_C
// 0x0018 (0x02D8 - 0x02C0)
class UW_Director_Circle_C final : public UW_Director_ActionControl_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_W_Director_Circle_C;                // 0x02C0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UBorder*                                Fill;                                              // 0x02C8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USizeBox*                               SizeBox_0;                                         // 0x02D0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_W_Director_Circle(int32 EntryPoint);
	void Tick(const struct FGeometry& MyGeometry, float InDeltaTime);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_Director_Circle_C">();
	}
	static class UW_Director_Circle_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_Director_Circle_C>();
	}
};
static_assert(alignof(UW_Director_Circle_C) == 0x000008, "Wrong alignment on UW_Director_Circle_C");
static_assert(sizeof(UW_Director_Circle_C) == 0x0002D8, "Wrong size on UW_Director_Circle_C");
static_assert(offsetof(UW_Director_Circle_C, UberGraphFrame_W_Director_Circle_C) == 0x0002C0, "Member 'UW_Director_Circle_C::UberGraphFrame_W_Director_Circle_C' has a wrong offset!");
static_assert(offsetof(UW_Director_Circle_C, Fill) == 0x0002C8, "Member 'UW_Director_Circle_C::Fill' has a wrong offset!");
static_assert(offsetof(UW_Director_Circle_C, SizeBox_0) == 0x0002D0, "Member 'UW_Director_Circle_C::SizeBox_0' has a wrong offset!");

}
