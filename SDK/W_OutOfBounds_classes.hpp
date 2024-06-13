#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_OutOfBounds

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_OutOfBounds.W_OutOfBounds_C
// 0x0028 (0x0288 - 0x0260)
class UW_OutOfBounds_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       RepeatAnim;                                        // 0x0268(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UImage*                                 Image_0;                                           // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Line;                                              // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	float                                         Kill_Timestamp;                                    // 0x0280(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_W_OutOfBounds(int32 EntryPoint);
	void Hide_Out_of_Bounds_Widget();
	void Show_Out_of_Bounds_Widget();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_OutOfBounds_C">();
	}
	static class UW_OutOfBounds_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_OutOfBounds_C>();
	}
};
static_assert(alignof(UW_OutOfBounds_C) == 0x000008, "Wrong alignment on UW_OutOfBounds_C");
static_assert(sizeof(UW_OutOfBounds_C) == 0x000288, "Wrong size on UW_OutOfBounds_C");
static_assert(offsetof(UW_OutOfBounds_C, UberGraphFrame) == 0x000260, "Member 'UW_OutOfBounds_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_OutOfBounds_C, RepeatAnim) == 0x000268, "Member 'UW_OutOfBounds_C::RepeatAnim' has a wrong offset!");
static_assert(offsetof(UW_OutOfBounds_C, Image_0) == 0x000270, "Member 'UW_OutOfBounds_C::Image_0' has a wrong offset!");
static_assert(offsetof(UW_OutOfBounds_C, Line) == 0x000278, "Member 'UW_OutOfBounds_C::Line' has a wrong offset!");
static_assert(offsetof(UW_OutOfBounds_C, Kill_Timestamp) == 0x000280, "Member 'UW_OutOfBounds_C::Kill_Timestamp' has a wrong offset!");

}
