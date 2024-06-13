#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_MapMarker_Circle

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "W_MapMarker_DirectorParent_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_MapMarker_Circle.W_MapMarker_Circle_C
// 0x0028 (0x0340 - 0x0318)
class UW_MapMarker_Circle_C final : public UW_MapMarker_DirectorParent_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_W_MapMarker_Circle_C;               // 0x0318(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       In;                                                // 0x0320(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UBorder*                                Fill;                                              // 0x0328(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USizeBox*                               SizeBox_0;                                         // 0x0330(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UMaterialInstanceDynamic*               MI_Arrows;                                         // 0x0338(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_W_MapMarker_Circle(int32 EntryPoint);
	void OnTintChanged();
	void Tick(const struct FGeometry& MyGeometry, float InDeltaTime);
	void Update_Size();
	void Construct();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_MapMarker_Circle_C">();
	}
	static class UW_MapMarker_Circle_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_MapMarker_Circle_C>();
	}
};
static_assert(alignof(UW_MapMarker_Circle_C) == 0x000008, "Wrong alignment on UW_MapMarker_Circle_C");
static_assert(sizeof(UW_MapMarker_Circle_C) == 0x000340, "Wrong size on UW_MapMarker_Circle_C");
static_assert(offsetof(UW_MapMarker_Circle_C, UberGraphFrame_W_MapMarker_Circle_C) == 0x000318, "Member 'UW_MapMarker_Circle_C::UberGraphFrame_W_MapMarker_Circle_C' has a wrong offset!");
static_assert(offsetof(UW_MapMarker_Circle_C, In) == 0x000320, "Member 'UW_MapMarker_Circle_C::In' has a wrong offset!");
static_assert(offsetof(UW_MapMarker_Circle_C, Fill) == 0x000328, "Member 'UW_MapMarker_Circle_C::Fill' has a wrong offset!");
static_assert(offsetof(UW_MapMarker_Circle_C, SizeBox_0) == 0x000330, "Member 'UW_MapMarker_Circle_C::SizeBox_0' has a wrong offset!");
static_assert(offsetof(UW_MapMarker_Circle_C, MI_Arrows) == 0x000338, "Member 'UW_MapMarker_Circle_C::MI_Arrows' has a wrong offset!");

}
