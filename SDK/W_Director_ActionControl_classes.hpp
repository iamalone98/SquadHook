#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_Director_ActionControl

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "W_FloatingWidget_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_Director_ActionControl.W_Director_ActionControl_C
// 0x0048 (0x02C0 - 0x0278)
class UW_Director_ActionControl_C : public UW_FloatingWidget_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_W_Director_ActionControl_C;         // 0x0278(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	float                                         Widget_Angle_Rotation_Offset;                      // 0x0280(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_258A[0x4];                                     // 0x0284(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UClass*                                 Director_Action;                                   // 0x0288(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	struct FVector                                Local_World_Location;                              // 0x0290(0x000C)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	struct FVector2D                              Alignment;                                         // 0x029C(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Squad_ID;                                          // 0x02A4(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	class UW_SQMapCore_C*                         Map_Core;                                          // 0x02A8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              Origin_Map_Position;                               // 0x02B0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQMapMarkerDataAsset*                  MapMarkerDataAsset;                                // 0x02B8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_W_Director_ActionControl(int32 EntryPoint);
	void Add_Self_To_Viewport();
	void On_Map_Mouse_Down(const struct FPointerEvent& Mouse_Event, const struct FVector& World_Location);
	void Remove();
	void Construct();
	void Get_Angle(float* Widget_Angle, struct FRotator* World_Rotation);
	void Get_Pixel_Distance(float* Distance);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_Director_ActionControl_C">();
	}
	static class UW_Director_ActionControl_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_Director_ActionControl_C>();
	}
};
static_assert(alignof(UW_Director_ActionControl_C) == 0x000008, "Wrong alignment on UW_Director_ActionControl_C");
static_assert(sizeof(UW_Director_ActionControl_C) == 0x0002C0, "Wrong size on UW_Director_ActionControl_C");
static_assert(offsetof(UW_Director_ActionControl_C, UberGraphFrame_W_Director_ActionControl_C) == 0x000278, "Member 'UW_Director_ActionControl_C::UberGraphFrame_W_Director_ActionControl_C' has a wrong offset!");
static_assert(offsetof(UW_Director_ActionControl_C, Widget_Angle_Rotation_Offset) == 0x000280, "Member 'UW_Director_ActionControl_C::Widget_Angle_Rotation_Offset' has a wrong offset!");
static_assert(offsetof(UW_Director_ActionControl_C, Director_Action) == 0x000288, "Member 'UW_Director_ActionControl_C::Director_Action' has a wrong offset!");
static_assert(offsetof(UW_Director_ActionControl_C, Local_World_Location) == 0x000290, "Member 'UW_Director_ActionControl_C::Local_World_Location' has a wrong offset!");
static_assert(offsetof(UW_Director_ActionControl_C, Alignment) == 0x00029C, "Member 'UW_Director_ActionControl_C::Alignment' has a wrong offset!");
static_assert(offsetof(UW_Director_ActionControl_C, Squad_ID) == 0x0002A4, "Member 'UW_Director_ActionControl_C::Squad_ID' has a wrong offset!");
static_assert(offsetof(UW_Director_ActionControl_C, Map_Core) == 0x0002A8, "Member 'UW_Director_ActionControl_C::Map_Core' has a wrong offset!");
static_assert(offsetof(UW_Director_ActionControl_C, Origin_Map_Position) == 0x0002B0, "Member 'UW_Director_ActionControl_C::Origin_Map_Position' has a wrong offset!");
static_assert(offsetof(UW_Director_ActionControl_C, MapMarkerDataAsset) == 0x0002B8, "Member 'UW_Director_ActionControl_C::MapMarkerDataAsset' has a wrong offset!");

}

