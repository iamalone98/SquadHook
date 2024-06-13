#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_GridHeader

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "E_HeaderDirection_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "UMG_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_GridHeader.W_GridHeader_C
// 0x0068 (0x02C8 - 0x0260)
class UW_GridHeader_C : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UGridPanel*                             GridPanel_Main;                                    // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	E_HeaderDirection                             Draw_Direction;                                    // 0x0270(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	E_HeaderDirection                             Build_Direction;                                   // 0x0271(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	uint8                                         Pad_3CCE[0x6];                                     // 0x0272(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<class UClass*>                         Buttons;                                           // 0x0278(0x0010)(Edit, BlueprintVisible)
	class UTexture2D*                             Header_Icon;                                       // 0x0288(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           Icon_Color;                                        // 0x0290(0x0010)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TArray<class UW_GridButton_C*>                My_Buttons;                                        // 0x02A0(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance, ContainsInstancedReference)
	bool                                          Buttons_Visible;                                   // 0x02B0(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3CCF[0x3];                                     // 0x02B1(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FVector2D                              Screen_Position;                                   // 0x02B4(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	uint8                                         Pad_3CD0[0x4];                                     // 0x02BC(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_GridMenu_C*                          Grid_Menu;                                         // 0x02C0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_W_GridHeader(int32 EntryPoint);
	void Construct_Buttons();
	void Construct();
	void Set_Viewport_Position();
	void Set_Buttons_Visibility(bool Visible);
	void Get_Fireteam_ID(int32* ID);
	void Get_Squad_ID(int32* ID);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_GridHeader_C">();
	}
	static class UW_GridHeader_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_GridHeader_C>();
	}
};
static_assert(alignof(UW_GridHeader_C) == 0x000008, "Wrong alignment on UW_GridHeader_C");
static_assert(sizeof(UW_GridHeader_C) == 0x0002C8, "Wrong size on UW_GridHeader_C");
static_assert(offsetof(UW_GridHeader_C, UberGraphFrame) == 0x000260, "Member 'UW_GridHeader_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_GridHeader_C, GridPanel_Main) == 0x000268, "Member 'UW_GridHeader_C::GridPanel_Main' has a wrong offset!");
static_assert(offsetof(UW_GridHeader_C, Draw_Direction) == 0x000270, "Member 'UW_GridHeader_C::Draw_Direction' has a wrong offset!");
static_assert(offsetof(UW_GridHeader_C, Build_Direction) == 0x000271, "Member 'UW_GridHeader_C::Build_Direction' has a wrong offset!");
static_assert(offsetof(UW_GridHeader_C, Buttons) == 0x000278, "Member 'UW_GridHeader_C::Buttons' has a wrong offset!");
static_assert(offsetof(UW_GridHeader_C, Header_Icon) == 0x000288, "Member 'UW_GridHeader_C::Header_Icon' has a wrong offset!");
static_assert(offsetof(UW_GridHeader_C, Icon_Color) == 0x000290, "Member 'UW_GridHeader_C::Icon_Color' has a wrong offset!");
static_assert(offsetof(UW_GridHeader_C, My_Buttons) == 0x0002A0, "Member 'UW_GridHeader_C::My_Buttons' has a wrong offset!");
static_assert(offsetof(UW_GridHeader_C, Buttons_Visible) == 0x0002B0, "Member 'UW_GridHeader_C::Buttons_Visible' has a wrong offset!");
static_assert(offsetof(UW_GridHeader_C, Screen_Position) == 0x0002B4, "Member 'UW_GridHeader_C::Screen_Position' has a wrong offset!");
static_assert(offsetof(UW_GridHeader_C, Grid_Menu) == 0x0002C0, "Member 'UW_GridHeader_C::Grid_Menu' has a wrong offset!");

}
