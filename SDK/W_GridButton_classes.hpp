#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_GridButton

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "E_HeaderDirection_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_GridButton.W_GridButton_C
// 0x00A8 (0x0308 - 0x0260)
class UW_GridButton_C : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UButton*                                Button_Main;                                       // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Icon;                                              // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UWidgetSwitcher*                        Switch_IconText;                                   // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_ID;                                             // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	E_HeaderDirection                             Parent_Draw_Direction;                             // 0x0288(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	E_HeaderDirection                             Build_Direction;                                   // 0x0289(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	uint8                                         Pad_2CAD[0x6];                                     // 0x028A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class UTexture2D*                             Button_Icon;                                       // 0x0290(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           Icon_Color;                                        // 0x0298(0x0010)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UW_GridHeader_C*                        Header_Parent;                                     // 0x02A8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	bool                                          Parent_Button;                                     // 0x02B0(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn)
	bool                                          Actions_Visible;                                   // 0x02B1(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2CAE[0x6];                                     // 0x02B2(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class UClass*                                 Default_Map_Marker;                                // 0x02B8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 Action_List_Class;                                 // 0x02C0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FText                                   Tooltip;                                           // 0x02C8(0x0018)(Edit, BlueprintVisible)
	TArray<class UClass*>                         Action_List;                                       // 0x02E0(0x0010)(Edit, BlueprintVisible)
	class UW_Grid_ActionList_C*                   REF_Action_List;                                   // 0x02F0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Fireteam_ID;                                       // 0x02F8(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	int32                                         Squad_ID;                                          // 0x02FC(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	class USQMapMarkerDataAsset*                  MapMarkerData;                                     // 0x0300(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_W_GridButton(int32 EntryPoint);
	void Grid_Button_Pressed();
	void BndEvt__Button_Main_K2Node_ComponentBoundEvent_0_OnButtonHoverEvent__DelegateSignature();
	void BndEvt__Button_Main_K2Node_ComponentBoundEvent_20_OnButtonClickedEvent__DelegateSignature();
	void PreConstruct(bool IsDesignTime);
	void Update_Appearance();
	void Show_Actions();
	void Close_Actions();
	class UWidget* Get_Button_Main_ToolTipWidget_0();
	void Get_Fireteam_ID(int32* ID);
	void Draw_List();
	void Get_Color(struct FLinearColor* Param_Icon_Color);
	void Get_Squad_ID(int32* ID);
	void Get_Text(class FText* Text);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_GridButton_C">();
	}
	static class UW_GridButton_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_GridButton_C>();
	}
};
static_assert(alignof(UW_GridButton_C) == 0x000008, "Wrong alignment on UW_GridButton_C");
static_assert(sizeof(UW_GridButton_C) == 0x000308, "Wrong size on UW_GridButton_C");
static_assert(offsetof(UW_GridButton_C, UberGraphFrame) == 0x000260, "Member 'UW_GridButton_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_GridButton_C, Button_Main) == 0x000268, "Member 'UW_GridButton_C::Button_Main' has a wrong offset!");
static_assert(offsetof(UW_GridButton_C, Icon) == 0x000270, "Member 'UW_GridButton_C::Icon' has a wrong offset!");
static_assert(offsetof(UW_GridButton_C, Switch_IconText) == 0x000278, "Member 'UW_GridButton_C::Switch_IconText' has a wrong offset!");
static_assert(offsetof(UW_GridButton_C, TB_ID) == 0x000280, "Member 'UW_GridButton_C::TB_ID' has a wrong offset!");
static_assert(offsetof(UW_GridButton_C, Parent_Draw_Direction) == 0x000288, "Member 'UW_GridButton_C::Parent_Draw_Direction' has a wrong offset!");
static_assert(offsetof(UW_GridButton_C, Build_Direction) == 0x000289, "Member 'UW_GridButton_C::Build_Direction' has a wrong offset!");
static_assert(offsetof(UW_GridButton_C, Button_Icon) == 0x000290, "Member 'UW_GridButton_C::Button_Icon' has a wrong offset!");
static_assert(offsetof(UW_GridButton_C, Icon_Color) == 0x000298, "Member 'UW_GridButton_C::Icon_Color' has a wrong offset!");
static_assert(offsetof(UW_GridButton_C, Header_Parent) == 0x0002A8, "Member 'UW_GridButton_C::Header_Parent' has a wrong offset!");
static_assert(offsetof(UW_GridButton_C, Parent_Button) == 0x0002B0, "Member 'UW_GridButton_C::Parent_Button' has a wrong offset!");
static_assert(offsetof(UW_GridButton_C, Actions_Visible) == 0x0002B1, "Member 'UW_GridButton_C::Actions_Visible' has a wrong offset!");
static_assert(offsetof(UW_GridButton_C, Default_Map_Marker) == 0x0002B8, "Member 'UW_GridButton_C::Default_Map_Marker' has a wrong offset!");
static_assert(offsetof(UW_GridButton_C, Action_List_Class) == 0x0002C0, "Member 'UW_GridButton_C::Action_List_Class' has a wrong offset!");
static_assert(offsetof(UW_GridButton_C, Tooltip) == 0x0002C8, "Member 'UW_GridButton_C::Tooltip' has a wrong offset!");
static_assert(offsetof(UW_GridButton_C, Action_List) == 0x0002E0, "Member 'UW_GridButton_C::Action_List' has a wrong offset!");
static_assert(offsetof(UW_GridButton_C, REF_Action_List) == 0x0002F0, "Member 'UW_GridButton_C::REF_Action_List' has a wrong offset!");
static_assert(offsetof(UW_GridButton_C, Fireteam_ID) == 0x0002F8, "Member 'UW_GridButton_C::Fireteam_ID' has a wrong offset!");
static_assert(offsetof(UW_GridButton_C, Squad_ID) == 0x0002FC, "Member 'UW_GridButton_C::Squad_ID' has a wrong offset!");
static_assert(offsetof(UW_GridButton_C, MapMarkerData) == 0x000300, "Member 'UW_GridButton_C::MapMarkerData' has a wrong offset!");

}

