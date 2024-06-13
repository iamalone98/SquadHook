#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_RoleDetails

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_structs.hpp"
#include "SlateCore_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_RoleDetails.W_RoleDetails_C
// 0x02C8 (0x0528 - 0x0260)
class UW_RoleDetails_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UImage*                                 Bar;                                               // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                Border_Details;                                    // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                Border_Info;                                       // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                BorderPreviewMessage;                              // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UButton*                                Button_MainWeapon;                                 // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UButton*                                Button_Secondary;                                  // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UButton*                                Button_Special;                                    // 0x0298(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_7;                                           // 0x02A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_MainWeapon;                                  // 0x02A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_Secondary;                                   // 0x02B0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_Special;                                     // 0x02B8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             Name_Description;                                  // 0x02C0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             Name_Primary;                                      // 0x02C8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Amount_Primary;                                 // 0x02D0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Amount_Secondary;                               // 0x02D8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Amount_Special;                                 // 0x02E0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Preview;                                        // 0x02E8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TextBlock_Description;                             // 0x02F0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UVerticalBox*                           V_SubRoles;                                        // 0x02F8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UVerticalBox*                           VerticalBox_Backpack;                              // 0x0300(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class ASQEquipableItem*                       Primary;                                           // 0x0308(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQEquipableItem*                       Secondary;                                         // 0x0310(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQEquipableItem*                       Special;                                           // 0x0318(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FSQInventoryData                       Primary_Data;                                      // 0x0320(0x0038)(Edit, BlueprintVisible, DisableEditOnInstance)
	struct FSQInventoryData                       Secondary_Data;                                    // 0x0358(0x0038)(Edit, BlueprintVisible, DisableEditOnInstance)
	struct FSQInventoryData                       Special_Data;                                      // 0x0390(0x0038)(Edit, BlueprintVisible, DisableEditOnInstance)
	bool                                          SubRoles_Open;                                     // 0x03C8(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_47F2[0x7];                                     // 0x03C9(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_RoleSelect_C*                        Role_Select;                                       // 0x03D0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	class ASQPlayerController*                    My_PC;                                             // 0x03D8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Has_Sub_Roles;                                     // 0x03E0(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_47F3[0x7];                                     // 0x03E1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class USQRoleSettings*                        Latest_Role;                                       // 0x03E8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	FMulticastInlineDelegateProperty_             OnSubRoleSelected;                                 // 0x03F0(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	struct FSlateBrush                            WidgetStyleNormal;                                 // 0x0400(0x0088)(Edit, BlueprintVisible, DisableEditOnInstance)
	struct FSlateBrush                            WidgetStyleHovered;                                // 0x0488(0x0088)(Edit, BlueprintVisible, DisableEditOnInstance)
	int32                                         CurrentHighlightedItemIndex;                       // 0x0510(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_47F4[0x4];                                     // 0x0514(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<class ASQEquipableItem*>               AvailableItems;                                    // 0x0518(0x0010)(Edit, BlueprintVisible, DisableEditOnTemplate, DisableEditOnInstance)

public:
	void OnSubRoleSelected__DelegateSignature(class USQRoleSettings* Role_Reference);
	void ExecuteUbergraph_W_RoleDetails(int32 EntryPoint);
	void OnTick(const TArray<struct FSQAvailabilityState_Role>& In_Player_Role_States);
	void Construct();
	void Sub_Role_Hovered(class USQRoleSettings* RoleReference);
	void Sub_Role_Selected(class USQRoleSettings* RoleReference);
	void BndEvt__Button_Special_K2Node_ComponentBoundEvent_2_OnButtonHoverEvent__DelegateSignature();
	void BndEvt__Button_Secondary_K2Node_ComponentBoundEvent_1_OnButtonHoverEvent__DelegateSignature();
	void BndEvt__Button_MainWeapon_K2Node_ComponentBoundEvent_0_OnButtonHoverEvent__DelegateSignature();
	void Update_Details(class USQRoleSettings* RoleReference);
	void Refresh_Description(class ASQEquipableItem* Target);
	void Refresh_Main_Icons();
	void Clear_All();
	void Get_Item_Info(const struct FSQInventoryData& Param_Primary_Data, int32* Item_Count);
	void Set_Preview_Message();
	void Init_Main_Weapon_Button();
	void SelectItem(class ASQEquipableItem* SQEquippableItem);
	void HighlightButton(class UButton* Button, bool bHighlighted);
	struct FEventReply ReceiveMouseWheel(float MouseWheelAxis);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_RoleDetails_C">();
	}
	static class UW_RoleDetails_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_RoleDetails_C>();
	}
};
static_assert(alignof(UW_RoleDetails_C) == 0x000008, "Wrong alignment on UW_RoleDetails_C");
static_assert(sizeof(UW_RoleDetails_C) == 0x000528, "Wrong size on UW_RoleDetails_C");
static_assert(offsetof(UW_RoleDetails_C, UberGraphFrame) == 0x000260, "Member 'UW_RoleDetails_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, Bar) == 0x000268, "Member 'UW_RoleDetails_C::Bar' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, Border_Details) == 0x000270, "Member 'UW_RoleDetails_C::Border_Details' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, Border_Info) == 0x000278, "Member 'UW_RoleDetails_C::Border_Info' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, BorderPreviewMessage) == 0x000280, "Member 'UW_RoleDetails_C::BorderPreviewMessage' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, Button_MainWeapon) == 0x000288, "Member 'UW_RoleDetails_C::Button_MainWeapon' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, Button_Secondary) == 0x000290, "Member 'UW_RoleDetails_C::Button_Secondary' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, Button_Special) == 0x000298, "Member 'UW_RoleDetails_C::Button_Special' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, Image_7) == 0x0002A0, "Member 'UW_RoleDetails_C::Image_7' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, Image_MainWeapon) == 0x0002A8, "Member 'UW_RoleDetails_C::Image_MainWeapon' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, Image_Secondary) == 0x0002B0, "Member 'UW_RoleDetails_C::Image_Secondary' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, Image_Special) == 0x0002B8, "Member 'UW_RoleDetails_C::Image_Special' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, Name_Description) == 0x0002C0, "Member 'UW_RoleDetails_C::Name_Description' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, Name_Primary) == 0x0002C8, "Member 'UW_RoleDetails_C::Name_Primary' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, TB_Amount_Primary) == 0x0002D0, "Member 'UW_RoleDetails_C::TB_Amount_Primary' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, TB_Amount_Secondary) == 0x0002D8, "Member 'UW_RoleDetails_C::TB_Amount_Secondary' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, TB_Amount_Special) == 0x0002E0, "Member 'UW_RoleDetails_C::TB_Amount_Special' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, TB_Preview) == 0x0002E8, "Member 'UW_RoleDetails_C::TB_Preview' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, TextBlock_Description) == 0x0002F0, "Member 'UW_RoleDetails_C::TextBlock_Description' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, V_SubRoles) == 0x0002F8, "Member 'UW_RoleDetails_C::V_SubRoles' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, VerticalBox_Backpack) == 0x000300, "Member 'UW_RoleDetails_C::VerticalBox_Backpack' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, Primary) == 0x000308, "Member 'UW_RoleDetails_C::Primary' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, Secondary) == 0x000310, "Member 'UW_RoleDetails_C::Secondary' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, Special) == 0x000318, "Member 'UW_RoleDetails_C::Special' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, Primary_Data) == 0x000320, "Member 'UW_RoleDetails_C::Primary_Data' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, Secondary_Data) == 0x000358, "Member 'UW_RoleDetails_C::Secondary_Data' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, Special_Data) == 0x000390, "Member 'UW_RoleDetails_C::Special_Data' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, SubRoles_Open) == 0x0003C8, "Member 'UW_RoleDetails_C::SubRoles_Open' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, Role_Select) == 0x0003D0, "Member 'UW_RoleDetails_C::Role_Select' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, My_PC) == 0x0003D8, "Member 'UW_RoleDetails_C::My_PC' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, Has_Sub_Roles) == 0x0003E0, "Member 'UW_RoleDetails_C::Has_Sub_Roles' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, Latest_Role) == 0x0003E8, "Member 'UW_RoleDetails_C::Latest_Role' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, OnSubRoleSelected) == 0x0003F0, "Member 'UW_RoleDetails_C::OnSubRoleSelected' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, WidgetStyleNormal) == 0x000400, "Member 'UW_RoleDetails_C::WidgetStyleNormal' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, WidgetStyleHovered) == 0x000488, "Member 'UW_RoleDetails_C::WidgetStyleHovered' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, CurrentHighlightedItemIndex) == 0x000510, "Member 'UW_RoleDetails_C::CurrentHighlightedItemIndex' has a wrong offset!");
static_assert(offsetof(UW_RoleDetails_C, AvailableItems) == 0x000518, "Member 'UW_RoleDetails_C::AvailableItems' has a wrong offset!");

}

