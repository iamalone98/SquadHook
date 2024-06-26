#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_PickupRallyPointAction

#include "Basic.hpp"


namespace SDK::Params
{

// Function BP_PickupRallyPointAction.BP_PickupRallyPointAction_C.ExecuteUbergraph_BP_PickupRallyPointAction
// 0x0090 (0x0090 - 0x0000)
struct BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3EF3[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      K2Node_Event_Player_2;                             // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_Event_Can_Pickup;                           // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3EF4[0x7];                                     // 0x0011(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      K2Node_Event_Player_1;                             // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      K2Node_Event_Player;                               // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBaseRadialMenu_C*                      K2Node_Event_Raidal_Menu;                          // 0x0028(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AHUD*                                   CallFunc_GetHUD_ReturnValue;                       // 0x0038(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APawn*                                  CallFunc_K2_GetPawn_ReturnValue;                   // 0x0040(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TScriptInterface<class IBPI_HUD_C>            K2Node_DynamicCast_AsBPI_HUD;                      // 0x0048(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0058(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3EF5[0x7];                                     // 0x0059(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQSoldier*                             K2Node_DynamicCast_AsSQSoldier;                    // 0x0060(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0068(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3EF6[0x7];                                     // 0x0069(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UBaseRadialMenu_C*                      CallFunc_Get_Radial_Menu_Radial_Menu;              // 0x0070(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TScriptInterface<class IBPI_Items_C>          K2Node_DynamicCast_AsBPI_Items;                    // 0x0078(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_DynamicCast_bSuccess_2;                     // 0x0088(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0089(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction) == 0x000008, "Wrong alignment on BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction");
static_assert(sizeof(BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction) == 0x000090, "Wrong size on BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction");
static_assert(offsetof(BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction, EntryPoint) == 0x000000, "Member 'BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction, K2Node_Event_Player_2) == 0x000008, "Member 'BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction::K2Node_Event_Player_2' has a wrong offset!");
static_assert(offsetof(BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction, K2Node_Event_Can_Pickup) == 0x000010, "Member 'BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction::K2Node_Event_Can_Pickup' has a wrong offset!");
static_assert(offsetof(BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction, K2Node_Event_Player_1) == 0x000018, "Member 'BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction::K2Node_Event_Player_1' has a wrong offset!");
static_assert(offsetof(BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction, K2Node_Event_Player) == 0x000020, "Member 'BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction::K2Node_Event_Player' has a wrong offset!");
static_assert(offsetof(BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction, K2Node_Event_Raidal_Menu) == 0x000028, "Member 'BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction::K2Node_Event_Raidal_Menu' has a wrong offset!");
static_assert(offsetof(BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction, CallFunc_GetOwningPlayer_ReturnValue) == 0x000030, "Member 'BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction, CallFunc_GetHUD_ReturnValue) == 0x000038, "Member 'BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction::CallFunc_GetHUD_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction, CallFunc_K2_GetPawn_ReturnValue) == 0x000040, "Member 'BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction::CallFunc_K2_GetPawn_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction, K2Node_DynamicCast_AsBPI_HUD) == 0x000048, "Member 'BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction::K2Node_DynamicCast_AsBPI_HUD' has a wrong offset!");
static_assert(offsetof(BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction, K2Node_DynamicCast_bSuccess) == 0x000058, "Member 'BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction, K2Node_DynamicCast_AsSQSoldier) == 0x000060, "Member 'BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction::K2Node_DynamicCast_AsSQSoldier' has a wrong offset!");
static_assert(offsetof(BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction, K2Node_DynamicCast_bSuccess_1) == 0x000068, "Member 'BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction, CallFunc_Get_Radial_Menu_Radial_Menu) == 0x000070, "Member 'BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction::CallFunc_Get_Radial_Menu_Radial_Menu' has a wrong offset!");
static_assert(offsetof(BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction, K2Node_DynamicCast_AsBPI_Items) == 0x000078, "Member 'BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction::K2Node_DynamicCast_AsBPI_Items' has a wrong offset!");
static_assert(offsetof(BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction, K2Node_DynamicCast_bSuccess_2) == 0x000088, "Member 'BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction::K2Node_DynamicCast_bSuccess_2' has a wrong offset!");
static_assert(offsetof(BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction, CallFunc_IsValid_ReturnValue) == 0x000089, "Member 'BP_PickupRallyPointAction_C_ExecuteUbergraph_BP_PickupRallyPointAction::CallFunc_IsValid_ReturnValue' has a wrong offset!");

// Function BP_PickupRallyPointAction.BP_PickupRallyPointAction_C.OnClicked
// 0x0008 (0x0008 - 0x0000)
struct BP_PickupRallyPointAction_C_OnClicked final
{
public:
	class UBaseRadialMenu_C*                      Raidal_Menu;                                       // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_PickupRallyPointAction_C_OnClicked) == 0x000008, "Wrong alignment on BP_PickupRallyPointAction_C_OnClicked");
static_assert(sizeof(BP_PickupRallyPointAction_C_OnClicked) == 0x000008, "Wrong size on BP_PickupRallyPointAction_C_OnClicked");
static_assert(offsetof(BP_PickupRallyPointAction_C_OnClicked, Raidal_Menu) == 0x000000, "Member 'BP_PickupRallyPointAction_C_OnClicked::Raidal_Menu' has a wrong offset!");

// Function BP_PickupRallyPointAction.BP_PickupRallyPointAction_C.Pickup Item
// 0x0008 (0x0008 - 0x0000)
struct BP_PickupRallyPointAction_C_Pickup_Item final
{
public:
	class APlayerController*                      Player;                                            // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_PickupRallyPointAction_C_Pickup_Item) == 0x000008, "Wrong alignment on BP_PickupRallyPointAction_C_Pickup_Item");
static_assert(sizeof(BP_PickupRallyPointAction_C_Pickup_Item) == 0x000008, "Wrong size on BP_PickupRallyPointAction_C_Pickup_Item");
static_assert(offsetof(BP_PickupRallyPointAction_C_Pickup_Item, Player) == 0x000000, "Member 'BP_PickupRallyPointAction_C_Pickup_Item::Player' has a wrong offset!");

// Function BP_PickupRallyPointAction.BP_PickupRallyPointAction_C.Player Left Radius
// 0x0008 (0x0008 - 0x0000)
struct BP_PickupRallyPointAction_C_Player_Left_Radius final
{
public:
	class APlayerController*                      Player;                                            // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_PickupRallyPointAction_C_Player_Left_Radius) == 0x000008, "Wrong alignment on BP_PickupRallyPointAction_C_Player_Left_Radius");
static_assert(sizeof(BP_PickupRallyPointAction_C_Player_Left_Radius) == 0x000008, "Wrong size on BP_PickupRallyPointAction_C_Player_Left_Radius");
static_assert(offsetof(BP_PickupRallyPointAction_C_Player_Left_Radius, Player) == 0x000000, "Member 'BP_PickupRallyPointAction_C_Player_Left_Radius::Player' has a wrong offset!");

// Function BP_PickupRallyPointAction.BP_PickupRallyPointAction_C.Player Enter Radius
// 0x0010 (0x0010 - 0x0000)
struct BP_PickupRallyPointAction_C_Player_Enter_Radius final
{
public:
	class APlayerController*                      Player;                                            // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Can_Pickup;                                        // 0x0008(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_PickupRallyPointAction_C_Player_Enter_Radius) == 0x000008, "Wrong alignment on BP_PickupRallyPointAction_C_Player_Enter_Radius");
static_assert(sizeof(BP_PickupRallyPointAction_C_Player_Enter_Radius) == 0x000010, "Wrong size on BP_PickupRallyPointAction_C_Player_Enter_Radius");
static_assert(offsetof(BP_PickupRallyPointAction_C_Player_Enter_Radius, Player) == 0x000000, "Member 'BP_PickupRallyPointAction_C_Player_Enter_Radius::Player' has a wrong offset!");
static_assert(offsetof(BP_PickupRallyPointAction_C_Player_Enter_Radius, Can_Pickup) == 0x000008, "Member 'BP_PickupRallyPointAction_C_Player_Enter_Radius::Can_Pickup' has a wrong offset!");

}

