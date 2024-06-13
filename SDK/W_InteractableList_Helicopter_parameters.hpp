#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_InteractableList_Helicopter

#include "Basic.hpp"

#include "Squad_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "SlateCore_structs.hpp"


namespace SDK::Params
{

// Function W_InteractableList_Helicopter.W_InteractableList_Helicopter_C.ExecuteUbergraph_W_InteractableList_Helicopter
// 0x00A0 (0x00A0 - 0x0000)
struct W_InteractableList_Helicopter_C_ExecuteUbergraph_W_InteractableList_Helicopter final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4124[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	TScriptInterface<class ISQUsable>             K2Node_DynamicCast_AsSQUsable;                     // 0x0008(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0019(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4125[0x6];                                     // 0x001A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSQUsableData                          CallFunc_GetUsableData_ReturnValue;                // 0x0020(0x0040)()
	bool                                          CallFunc_Check_for_Repair_Kit_bSuccess;            // 0x0060(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_Event_Force;                                // 0x0061(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4126[0x2];                                     // 0x0062(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x0064(0x0038)(IsPlainOldData, NoDestructor)
	float                                         K2Node_Event_InDeltaTime;                          // 0x009C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_InteractableList_Helicopter_C_ExecuteUbergraph_W_InteractableList_Helicopter) == 0x000008, "Wrong alignment on W_InteractableList_Helicopter_C_ExecuteUbergraph_W_InteractableList_Helicopter");
static_assert(sizeof(W_InteractableList_Helicopter_C_ExecuteUbergraph_W_InteractableList_Helicopter) == 0x0000A0, "Wrong size on W_InteractableList_Helicopter_C_ExecuteUbergraph_W_InteractableList_Helicopter");
static_assert(offsetof(W_InteractableList_Helicopter_C_ExecuteUbergraph_W_InteractableList_Helicopter, EntryPoint) == 0x000000, "Member 'W_InteractableList_Helicopter_C_ExecuteUbergraph_W_InteractableList_Helicopter::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_ExecuteUbergraph_W_InteractableList_Helicopter, K2Node_DynamicCast_AsSQUsable) == 0x000008, "Member 'W_InteractableList_Helicopter_C_ExecuteUbergraph_W_InteractableList_Helicopter::K2Node_DynamicCast_AsSQUsable' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_ExecuteUbergraph_W_InteractableList_Helicopter, K2Node_DynamicCast_bSuccess) == 0x000018, "Member 'W_InteractableList_Helicopter_C_ExecuteUbergraph_W_InteractableList_Helicopter::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_ExecuteUbergraph_W_InteractableList_Helicopter, CallFunc_IsValid_ReturnValue) == 0x000019, "Member 'W_InteractableList_Helicopter_C_ExecuteUbergraph_W_InteractableList_Helicopter::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_ExecuteUbergraph_W_InteractableList_Helicopter, CallFunc_GetUsableData_ReturnValue) == 0x000020, "Member 'W_InteractableList_Helicopter_C_ExecuteUbergraph_W_InteractableList_Helicopter::CallFunc_GetUsableData_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_ExecuteUbergraph_W_InteractableList_Helicopter, CallFunc_Check_for_Repair_Kit_bSuccess) == 0x000060, "Member 'W_InteractableList_Helicopter_C_ExecuteUbergraph_W_InteractableList_Helicopter::CallFunc_Check_for_Repair_Kit_bSuccess' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_ExecuteUbergraph_W_InteractableList_Helicopter, K2Node_Event_Force) == 0x000061, "Member 'W_InteractableList_Helicopter_C_ExecuteUbergraph_W_InteractableList_Helicopter::K2Node_Event_Force' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_ExecuteUbergraph_W_InteractableList_Helicopter, K2Node_Event_MyGeometry) == 0x000064, "Member 'W_InteractableList_Helicopter_C_ExecuteUbergraph_W_InteractableList_Helicopter::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_ExecuteUbergraph_W_InteractableList_Helicopter, K2Node_Event_InDeltaTime) == 0x00009C, "Member 'W_InteractableList_Helicopter_C_ExecuteUbergraph_W_InteractableList_Helicopter::K2Node_Event_InDeltaTime' has a wrong offset!");

// Function W_InteractableList_Helicopter.W_InteractableList_Helicopter_C.Tick
// 0x003C (0x003C - 0x0000)
struct W_InteractableList_Helicopter_C_Tick final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	float                                         InDeltaTime;                                       // 0x0038(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_InteractableList_Helicopter_C_Tick) == 0x000004, "Wrong alignment on W_InteractableList_Helicopter_C_Tick");
static_assert(sizeof(W_InteractableList_Helicopter_C_Tick) == 0x00003C, "Wrong size on W_InteractableList_Helicopter_C_Tick");
static_assert(offsetof(W_InteractableList_Helicopter_C_Tick, MyGeometry) == 0x000000, "Member 'W_InteractableList_Helicopter_C_Tick::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_Tick, InDeltaTime) == 0x000038, "Member 'W_InteractableList_Helicopter_C_Tick::InDeltaTime' has a wrong offset!");

// Function W_InteractableList_Helicopter.W_InteractableList_Helicopter_C.Create Interaction Items
// 0x0001 (0x0001 - 0x0000)
struct W_InteractableList_Helicopter_C_Create_Interaction_Items final
{
public:
	bool                                          Force;                                             // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_InteractableList_Helicopter_C_Create_Interaction_Items) == 0x000001, "Wrong alignment on W_InteractableList_Helicopter_C_Create_Interaction_Items");
static_assert(sizeof(W_InteractableList_Helicopter_C_Create_Interaction_Items) == 0x000001, "Wrong size on W_InteractableList_Helicopter_C_Create_Interaction_Items");
static_assert(offsetof(W_InteractableList_Helicopter_C_Create_Interaction_Items, Force) == 0x000000, "Member 'W_InteractableList_Helicopter_C_Create_Interaction_Items::Force' has a wrong offset!");

// Function W_InteractableList_Helicopter.W_InteractableList_Helicopter_C.Update Vehicle Claim
// 0x0058 (0x0058 - 0x0000)
struct W_InteractableList_Helicopter_C_Update_Vehicle_Claim final
{
public:
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0000(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Array_IsValidIndex_ReturnValue;           // 0x0001(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4127[0x6];                                     // 0x0002(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQVehicle*                             K2Node_DynamicCast_AsSQVehicle;                    // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0011(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4128[0x6];                                     // 0x0012(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Conv_IntToText_ReturnValue;               // 0x0018(0x0018)()
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerController*                    K2Node_DynamicCast_AsSQPlayer_Controller;          // 0x0038(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0040(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_2;                    // 0x0041(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_IntInt_ReturnValue;            // 0x0042(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4129[0x1];                                     // 0x0043(0x0001)(Fixing Size After Last Property [ Dumper-7 ])
	struct FLinearColor                           CallFunc_SelectColor_ReturnValue;                  // 0x0044(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_InteractableList_Helicopter_C_Update_Vehicle_Claim) == 0x000008, "Wrong alignment on W_InteractableList_Helicopter_C_Update_Vehicle_Claim");
static_assert(sizeof(W_InteractableList_Helicopter_C_Update_Vehicle_Claim) == 0x000058, "Wrong size on W_InteractableList_Helicopter_C_Update_Vehicle_Claim");
static_assert(offsetof(W_InteractableList_Helicopter_C_Update_Vehicle_Claim, CallFunc_IsValid_ReturnValue) == 0x000000, "Member 'W_InteractableList_Helicopter_C_Update_Vehicle_Claim::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_Update_Vehicle_Claim, CallFunc_Array_IsValidIndex_ReturnValue) == 0x000001, "Member 'W_InteractableList_Helicopter_C_Update_Vehicle_Claim::CallFunc_Array_IsValidIndex_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_Update_Vehicle_Claim, K2Node_DynamicCast_AsSQVehicle) == 0x000008, "Member 'W_InteractableList_Helicopter_C_Update_Vehicle_Claim::K2Node_DynamicCast_AsSQVehicle' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_Update_Vehicle_Claim, K2Node_DynamicCast_bSuccess) == 0x000010, "Member 'W_InteractableList_Helicopter_C_Update_Vehicle_Claim::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_Update_Vehicle_Claim, CallFunc_IsValid_ReturnValue_1) == 0x000011, "Member 'W_InteractableList_Helicopter_C_Update_Vehicle_Claim::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_Update_Vehicle_Claim, CallFunc_Conv_IntToText_ReturnValue) == 0x000018, "Member 'W_InteractableList_Helicopter_C_Update_Vehicle_Claim::CallFunc_Conv_IntToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_Update_Vehicle_Claim, CallFunc_GetOwningPlayer_ReturnValue) == 0x000030, "Member 'W_InteractableList_Helicopter_C_Update_Vehicle_Claim::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_Update_Vehicle_Claim, K2Node_DynamicCast_AsSQPlayer_Controller) == 0x000038, "Member 'W_InteractableList_Helicopter_C_Update_Vehicle_Claim::K2Node_DynamicCast_AsSQPlayer_Controller' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_Update_Vehicle_Claim, K2Node_DynamicCast_bSuccess_1) == 0x000040, "Member 'W_InteractableList_Helicopter_C_Update_Vehicle_Claim::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_Update_Vehicle_Claim, CallFunc_IsValid_ReturnValue_2) == 0x000041, "Member 'W_InteractableList_Helicopter_C_Update_Vehicle_Claim::CallFunc_IsValid_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_Update_Vehicle_Claim, CallFunc_EqualEqual_IntInt_ReturnValue) == 0x000042, "Member 'W_InteractableList_Helicopter_C_Update_Vehicle_Claim::CallFunc_EqualEqual_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_Update_Vehicle_Claim, CallFunc_SelectColor_ReturnValue) == 0x000044, "Member 'W_InteractableList_Helicopter_C_Update_Vehicle_Claim::CallFunc_SelectColor_ReturnValue' has a wrong offset!");

// Function W_InteractableList_Helicopter.W_InteractableList_Helicopter_C.Check for Repair Kit
// 0x0048 (0x0048 - 0x0000)
struct W_InteractableList_Helicopter_C_Check_for_Repair_Kit final
{
public:
	bool                                          bSuccess;                                          // 0x0000(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_412A[0x7];                                     // 0x0001(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQPlayerController*                    CallFunc_GetSquadPlayerController_Return_Value;    // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APawn*                                  CallFunc_K2_GetPawn_ReturnValue;                   // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_412B[0x7];                                     // 0x0019(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQSoldier*                             K2Node_DynamicCast_AsSQSoldier;                    // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0028(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_412C[0x7];                                     // 0x0029(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQEquipableItem*                       CallFunc_GetCurrentWeapon_ReturnValue;             // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQRepairTool*                          K2Node_DynamicCast_AsSQRepair_Tool;                // 0x0038(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0040(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0041(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_InteractableList_Helicopter_C_Check_for_Repair_Kit) == 0x000008, "Wrong alignment on W_InteractableList_Helicopter_C_Check_for_Repair_Kit");
static_assert(sizeof(W_InteractableList_Helicopter_C_Check_for_Repair_Kit) == 0x000048, "Wrong size on W_InteractableList_Helicopter_C_Check_for_Repair_Kit");
static_assert(offsetof(W_InteractableList_Helicopter_C_Check_for_Repair_Kit, bSuccess) == 0x000000, "Member 'W_InteractableList_Helicopter_C_Check_for_Repair_Kit::bSuccess' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_Check_for_Repair_Kit, CallFunc_GetSquadPlayerController_Return_Value) == 0x000008, "Member 'W_InteractableList_Helicopter_C_Check_for_Repair_Kit::CallFunc_GetSquadPlayerController_Return_Value' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_Check_for_Repair_Kit, CallFunc_K2_GetPawn_ReturnValue) == 0x000010, "Member 'W_InteractableList_Helicopter_C_Check_for_Repair_Kit::CallFunc_K2_GetPawn_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_Check_for_Repair_Kit, CallFunc_IsValid_ReturnValue) == 0x000018, "Member 'W_InteractableList_Helicopter_C_Check_for_Repair_Kit::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_Check_for_Repair_Kit, K2Node_DynamicCast_AsSQSoldier) == 0x000020, "Member 'W_InteractableList_Helicopter_C_Check_for_Repair_Kit::K2Node_DynamicCast_AsSQSoldier' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_Check_for_Repair_Kit, K2Node_DynamicCast_bSuccess) == 0x000028, "Member 'W_InteractableList_Helicopter_C_Check_for_Repair_Kit::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_Check_for_Repair_Kit, CallFunc_GetCurrentWeapon_ReturnValue) == 0x000030, "Member 'W_InteractableList_Helicopter_C_Check_for_Repair_Kit::CallFunc_GetCurrentWeapon_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_Check_for_Repair_Kit, K2Node_DynamicCast_AsSQRepair_Tool) == 0x000038, "Member 'W_InteractableList_Helicopter_C_Check_for_Repair_Kit::K2Node_DynamicCast_AsSQRepair_Tool' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_Check_for_Repair_Kit, K2Node_DynamicCast_bSuccess_1) == 0x000040, "Member 'W_InteractableList_Helicopter_C_Check_for_Repair_Kit::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_Check_for_Repair_Kit, CallFunc_IsValid_ReturnValue_1) == 0x000041, "Member 'W_InteractableList_Helicopter_C_Check_for_Repair_Kit::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");

// Function W_InteractableList_Helicopter.W_InteractableList_Helicopter_C.Get Interact List
// 0x0008 (0x0008 - 0x0000)
struct W_InteractableList_Helicopter_C_Get_Interact_List final
{
public:
	class UVerticalBox*                           Param_InteractList;                                // 0x0000(0x0008)(Parm, OutParm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_InteractableList_Helicopter_C_Get_Interact_List) == 0x000008, "Wrong alignment on W_InteractableList_Helicopter_C_Get_Interact_List");
static_assert(sizeof(W_InteractableList_Helicopter_C_Get_Interact_List) == 0x000008, "Wrong size on W_InteractableList_Helicopter_C_Get_Interact_List");
static_assert(offsetof(W_InteractableList_Helicopter_C_Get_Interact_List, Param_InteractList) == 0x000000, "Member 'W_InteractableList_Helicopter_C_Get_Interact_List::Param_InteractList' has a wrong offset!");

// Function W_InteractableList_Helicopter.W_InteractableList_Helicopter_C.Get Fade Animation
// 0x0008 (0x0008 - 0x0000)
struct W_InteractableList_Helicopter_C_Get_Fade_Animation final
{
public:
	class UWidgetAnimation*                       Fade_Animation;                                    // 0x0000(0x0008)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_InteractableList_Helicopter_C_Get_Fade_Animation) == 0x000008, "Wrong alignment on W_InteractableList_Helicopter_C_Get_Fade_Animation");
static_assert(sizeof(W_InteractableList_Helicopter_C_Get_Fade_Animation) == 0x000008, "Wrong size on W_InteractableList_Helicopter_C_Get_Fade_Animation");
static_assert(offsetof(W_InteractableList_Helicopter_C_Get_Fade_Animation, Fade_Animation) == 0x000000, "Member 'W_InteractableList_Helicopter_C_Get_Fade_Animation::Fade_Animation' has a wrong offset!");

// Function W_InteractableList_Helicopter.W_InteractableList_Helicopter_C.Get Original Offset
// 0x0058 (0x0058 - 0x0000)
struct W_InteractableList_Helicopter_C_Get_Original_Offset final
{
public:
	TScriptInterface<class ISQUsable>             K2Node_DynamicCast_AsSQUsable;                     // 0x0000(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_412D[0x7];                                     // 0x0011(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSQUsableData                          CallFunc_GetUsableData_ReturnValue;                // 0x0018(0x0040)()
};
static_assert(alignof(W_InteractableList_Helicopter_C_Get_Original_Offset) == 0x000008, "Wrong alignment on W_InteractableList_Helicopter_C_Get_Original_Offset");
static_assert(sizeof(W_InteractableList_Helicopter_C_Get_Original_Offset) == 0x000058, "Wrong size on W_InteractableList_Helicopter_C_Get_Original_Offset");
static_assert(offsetof(W_InteractableList_Helicopter_C_Get_Original_Offset, K2Node_DynamicCast_AsSQUsable) == 0x000000, "Member 'W_InteractableList_Helicopter_C_Get_Original_Offset::K2Node_DynamicCast_AsSQUsable' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_Get_Original_Offset, K2Node_DynamicCast_bSuccess) == 0x000010, "Member 'W_InteractableList_Helicopter_C_Get_Original_Offset::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Helicopter_C_Get_Original_Offset, CallFunc_GetUsableData_ReturnValue) == 0x000018, "Member 'W_InteractableList_Helicopter_C_Get_Original_Offset::CallFunc_GetUsableData_ReturnValue' has a wrong offset!");

}
