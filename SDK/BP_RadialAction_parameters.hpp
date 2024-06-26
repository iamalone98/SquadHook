#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_RadialAction

#include "Basic.hpp"


namespace SDK::Params
{

// Function BP_RadialAction.BP_RadialAction_C.ExecuteUbergraph_BP_RadialAction
// 0x0010 (0x0010 - 0x0000)
struct BP_RadialAction_C_ExecuteUbergraph_BP_RadialAction final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3EF0[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UBaseRadialMenu_C*                      K2Node_CustomEvent_Raidal_Menu;                    // 0x0008(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_RadialAction_C_ExecuteUbergraph_BP_RadialAction) == 0x000008, "Wrong alignment on BP_RadialAction_C_ExecuteUbergraph_BP_RadialAction");
static_assert(sizeof(BP_RadialAction_C_ExecuteUbergraph_BP_RadialAction) == 0x000010, "Wrong size on BP_RadialAction_C_ExecuteUbergraph_BP_RadialAction");
static_assert(offsetof(BP_RadialAction_C_ExecuteUbergraph_BP_RadialAction, EntryPoint) == 0x000000, "Member 'BP_RadialAction_C_ExecuteUbergraph_BP_RadialAction::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_RadialAction_C_ExecuteUbergraph_BP_RadialAction, K2Node_CustomEvent_Raidal_Menu) == 0x000008, "Member 'BP_RadialAction_C_ExecuteUbergraph_BP_RadialAction::K2Node_CustomEvent_Raidal_Menu' has a wrong offset!");

// Function BP_RadialAction.BP_RadialAction_C.OnClicked
// 0x0008 (0x0008 - 0x0000)
struct BP_RadialAction_C_OnClicked final
{
public:
	class UBaseRadialMenu_C*                      Raidal_Menu;                                       // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_RadialAction_C_OnClicked) == 0x000008, "Wrong alignment on BP_RadialAction_C_OnClicked");
static_assert(sizeof(BP_RadialAction_C_OnClicked) == 0x000008, "Wrong size on BP_RadialAction_C_OnClicked");
static_assert(offsetof(BP_RadialAction_C_OnClicked, Raidal_Menu) == 0x000000, "Member 'BP_RadialAction_C_OnClicked::Raidal_Menu' has a wrong offset!");

// Function BP_RadialAction.BP_RadialAction_C.CanClick
// 0x0018 (0x0018 - 0x0000)
struct BP_RadialAction_C_CanClick final
{
public:
	class APlayerController*                      Controller;                                        // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_RadialItemModel_C*                  Model;                                             // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Param_CanClick;                                    // 0x0010(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0011(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsInVehicle_IsInVehicle;                  // 0x0012(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Not_PreBool_ReturnValue;                  // 0x0013(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_RadialAction_C_CanClick) == 0x000008, "Wrong alignment on BP_RadialAction_C_CanClick");
static_assert(sizeof(BP_RadialAction_C_CanClick) == 0x000018, "Wrong size on BP_RadialAction_C_CanClick");
static_assert(offsetof(BP_RadialAction_C_CanClick, Controller) == 0x000000, "Member 'BP_RadialAction_C_CanClick::Controller' has a wrong offset!");
static_assert(offsetof(BP_RadialAction_C_CanClick, Model) == 0x000008, "Member 'BP_RadialAction_C_CanClick::Model' has a wrong offset!");
static_assert(offsetof(BP_RadialAction_C_CanClick, Param_CanClick) == 0x000010, "Member 'BP_RadialAction_C_CanClick::Param_CanClick' has a wrong offset!");
static_assert(offsetof(BP_RadialAction_C_CanClick, CallFunc_IsValid_ReturnValue) == 0x000011, "Member 'BP_RadialAction_C_CanClick::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RadialAction_C_CanClick, CallFunc_IsInVehicle_IsInVehicle) == 0x000012, "Member 'BP_RadialAction_C_CanClick::CallFunc_IsInVehicle_IsInVehicle' has a wrong offset!");
static_assert(offsetof(BP_RadialAction_C_CanClick, CallFunc_Not_PreBool_ReturnValue) == 0x000013, "Member 'BP_RadialAction_C_CanClick::CallFunc_Not_PreBool_ReturnValue' has a wrong offset!");

// Function BP_RadialAction.BP_RadialAction_C.IsInVehicle
// 0x0038 (0x0038 - 0x0000)
struct BP_RadialAction_C_IsInVehicle final
{
public:
	class AController*                            Controller;                                        // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Param_IsInVehicle;                                 // 0x0008(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0009(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3EF1[0x6];                                     // 0x000A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQPlayerState*                         K2Node_DynamicCast_AsSQPlayer_State;               // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3EF2[0x7];                                     // 0x0019(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQSoldier*                             CallFunc_GetSoldier_ReturnValue;                   // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQVehicle*                             CallFunc_GetCurrentVehicle_ReturnValue;            // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_2;                    // 0x0031(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_RadialAction_C_IsInVehicle) == 0x000008, "Wrong alignment on BP_RadialAction_C_IsInVehicle");
static_assert(sizeof(BP_RadialAction_C_IsInVehicle) == 0x000038, "Wrong size on BP_RadialAction_C_IsInVehicle");
static_assert(offsetof(BP_RadialAction_C_IsInVehicle, Controller) == 0x000000, "Member 'BP_RadialAction_C_IsInVehicle::Controller' has a wrong offset!");
static_assert(offsetof(BP_RadialAction_C_IsInVehicle, Param_IsInVehicle) == 0x000008, "Member 'BP_RadialAction_C_IsInVehicle::Param_IsInVehicle' has a wrong offset!");
static_assert(offsetof(BP_RadialAction_C_IsInVehicle, CallFunc_IsValid_ReturnValue) == 0x000009, "Member 'BP_RadialAction_C_IsInVehicle::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RadialAction_C_IsInVehicle, K2Node_DynamicCast_AsSQPlayer_State) == 0x000010, "Member 'BP_RadialAction_C_IsInVehicle::K2Node_DynamicCast_AsSQPlayer_State' has a wrong offset!");
static_assert(offsetof(BP_RadialAction_C_IsInVehicle, K2Node_DynamicCast_bSuccess) == 0x000018, "Member 'BP_RadialAction_C_IsInVehicle::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_RadialAction_C_IsInVehicle, CallFunc_GetSoldier_ReturnValue) == 0x000020, "Member 'BP_RadialAction_C_IsInVehicle::CallFunc_GetSoldier_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RadialAction_C_IsInVehicle, CallFunc_GetCurrentVehicle_ReturnValue) == 0x000028, "Member 'BP_RadialAction_C_IsInVehicle::CallFunc_GetCurrentVehicle_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RadialAction_C_IsInVehicle, CallFunc_IsValid_ReturnValue_1) == 0x000030, "Member 'BP_RadialAction_C_IsInVehicle::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_RadialAction_C_IsInVehicle, CallFunc_IsValid_ReturnValue_2) == 0x000031, "Member 'BP_RadialAction_C_IsInVehicle::CallFunc_IsValid_ReturnValue_2' has a wrong offset!");

}

