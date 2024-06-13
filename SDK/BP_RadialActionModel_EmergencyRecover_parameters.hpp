#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_RadialActionModel_EmergencyRecover

#include "Basic.hpp"

#include "Squad_structs.hpp"
#include "CoreUObject_structs.hpp"


namespace SDK::Params
{

// Function BP_RadialActionModel_EmergencyRecover.BP_RadialActionModel_EmergencyRecover_C.ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover
// 0x0058 (0x0058 - 0x0000)
struct BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2C28[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQHelicopter2*                         K2Node_DynamicCast_AsSQHelicopter_2;               // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2C29[0x7];                                     // 0x0011(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UBaseRadialMenu_C*                      K2Node_Event_Radial;                               // 0x0018(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQRadialButton*                        K2Node_Event_Widget;                               // 0x0020(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBaseRadialMenu_C*                      K2Node_Event_Menu;                                 // 0x0028(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UObject*                                K2Node_Event_Context;                              // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQVehicle*                             K2Node_DynamicCast_AsSQVehicle;                    // 0x0038(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0040(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2C2A[0x7];                                     // 0x0041(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_RadialTowingWidget_C*                K2Node_DynamicCast_AsW_Radial_Towing_Widget;       // 0x0048(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_2;                     // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover) == 0x000008, "Wrong alignment on BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover");
static_assert(sizeof(BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover) == 0x000058, "Wrong size on BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover, EntryPoint) == 0x000000, "Member 'BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover, K2Node_DynamicCast_AsSQHelicopter_2) == 0x000008, "Member 'BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover::K2Node_DynamicCast_AsSQHelicopter_2' has a wrong offset!");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover, K2Node_DynamicCast_bSuccess) == 0x000010, "Member 'BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover, K2Node_Event_Radial) == 0x000018, "Member 'BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover::K2Node_Event_Radial' has a wrong offset!");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover, K2Node_Event_Widget) == 0x000020, "Member 'BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover::K2Node_Event_Widget' has a wrong offset!");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover, K2Node_Event_Menu) == 0x000028, "Member 'BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover::K2Node_Event_Menu' has a wrong offset!");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover, K2Node_Event_Context) == 0x000030, "Member 'BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover::K2Node_Event_Context' has a wrong offset!");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover, K2Node_DynamicCast_AsSQVehicle) == 0x000038, "Member 'BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover::K2Node_DynamicCast_AsSQVehicle' has a wrong offset!");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover, K2Node_DynamicCast_bSuccess_1) == 0x000040, "Member 'BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover, K2Node_DynamicCast_AsW_Radial_Towing_Widget) == 0x000048, "Member 'BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover::K2Node_DynamicCast_AsW_Radial_Towing_Widget' has a wrong offset!");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover, K2Node_DynamicCast_bSuccess_2) == 0x000050, "Member 'BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover::K2Node_DynamicCast_bSuccess_2' has a wrong offset!");

// Function BP_RadialActionModel_EmergencyRecover.BP_RadialActionModel_EmergencyRecover_C.OnClicked
// 0x0008 (0x0008 - 0x0000)
struct BP_RadialActionModel_EmergencyRecover_C_OnClicked final
{
public:
	class UBaseRadialMenu_C*                      Radial;                                            // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_RadialActionModel_EmergencyRecover_C_OnClicked) == 0x000008, "Wrong alignment on BP_RadialActionModel_EmergencyRecover_C_OnClicked");
static_assert(sizeof(BP_RadialActionModel_EmergencyRecover_C_OnClicked) == 0x000008, "Wrong size on BP_RadialActionModel_EmergencyRecover_C_OnClicked");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_OnClicked, Radial) == 0x000000, "Member 'BP_RadialActionModel_EmergencyRecover_C_OnClicked::Radial' has a wrong offset!");

// Function BP_RadialActionModel_EmergencyRecover.BP_RadialActionModel_EmergencyRecover_C.Populate
// 0x0018 (0x0018 - 0x0000)
struct BP_RadialActionModel_EmergencyRecover_C_Populate final
{
public:
	class USQRadialButton*                        Param_Widget;                                      // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBaseRadialMenu_C*                      Menu;                                              // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UObject*                                Context;                                           // 0x0010(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_RadialActionModel_EmergencyRecover_C_Populate) == 0x000008, "Wrong alignment on BP_RadialActionModel_EmergencyRecover_C_Populate");
static_assert(sizeof(BP_RadialActionModel_EmergencyRecover_C_Populate) == 0x000018, "Wrong size on BP_RadialActionModel_EmergencyRecover_C_Populate");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_Populate, Param_Widget) == 0x000000, "Member 'BP_RadialActionModel_EmergencyRecover_C_Populate::Param_Widget' has a wrong offset!");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_Populate, Menu) == 0x000008, "Member 'BP_RadialActionModel_EmergencyRecover_C_Populate::Menu' has a wrong offset!");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_Populate, Context) == 0x000010, "Member 'BP_RadialActionModel_EmergencyRecover_C_Populate::Context' has a wrong offset!");

// Function BP_RadialActionModel_EmergencyRecover.BP_RadialActionModel_EmergencyRecover_C.Update Button
// 0x0080 (0x0080 - 0x0000)
struct BP_RadialActionModel_EmergencyRecover_C_Update_Button final
{
public:
	class USQRadialButton*                        Param_Widget;                                      // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQVehicle*                             Param_Vehicle;                                     // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQVehicleEmergencyRecoveryComponent*   CallFunc_GetEmergencyRecoveryComponent_ReturnValue; // 0x0010(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TSet<ESQVehicleRecoveryMethod>                CallFunc_Get_Correct_Recovery_Methods_RecoveryMethodsAvailable; // 0x0018(0x0050)()
	bool                                          CallFunc_CanUseEmergencyRecovery_ReturnValue;      // 0x0068(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2C2B[0x3];                                     // 0x0069(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FLinearColor                           CallFunc_SelectColor_ReturnValue;                  // 0x006C(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Set_Contains_ReturnValue;                 // 0x007C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_RadialActionModel_EmergencyRecover_C_Update_Button) == 0x000008, "Wrong alignment on BP_RadialActionModel_EmergencyRecover_C_Update_Button");
static_assert(sizeof(BP_RadialActionModel_EmergencyRecover_C_Update_Button) == 0x000080, "Wrong size on BP_RadialActionModel_EmergencyRecover_C_Update_Button");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_Update_Button, Param_Widget) == 0x000000, "Member 'BP_RadialActionModel_EmergencyRecover_C_Update_Button::Param_Widget' has a wrong offset!");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_Update_Button, Param_Vehicle) == 0x000008, "Member 'BP_RadialActionModel_EmergencyRecover_C_Update_Button::Param_Vehicle' has a wrong offset!");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_Update_Button, CallFunc_GetEmergencyRecoveryComponent_ReturnValue) == 0x000010, "Member 'BP_RadialActionModel_EmergencyRecover_C_Update_Button::CallFunc_GetEmergencyRecoveryComponent_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_Update_Button, CallFunc_Get_Correct_Recovery_Methods_RecoveryMethodsAvailable) == 0x000018, "Member 'BP_RadialActionModel_EmergencyRecover_C_Update_Button::CallFunc_Get_Correct_Recovery_Methods_RecoveryMethodsAvailable' has a wrong offset!");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_Update_Button, CallFunc_CanUseEmergencyRecovery_ReturnValue) == 0x000068, "Member 'BP_RadialActionModel_EmergencyRecover_C_Update_Button::CallFunc_CanUseEmergencyRecovery_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_Update_Button, CallFunc_SelectColor_ReturnValue) == 0x00006C, "Member 'BP_RadialActionModel_EmergencyRecover_C_Update_Button::CallFunc_SelectColor_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_Update_Button, CallFunc_Set_Contains_ReturnValue) == 0x00007C, "Member 'BP_RadialActionModel_EmergencyRecover_C_Update_Button::CallFunc_Set_Contains_ReturnValue' has a wrong offset!");

// Function BP_RadialActionModel_EmergencyRecover.BP_RadialActionModel_EmergencyRecover_C.Get Correct Recovery Methods
// 0x0068 (0x0068 - 0x0000)
struct BP_RadialActionModel_EmergencyRecover_C_Get_Correct_Recovery_Methods final
{
public:
	class ASQVehicle*                             Param_Vehicle;                                     // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TSet<ESQVehicleRecoveryMethod>                RecoveryMethodsAvailable;                          // 0x0008(0x0050)(Parm, OutParm)
	class USQVehicleEmergencyRecoveryComponent*   CallFunc_GetEmergencyRecoveryComponent_ReturnValue; // 0x0058(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0060(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_RadialActionModel_EmergencyRecover_C_Get_Correct_Recovery_Methods) == 0x000008, "Wrong alignment on BP_RadialActionModel_EmergencyRecover_C_Get_Correct_Recovery_Methods");
static_assert(sizeof(BP_RadialActionModel_EmergencyRecover_C_Get_Correct_Recovery_Methods) == 0x000068, "Wrong size on BP_RadialActionModel_EmergencyRecover_C_Get_Correct_Recovery_Methods");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_Get_Correct_Recovery_Methods, Param_Vehicle) == 0x000000, "Member 'BP_RadialActionModel_EmergencyRecover_C_Get_Correct_Recovery_Methods::Param_Vehicle' has a wrong offset!");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_Get_Correct_Recovery_Methods, RecoveryMethodsAvailable) == 0x000008, "Member 'BP_RadialActionModel_EmergencyRecover_C_Get_Correct_Recovery_Methods::RecoveryMethodsAvailable' has a wrong offset!");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_Get_Correct_Recovery_Methods, CallFunc_GetEmergencyRecoveryComponent_ReturnValue) == 0x000058, "Member 'BP_RadialActionModel_EmergencyRecover_C_Get_Correct_Recovery_Methods::CallFunc_GetEmergencyRecoveryComponent_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RadialActionModel_EmergencyRecover_C_Get_Correct_Recovery_Methods, CallFunc_IsValid_ReturnValue) == 0x000060, "Member 'BP_RadialActionModel_EmergencyRecover_C_Get_Correct_Recovery_Methods::CallFunc_IsValid_ReturnValue' has a wrong offset!");

}
