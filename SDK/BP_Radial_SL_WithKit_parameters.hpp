#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Radial_SL_WithKit

#include "Basic.hpp"

#include "Squad_structs.hpp"
#include "SQDeployableEntry_structs.hpp"


namespace SDK::Params
{

// Function BP_Radial_SL_WithKit.BP_Radial_SL_WithKit_C.ExecuteUbergraph_BP_Radial_SL_WithKit
// 0x0010 (0x0010 - 0x0000)
struct BP_Radial_SL_WithKit_C_ExecuteUbergraph_BP_Radial_SL_WithKit final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_412E[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UBaseRadialMenu_C*                      K2Node_Event_BaseRadialMenu;                       // 0x0008(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_Radial_SL_WithKit_C_ExecuteUbergraph_BP_Radial_SL_WithKit) == 0x000008, "Wrong alignment on BP_Radial_SL_WithKit_C_ExecuteUbergraph_BP_Radial_SL_WithKit");
static_assert(sizeof(BP_Radial_SL_WithKit_C_ExecuteUbergraph_BP_Radial_SL_WithKit) == 0x000010, "Wrong size on BP_Radial_SL_WithKit_C_ExecuteUbergraph_BP_Radial_SL_WithKit");
static_assert(offsetof(BP_Radial_SL_WithKit_C_ExecuteUbergraph_BP_Radial_SL_WithKit, EntryPoint) == 0x000000, "Member 'BP_Radial_SL_WithKit_C_ExecuteUbergraph_BP_Radial_SL_WithKit::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_ExecuteUbergraph_BP_Radial_SL_WithKit, K2Node_Event_BaseRadialMenu) == 0x000008, "Member 'BP_Radial_SL_WithKit_C_ExecuteUbergraph_BP_Radial_SL_WithKit::K2Node_Event_BaseRadialMenu' has a wrong offset!");

// Function BP_Radial_SL_WithKit.BP_Radial_SL_WithKit_C.CreateChildWidgets
// 0x0008 (0x0008 - 0x0000)
struct BP_Radial_SL_WithKit_C_CreateChildWidgets final
{
public:
	class UBaseRadialMenu_C*                      BaseRadialMenu;                                    // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_Radial_SL_WithKit_C_CreateChildWidgets) == 0x000008, "Wrong alignment on BP_Radial_SL_WithKit_C_CreateChildWidgets");
static_assert(sizeof(BP_Radial_SL_WithKit_C_CreateChildWidgets) == 0x000008, "Wrong size on BP_Radial_SL_WithKit_C_CreateChildWidgets");
static_assert(offsetof(BP_Radial_SL_WithKit_C_CreateChildWidgets, BaseRadialMenu) == 0x000000, "Member 'BP_Radial_SL_WithKit_C_CreateChildWidgets::BaseRadialMenu' has a wrong offset!");

// Function BP_Radial_SL_WithKit.BP_Radial_SL_WithKit_C.FindRadioAvailability
// 0x01D8 (0x01D8 - 0x0000)
struct BP_Radial_SL_WithKit_C_FindRadioAvailability final
{
public:
	class APlayerController*                      PlayerController;                                  // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Success;                                           // 0x0008(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_412F[0x7];                                     // 0x0009(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSQAvailabilityState_Deployable        Out_Radio_State;                                   // 0x0010(0x0050)(Parm, OutParm, ContainsInstancedReference)
	struct FSQDeployableEntry                     Out_Radio_Entry;                                   // 0x0060(0x0068)(Parm, OutParm, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable;                     // 0x00C8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4130[0x4];                                     // 0x00CC(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQPlayerController*                    K2Node_DynamicCast_AsSQPlayer_Controller;          // 0x00D0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x00D8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4131[0x3];                                     // 0x00D9(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x00DC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x00E0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4132[0x3];                                     // 0x00E1(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x00E4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TArray<struct FSQAvailabilityState_Deployable> CallFunc_GetDeployables_OutDeployables;            // 0x00E8(0x0010)(ReferenceParm, ContainsInstancedReference)
	bool                                          Temp_bool_True_if_break_was_hit_Variable;          // 0x00F8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4133[0x7];                                     // 0x00F9(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSQAvailabilityState_Deployable        CallFunc_Array_Get_Item;                           // 0x0100(0x0050)(ContainsInstancedReference)
	bool                                          CallFunc_Not_PreBool_ReturnValue;                  // 0x0150(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0151(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4134[0x6];                                     // 0x0152(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_SQDeployableSettings_C*             K2Node_DynamicCast_AsBP_SQDeployable_Settings;     // 0x0158(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0160(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_2;                    // 0x0161(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_GetDeployableEntry_Success;               // 0x0162(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4135[0x5];                                     // 0x0163(0x0005)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSQDeployableEntry                     CallFunc_GetDeployableEntry_DeployableEntry;       // 0x0168(0x0068)(HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x01D0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_EqualEqual_ByteByte_ReturnValue;          // 0x01D4(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x01D5(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue;                   // 0x01D6(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_Radial_SL_WithKit_C_FindRadioAvailability) == 0x000008, "Wrong alignment on BP_Radial_SL_WithKit_C_FindRadioAvailability");
static_assert(sizeof(BP_Radial_SL_WithKit_C_FindRadioAvailability) == 0x0001D8, "Wrong size on BP_Radial_SL_WithKit_C_FindRadioAvailability");
static_assert(offsetof(BP_Radial_SL_WithKit_C_FindRadioAvailability, PlayerController) == 0x000000, "Member 'BP_Radial_SL_WithKit_C_FindRadioAvailability::PlayerController' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_FindRadioAvailability, Success) == 0x000008, "Member 'BP_Radial_SL_WithKit_C_FindRadioAvailability::Success' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_FindRadioAvailability, Out_Radio_State) == 0x000010, "Member 'BP_Radial_SL_WithKit_C_FindRadioAvailability::Out_Radio_State' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_FindRadioAvailability, Out_Radio_Entry) == 0x000060, "Member 'BP_Radial_SL_WithKit_C_FindRadioAvailability::Out_Radio_Entry' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_FindRadioAvailability, Temp_int_Array_Index_Variable) == 0x0000C8, "Member 'BP_Radial_SL_WithKit_C_FindRadioAvailability::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_FindRadioAvailability, K2Node_DynamicCast_AsSQPlayer_Controller) == 0x0000D0, "Member 'BP_Radial_SL_WithKit_C_FindRadioAvailability::K2Node_DynamicCast_AsSQPlayer_Controller' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_FindRadioAvailability, K2Node_DynamicCast_bSuccess) == 0x0000D8, "Member 'BP_Radial_SL_WithKit_C_FindRadioAvailability::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_FindRadioAvailability, Temp_int_Loop_Counter_Variable) == 0x0000DC, "Member 'BP_Radial_SL_WithKit_C_FindRadioAvailability::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_FindRadioAvailability, CallFunc_IsValid_ReturnValue) == 0x0000E0, "Member 'BP_Radial_SL_WithKit_C_FindRadioAvailability::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_FindRadioAvailability, CallFunc_Add_IntInt_ReturnValue) == 0x0000E4, "Member 'BP_Radial_SL_WithKit_C_FindRadioAvailability::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_FindRadioAvailability, CallFunc_GetDeployables_OutDeployables) == 0x0000E8, "Member 'BP_Radial_SL_WithKit_C_FindRadioAvailability::CallFunc_GetDeployables_OutDeployables' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_FindRadioAvailability, Temp_bool_True_if_break_was_hit_Variable) == 0x0000F8, "Member 'BP_Radial_SL_WithKit_C_FindRadioAvailability::Temp_bool_True_if_break_was_hit_Variable' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_FindRadioAvailability, CallFunc_Array_Get_Item) == 0x000100, "Member 'BP_Radial_SL_WithKit_C_FindRadioAvailability::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_FindRadioAvailability, CallFunc_Not_PreBool_ReturnValue) == 0x000150, "Member 'BP_Radial_SL_WithKit_C_FindRadioAvailability::CallFunc_Not_PreBool_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_FindRadioAvailability, CallFunc_IsValid_ReturnValue_1) == 0x000151, "Member 'BP_Radial_SL_WithKit_C_FindRadioAvailability::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_FindRadioAvailability, K2Node_DynamicCast_AsBP_SQDeployable_Settings) == 0x000158, "Member 'BP_Radial_SL_WithKit_C_FindRadioAvailability::K2Node_DynamicCast_AsBP_SQDeployable_Settings' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_FindRadioAvailability, K2Node_DynamicCast_bSuccess_1) == 0x000160, "Member 'BP_Radial_SL_WithKit_C_FindRadioAvailability::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_FindRadioAvailability, CallFunc_IsValid_ReturnValue_2) == 0x000161, "Member 'BP_Radial_SL_WithKit_C_FindRadioAvailability::CallFunc_IsValid_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_FindRadioAvailability, CallFunc_GetDeployableEntry_Success) == 0x000162, "Member 'BP_Radial_SL_WithKit_C_FindRadioAvailability::CallFunc_GetDeployableEntry_Success' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_FindRadioAvailability, CallFunc_GetDeployableEntry_DeployableEntry) == 0x000168, "Member 'BP_Radial_SL_WithKit_C_FindRadioAvailability::CallFunc_GetDeployableEntry_DeployableEntry' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_FindRadioAvailability, CallFunc_Array_Length_ReturnValue) == 0x0001D0, "Member 'BP_Radial_SL_WithKit_C_FindRadioAvailability::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_FindRadioAvailability, CallFunc_EqualEqual_ByteByte_ReturnValue) == 0x0001D4, "Member 'BP_Radial_SL_WithKit_C_FindRadioAvailability::CallFunc_EqualEqual_ByteByte_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_FindRadioAvailability, CallFunc_Less_IntInt_ReturnValue) == 0x0001D5, "Member 'BP_Radial_SL_WithKit_C_FindRadioAvailability::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_FindRadioAvailability, CallFunc_BooleanAND_ReturnValue) == 0x0001D6, "Member 'BP_Radial_SL_WithKit_C_FindRadioAvailability::CallFunc_BooleanAND_ReturnValue' has a wrong offset!");

// Function BP_Radial_SL_WithKit.BP_Radial_SL_WithKit_C.Add Radio Button
// 0x0108 (0x0108 - 0x0000)
struct BP_Radial_SL_WithKit_C_Add_Radio_Button final
{
public:
	class UBaseRadialMenu_C*                      Base_Radial_Menu;                                  // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBPRadialPopulatorIcon_C*               L_Populator;                                       // 0x0008(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_ActionModel_Deployable_C*           L_Deploy_Action_Model;                             // 0x0010(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UObject*                                CallFunc_GetDefaultObjectFor_ReturnValue;          // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_FindRadioAvailability_Success;            // 0x0028(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4136[0x7];                                     // 0x0029(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSQAvailabilityState_Deployable        CallFunc_FindRadioAvailability_Out_Radio_State;    // 0x0030(0x0050)(ContainsInstancedReference)
	struct FSQDeployableEntry                     CallFunc_FindRadioAvailability_Out_Radio_Entry;    // 0x0080(0x0068)(HasGetValueTypeHash)
	class UBP_Populator_Deployable_C*             K2Node_DynamicCast_AsBP_Populator_Deployable;      // 0x00E8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x00F0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4137[0x7];                                     // 0x00F1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_ActionModel_Deployable_C*           CallFunc_SpawnObject_ReturnValue;                  // 0x00F8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQUserWidget*                          CallFunc_CreateRadialChildWidget_CreatedWidget;    // 0x0100(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_Radial_SL_WithKit_C_Add_Radio_Button) == 0x000008, "Wrong alignment on BP_Radial_SL_WithKit_C_Add_Radio_Button");
static_assert(sizeof(BP_Radial_SL_WithKit_C_Add_Radio_Button) == 0x000108, "Wrong size on BP_Radial_SL_WithKit_C_Add_Radio_Button");
static_assert(offsetof(BP_Radial_SL_WithKit_C_Add_Radio_Button, Base_Radial_Menu) == 0x000000, "Member 'BP_Radial_SL_WithKit_C_Add_Radio_Button::Base_Radial_Menu' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_Add_Radio_Button, L_Populator) == 0x000008, "Member 'BP_Radial_SL_WithKit_C_Add_Radio_Button::L_Populator' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_Add_Radio_Button, L_Deploy_Action_Model) == 0x000010, "Member 'BP_Radial_SL_WithKit_C_Add_Radio_Button::L_Deploy_Action_Model' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_Add_Radio_Button, CallFunc_GetOwningPlayer_ReturnValue) == 0x000018, "Member 'BP_Radial_SL_WithKit_C_Add_Radio_Button::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_Add_Radio_Button, CallFunc_GetDefaultObjectFor_ReturnValue) == 0x000020, "Member 'BP_Radial_SL_WithKit_C_Add_Radio_Button::CallFunc_GetDefaultObjectFor_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_Add_Radio_Button, CallFunc_FindRadioAvailability_Success) == 0x000028, "Member 'BP_Radial_SL_WithKit_C_Add_Radio_Button::CallFunc_FindRadioAvailability_Success' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_Add_Radio_Button, CallFunc_FindRadioAvailability_Out_Radio_State) == 0x000030, "Member 'BP_Radial_SL_WithKit_C_Add_Radio_Button::CallFunc_FindRadioAvailability_Out_Radio_State' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_Add_Radio_Button, CallFunc_FindRadioAvailability_Out_Radio_Entry) == 0x000080, "Member 'BP_Radial_SL_WithKit_C_Add_Radio_Button::CallFunc_FindRadioAvailability_Out_Radio_Entry' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_Add_Radio_Button, K2Node_DynamicCast_AsBP_Populator_Deployable) == 0x0000E8, "Member 'BP_Radial_SL_WithKit_C_Add_Radio_Button::K2Node_DynamicCast_AsBP_Populator_Deployable' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_Add_Radio_Button, K2Node_DynamicCast_bSuccess) == 0x0000F0, "Member 'BP_Radial_SL_WithKit_C_Add_Radio_Button::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_Add_Radio_Button, CallFunc_SpawnObject_ReturnValue) == 0x0000F8, "Member 'BP_Radial_SL_WithKit_C_Add_Radio_Button::CallFunc_SpawnObject_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Radial_SL_WithKit_C_Add_Radio_Button, CallFunc_CreateRadialChildWidget_CreatedWidget) == 0x000100, "Member 'BP_Radial_SL_WithKit_C_Add_Radio_Button::CallFunc_CreateRadialChildWidget_CreatedWidget' has a wrong offset!");

}

