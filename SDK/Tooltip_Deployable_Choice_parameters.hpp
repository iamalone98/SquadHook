#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Tooltip_Deployable_Choice

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "SQCostEntry_structs.hpp"
#include "ESQCurrency_structs.hpp"


namespace SDK::Params
{

// Function Tooltip_Deployable_Choice.Tooltip_Deployable_Choice_C.ExecuteUbergraph_Tooltip_Deployable_Choice
// 0x0020 (0x0020 - 0x0000)
struct Tooltip_Deployable_Choice_C_ExecuteUbergraph_Tooltip_Deployable_Choice final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2611[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_RadialItemModel_C*                  K2Node_Event_In_Outer_Context;                     // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_ActionModel_Deployable_C*           K2Node_DynamicCast_AsBP_Action_Model_Deployable;   // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(Tooltip_Deployable_Choice_C_ExecuteUbergraph_Tooltip_Deployable_Choice) == 0x000008, "Wrong alignment on Tooltip_Deployable_Choice_C_ExecuteUbergraph_Tooltip_Deployable_Choice");
static_assert(sizeof(Tooltip_Deployable_Choice_C_ExecuteUbergraph_Tooltip_Deployable_Choice) == 0x000020, "Wrong size on Tooltip_Deployable_Choice_C_ExecuteUbergraph_Tooltip_Deployable_Choice");
static_assert(offsetof(Tooltip_Deployable_Choice_C_ExecuteUbergraph_Tooltip_Deployable_Choice, EntryPoint) == 0x000000, "Member 'Tooltip_Deployable_Choice_C_ExecuteUbergraph_Tooltip_Deployable_Choice::EntryPoint' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_ExecuteUbergraph_Tooltip_Deployable_Choice, K2Node_Event_In_Outer_Context) == 0x000008, "Member 'Tooltip_Deployable_Choice_C_ExecuteUbergraph_Tooltip_Deployable_Choice::K2Node_Event_In_Outer_Context' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_ExecuteUbergraph_Tooltip_Deployable_Choice, K2Node_DynamicCast_AsBP_Action_Model_Deployable) == 0x000010, "Member 'Tooltip_Deployable_Choice_C_ExecuteUbergraph_Tooltip_Deployable_Choice::K2Node_DynamicCast_AsBP_Action_Model_Deployable' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_ExecuteUbergraph_Tooltip_Deployable_Choice, K2Node_DynamicCast_bSuccess) == 0x000018, "Member 'Tooltip_Deployable_Choice_C_ExecuteUbergraph_Tooltip_Deployable_Choice::K2Node_DynamicCast_bSuccess' has a wrong offset!");

// Function Tooltip_Deployable_Choice.Tooltip_Deployable_Choice_C.OnSetContext
// 0x0008 (0x0008 - 0x0000)
struct Tooltip_Deployable_Choice_C_OnSetContext final
{
public:
	class UBP_RadialItemModel_C*                  In_Outer_Context;                                  // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(Tooltip_Deployable_Choice_C_OnSetContext) == 0x000008, "Wrong alignment on Tooltip_Deployable_Choice_C_OnSetContext");
static_assert(sizeof(Tooltip_Deployable_Choice_C_OnSetContext) == 0x000008, "Wrong size on Tooltip_Deployable_Choice_C_OnSetContext");
static_assert(offsetof(Tooltip_Deployable_Choice_C_OnSetContext, In_Outer_Context) == 0x000000, "Member 'Tooltip_Deployable_Choice_C_OnSetContext::In_Outer_Context' has a wrong offset!");

// Function Tooltip_Deployable_Choice.Tooltip_Deployable_Choice_C.UpdateDetails
// 0x01A8 (0x01A8 - 0x0000)
struct Tooltip_Deployable_Choice_C_UpdateDetails final
{
public:
	class FText                                   Details;                                           // 0x0000(0x0018)(BlueprintVisible, BlueprintReadOnly, Parm)
	class FName                                   Key_0;                                             // 0x0018(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   Key_1;                                             // 0x0020(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   Key_2;                                             // 0x0028(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   Key2Name;                                          // 0x0030(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   Key1Name;                                          // 0x0038(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   Key0Name;                                          // 0x0040(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   CallFunc_GetActionKeyName_Name;                    // 0x0048(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_NotEqual_NameName_ReturnValue;            // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2612[0x3];                                     // 0x0051(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class FName                                   CallFunc_GetActionKeyName_Name_1;                  // 0x0054(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_NotEqual_NameName_ReturnValue_1;          // 0x005C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2613[0x3];                                     // 0x005D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class FName                                   CallFunc_GetActionKeyName_Name_2;                  // 0x0060(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_NotEqual_NameName_ReturnValue_2;          // 0x0068(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2614[0x7];                                     // 0x0069(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Conv_NameToText_ReturnValue;              // 0x0070(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData;              // 0x0088(0x0040)(HasGetValueTypeHash)
	class FText                                   CallFunc_Conv_NameToText_ReturnValue_1;            // 0x00C8(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_1;            // 0x00E0(0x0040)(HasGetValueTypeHash)
	class FText                                   CallFunc_Conv_NameToText_ReturnValue_2;            // 0x0120(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_2;            // 0x0138(0x0040)(HasGetValueTypeHash)
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array;                            // 0x0178(0x0010)(ReferenceParm)
	class FText                                   CallFunc_Format_ReturnValue;                       // 0x0188(0x0018)()
	bool                                          CallFunc_TextIsEmpty_ReturnValue;                  // 0x01A0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(Tooltip_Deployable_Choice_C_UpdateDetails) == 0x000008, "Wrong alignment on Tooltip_Deployable_Choice_C_UpdateDetails");
static_assert(sizeof(Tooltip_Deployable_Choice_C_UpdateDetails) == 0x0001A8, "Wrong size on Tooltip_Deployable_Choice_C_UpdateDetails");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDetails, Details) == 0x000000, "Member 'Tooltip_Deployable_Choice_C_UpdateDetails::Details' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDetails, Key_0) == 0x000018, "Member 'Tooltip_Deployable_Choice_C_UpdateDetails::Key_0' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDetails, Key_1) == 0x000020, "Member 'Tooltip_Deployable_Choice_C_UpdateDetails::Key_1' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDetails, Key_2) == 0x000028, "Member 'Tooltip_Deployable_Choice_C_UpdateDetails::Key_2' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDetails, Key2Name) == 0x000030, "Member 'Tooltip_Deployable_Choice_C_UpdateDetails::Key2Name' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDetails, Key1Name) == 0x000038, "Member 'Tooltip_Deployable_Choice_C_UpdateDetails::Key1Name' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDetails, Key0Name) == 0x000040, "Member 'Tooltip_Deployable_Choice_C_UpdateDetails::Key0Name' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDetails, CallFunc_GetActionKeyName_Name) == 0x000048, "Member 'Tooltip_Deployable_Choice_C_UpdateDetails::CallFunc_GetActionKeyName_Name' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDetails, CallFunc_NotEqual_NameName_ReturnValue) == 0x000050, "Member 'Tooltip_Deployable_Choice_C_UpdateDetails::CallFunc_NotEqual_NameName_ReturnValue' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDetails, CallFunc_GetActionKeyName_Name_1) == 0x000054, "Member 'Tooltip_Deployable_Choice_C_UpdateDetails::CallFunc_GetActionKeyName_Name_1' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDetails, CallFunc_NotEqual_NameName_ReturnValue_1) == 0x00005C, "Member 'Tooltip_Deployable_Choice_C_UpdateDetails::CallFunc_NotEqual_NameName_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDetails, CallFunc_GetActionKeyName_Name_2) == 0x000060, "Member 'Tooltip_Deployable_Choice_C_UpdateDetails::CallFunc_GetActionKeyName_Name_2' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDetails, CallFunc_NotEqual_NameName_ReturnValue_2) == 0x000068, "Member 'Tooltip_Deployable_Choice_C_UpdateDetails::CallFunc_NotEqual_NameName_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDetails, CallFunc_Conv_NameToText_ReturnValue) == 0x000070, "Member 'Tooltip_Deployable_Choice_C_UpdateDetails::CallFunc_Conv_NameToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDetails, K2Node_MakeStruct_FormatArgumentData) == 0x000088, "Member 'Tooltip_Deployable_Choice_C_UpdateDetails::K2Node_MakeStruct_FormatArgumentData' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDetails, CallFunc_Conv_NameToText_ReturnValue_1) == 0x0000C8, "Member 'Tooltip_Deployable_Choice_C_UpdateDetails::CallFunc_Conv_NameToText_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDetails, K2Node_MakeStruct_FormatArgumentData_1) == 0x0000E0, "Member 'Tooltip_Deployable_Choice_C_UpdateDetails::K2Node_MakeStruct_FormatArgumentData_1' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDetails, CallFunc_Conv_NameToText_ReturnValue_2) == 0x000120, "Member 'Tooltip_Deployable_Choice_C_UpdateDetails::CallFunc_Conv_NameToText_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDetails, K2Node_MakeStruct_FormatArgumentData_2) == 0x000138, "Member 'Tooltip_Deployable_Choice_C_UpdateDetails::K2Node_MakeStruct_FormatArgumentData_2' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDetails, K2Node_MakeArray_Array) == 0x000178, "Member 'Tooltip_Deployable_Choice_C_UpdateDetails::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDetails, CallFunc_Format_ReturnValue) == 0x000188, "Member 'Tooltip_Deployable_Choice_C_UpdateDetails::CallFunc_Format_ReturnValue' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDetails, CallFunc_TextIsEmpty_ReturnValue) == 0x0001A0, "Member 'Tooltip_Deployable_Choice_C_UpdateDetails::CallFunc_TextIsEmpty_ReturnValue' has a wrong offset!");

// Function Tooltip_Deployable_Choice.Tooltip_Deployable_Choice_C.UpdateRearmAction
// 0x0038 (0x0038 - 0x0000)
struct Tooltip_Deployable_Choice_C_UpdateRearmAction final
{
public:
	class UBP_RadialItemModel_C*                  In_Outer_Context;                                  // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Out_HasCost;                                       // 0x0008(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2615[0x7];                                     // 0x0009(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_RearmWeaponDynamicModel_C*          K2Node_DynamicCast_AsBP_Rearm_Weapon_Dynamic_Model; // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2616[0x3];                                     // 0x0019(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_FTrunc_ReturnValue;                       // 0x001C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FText                                   CallFunc_Conv_IntToText_ReturnValue;               // 0x0020(0x0018)()
};
static_assert(alignof(Tooltip_Deployable_Choice_C_UpdateRearmAction) == 0x000008, "Wrong alignment on Tooltip_Deployable_Choice_C_UpdateRearmAction");
static_assert(sizeof(Tooltip_Deployable_Choice_C_UpdateRearmAction) == 0x000038, "Wrong size on Tooltip_Deployable_Choice_C_UpdateRearmAction");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateRearmAction, In_Outer_Context) == 0x000000, "Member 'Tooltip_Deployable_Choice_C_UpdateRearmAction::In_Outer_Context' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateRearmAction, Out_HasCost) == 0x000008, "Member 'Tooltip_Deployable_Choice_C_UpdateRearmAction::Out_HasCost' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateRearmAction, K2Node_DynamicCast_AsBP_Rearm_Weapon_Dynamic_Model) == 0x000010, "Member 'Tooltip_Deployable_Choice_C_UpdateRearmAction::K2Node_DynamicCast_AsBP_Rearm_Weapon_Dynamic_Model' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateRearmAction, K2Node_DynamicCast_bSuccess) == 0x000018, "Member 'Tooltip_Deployable_Choice_C_UpdateRearmAction::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateRearmAction, CallFunc_FTrunc_ReturnValue) == 0x00001C, "Member 'Tooltip_Deployable_Choice_C_UpdateRearmAction::CallFunc_FTrunc_ReturnValue' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateRearmAction, CallFunc_Conv_IntToText_ReturnValue) == 0x000020, "Member 'Tooltip_Deployable_Choice_C_UpdateRearmAction::CallFunc_Conv_IntToText_ReturnValue' has a wrong offset!");

// Function Tooltip_Deployable_Choice.Tooltip_Deployable_Choice_C.UpdateDeployable
// 0x00E0 (0x00E0 - 0x0000)
struct Tooltip_Deployable_Choice_C_UpdateDeployable final
{
public:
	class UBP_ActionModel_Deployable_C*           In_Outer_Context;                                  // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TSoftObjectPtr<class UTexture2D>              Temp_softobject_Variable;                          // 0x0008(0x0028)(HasGetValueTypeHash)
	bool                                          CallFunc_GetCost_Out_Has_Cost;                     // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2617[0x7];                                     // 0x0031(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<struct FSQCostEntry>                   CallFunc_GetCost_Out_Cost;                         // 0x0038(0x0010)(ReferenceParm)
	class FText                                   CallFunc_Conv_IntToText_ReturnValue;               // 0x0048(0x0018)()
	TSoftObjectPtr<class UTexture2D>              Temp_softobject_Variable_1;                        // 0x0060(0x0028)(HasGetValueTypeHash)
	TSoftObjectPtr<class UTexture2D>              Temp_softobject_Variable_2;                        // 0x0088(0x0028)(HasGetValueTypeHash)
	ESQCurrency                                   Temp_byte_Variable;                                // 0x00B0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2618[0x7];                                     // 0x00B1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TSoftObjectPtr<class UTexture2D>              K2Node_Select_Default;                             // 0x00B8(0x0028)(HasGetValueTypeHash)
};
static_assert(alignof(Tooltip_Deployable_Choice_C_UpdateDeployable) == 0x000008, "Wrong alignment on Tooltip_Deployable_Choice_C_UpdateDeployable");
static_assert(sizeof(Tooltip_Deployable_Choice_C_UpdateDeployable) == 0x0000E0, "Wrong size on Tooltip_Deployable_Choice_C_UpdateDeployable");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDeployable, In_Outer_Context) == 0x000000, "Member 'Tooltip_Deployable_Choice_C_UpdateDeployable::In_Outer_Context' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDeployable, Temp_softobject_Variable) == 0x000008, "Member 'Tooltip_Deployable_Choice_C_UpdateDeployable::Temp_softobject_Variable' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDeployable, CallFunc_GetCost_Out_Has_Cost) == 0x000030, "Member 'Tooltip_Deployable_Choice_C_UpdateDeployable::CallFunc_GetCost_Out_Has_Cost' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDeployable, CallFunc_GetCost_Out_Cost) == 0x000038, "Member 'Tooltip_Deployable_Choice_C_UpdateDeployable::CallFunc_GetCost_Out_Cost' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDeployable, CallFunc_Conv_IntToText_ReturnValue) == 0x000048, "Member 'Tooltip_Deployable_Choice_C_UpdateDeployable::CallFunc_Conv_IntToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDeployable, Temp_softobject_Variable_1) == 0x000060, "Member 'Tooltip_Deployable_Choice_C_UpdateDeployable::Temp_softobject_Variable_1' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDeployable, Temp_softobject_Variable_2) == 0x000088, "Member 'Tooltip_Deployable_Choice_C_UpdateDeployable::Temp_softobject_Variable_2' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDeployable, Temp_byte_Variable) == 0x0000B0, "Member 'Tooltip_Deployable_Choice_C_UpdateDeployable::Temp_byte_Variable' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_UpdateDeployable, K2Node_Select_Default) == 0x0000B8, "Member 'Tooltip_Deployable_Choice_C_UpdateDeployable::K2Node_Select_Default' has a wrong offset!");

// Function Tooltip_Deployable_Choice.Tooltip_Deployable_Choice_C.Update DeployableDetails
// 0x00C0 (0x00C0 - 0x0000)
struct Tooltip_Deployable_Choice_C_Update_DeployableDetails final
{
public:
	class UBP_ActionModel_Deployable_C*           In_Outer_Context;                                  // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   CallFunc_GetActionKeyName_Name;                    // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_NotEqual_NameName_ReturnValue;            // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2619[0x7];                                     // 0x0011(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Conv_NameToText_ReturnValue;              // 0x0018(0x0018)()
	bool                                          Temp_bool_Variable;                                // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_261A[0x7];                                     // 0x0031(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData;              // 0x0038(0x0040)(HasGetValueTypeHash)
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array;                            // 0x0078(0x0010)(ReferenceParm)
	class FText                                   CallFunc_Format_ReturnValue;                       // 0x0088(0x0018)()
	class FText                                   K2Node_Select_Default;                             // 0x00A0(0x0018)(ConstParm)
	bool                                          CallFunc_TextIsEmpty_ReturnValue;                  // 0x00B8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(Tooltip_Deployable_Choice_C_Update_DeployableDetails) == 0x000008, "Wrong alignment on Tooltip_Deployable_Choice_C_Update_DeployableDetails");
static_assert(sizeof(Tooltip_Deployable_Choice_C_Update_DeployableDetails) == 0x0000C0, "Wrong size on Tooltip_Deployable_Choice_C_Update_DeployableDetails");
static_assert(offsetof(Tooltip_Deployable_Choice_C_Update_DeployableDetails, In_Outer_Context) == 0x000000, "Member 'Tooltip_Deployable_Choice_C_Update_DeployableDetails::In_Outer_Context' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_Update_DeployableDetails, CallFunc_GetActionKeyName_Name) == 0x000008, "Member 'Tooltip_Deployable_Choice_C_Update_DeployableDetails::CallFunc_GetActionKeyName_Name' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_Update_DeployableDetails, CallFunc_NotEqual_NameName_ReturnValue) == 0x000010, "Member 'Tooltip_Deployable_Choice_C_Update_DeployableDetails::CallFunc_NotEqual_NameName_ReturnValue' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_Update_DeployableDetails, CallFunc_Conv_NameToText_ReturnValue) == 0x000018, "Member 'Tooltip_Deployable_Choice_C_Update_DeployableDetails::CallFunc_Conv_NameToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_Update_DeployableDetails, Temp_bool_Variable) == 0x000030, "Member 'Tooltip_Deployable_Choice_C_Update_DeployableDetails::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_Update_DeployableDetails, K2Node_MakeStruct_FormatArgumentData) == 0x000038, "Member 'Tooltip_Deployable_Choice_C_Update_DeployableDetails::K2Node_MakeStruct_FormatArgumentData' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_Update_DeployableDetails, K2Node_MakeArray_Array) == 0x000078, "Member 'Tooltip_Deployable_Choice_C_Update_DeployableDetails::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_Update_DeployableDetails, CallFunc_Format_ReturnValue) == 0x000088, "Member 'Tooltip_Deployable_Choice_C_Update_DeployableDetails::CallFunc_Format_ReturnValue' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_Update_DeployableDetails, K2Node_Select_Default) == 0x0000A0, "Member 'Tooltip_Deployable_Choice_C_Update_DeployableDetails::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Choice_C_Update_DeployableDetails, CallFunc_TextIsEmpty_ReturnValue) == 0x0000B8, "Member 'Tooltip_Deployable_Choice_C_Update_DeployableDetails::CallFunc_TextIsEmpty_ReturnValue' has a wrong offset!");

}
