#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_SpawnableDeployableItem

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "SQDeployableEntry_structs.hpp"


namespace SDK::Params
{

// Function BP_SpawnableDeployableItem.BP_SpawnableDeployableItem_C.Setup
// 0x02E0 (0x02E0 - 0x0000)
struct BP_SpawnableDeployableItem_C_Setup final
{
public:
	class UObject*                                Data;                                              // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Success;                                           // 0x0008(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_301C[0x7];                                     // 0x0009(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   FailReason;                                        // 0x0010(0x0018)(Parm, OutParm)
	class UBP_SQDeployableSettings_C*             K2Node_DynamicCast_AsBP_SQDeployable_Settings;     // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0031(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValidSoftClassReference_ReturnValue;    // 0x0032(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_301D[0x5];                                     // 0x0033(0x0005)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Conv_ObjectToText_ReturnValue;            // 0x0038(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData;              // 0x0050(0x0040)(HasGetValueTypeHash)
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array;                            // 0x0090(0x0010)(ReferenceParm)
	class FText                                   CallFunc_Format_ReturnValue;                       // 0x00A0(0x0018)()
	class FString                                 CallFunc_Conv_SoftClassReferenceToString_ReturnValue; // 0x00B8(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	class FText                                   CallFunc_Conv_ObjectToText_ReturnValue_1;          // 0x00C8(0x0018)()
	class FText                                   CallFunc_Conv_StringToText_ReturnValue;            // 0x00E0(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_1;            // 0x00F8(0x0040)(HasGetValueTypeHash)
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array_1;                          // 0x0138(0x0010)(ReferenceParm)
	class FText                                   CallFunc_Format_ReturnValue_1;                     // 0x0148(0x0018)()
	class FText                                   CallFunc_Conv_NameToText_ReturnValue;              // 0x0160(0x0018)()
	struct FSQDeployableEntry                     CallFunc_GetDataTableRowFromName_OutRow;           // 0x0178(0x0068)(HasGetValueTypeHash)
	bool                                          CallFunc_GetDataTableRowFromName_ReturnValue;      // 0x01E0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_301E[0x7];                                     // 0x01E1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_2;            // 0x01E8(0x0040)(HasGetValueTypeHash)
	class FText                                   CallFunc_Conv_ObjectToText_ReturnValue_2;          // 0x0228(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_3;            // 0x0240(0x0040)(HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0280(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_301F[0x7];                                     // 0x0281(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array_2;                          // 0x0288(0x0010)(ReferenceParm)
	class FText                                   CallFunc_Format_ReturnValue_2;                     // 0x0298(0x0018)()
	TSoftClassPtr<class UClass>                   CallFunc_TryGetDeployableWithLayer_OutDeployable;  // 0x02B0(0x0028)(UObjectWrapper, HasGetValueTypeHash)
	bool                                          CallFunc_TryGetDeployableWithLayer_ReturnValue;    // 0x02D8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_SpawnableDeployableItem_C_Setup) == 0x000008, "Wrong alignment on BP_SpawnableDeployableItem_C_Setup");
static_assert(sizeof(BP_SpawnableDeployableItem_C_Setup) == 0x0002E0, "Wrong size on BP_SpawnableDeployableItem_C_Setup");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, Data) == 0x000000, "Member 'BP_SpawnableDeployableItem_C_Setup::Data' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, Success) == 0x000008, "Member 'BP_SpawnableDeployableItem_C_Setup::Success' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, FailReason) == 0x000010, "Member 'BP_SpawnableDeployableItem_C_Setup::FailReason' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, K2Node_DynamicCast_AsBP_SQDeployable_Settings) == 0x000028, "Member 'BP_SpawnableDeployableItem_C_Setup::K2Node_DynamicCast_AsBP_SQDeployable_Settings' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, K2Node_DynamicCast_bSuccess) == 0x000030, "Member 'BP_SpawnableDeployableItem_C_Setup::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, CallFunc_IsValid_ReturnValue) == 0x000031, "Member 'BP_SpawnableDeployableItem_C_Setup::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, CallFunc_IsValidSoftClassReference_ReturnValue) == 0x000032, "Member 'BP_SpawnableDeployableItem_C_Setup::CallFunc_IsValidSoftClassReference_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, CallFunc_Conv_ObjectToText_ReturnValue) == 0x000038, "Member 'BP_SpawnableDeployableItem_C_Setup::CallFunc_Conv_ObjectToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, K2Node_MakeStruct_FormatArgumentData) == 0x000050, "Member 'BP_SpawnableDeployableItem_C_Setup::K2Node_MakeStruct_FormatArgumentData' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, K2Node_MakeArray_Array) == 0x000090, "Member 'BP_SpawnableDeployableItem_C_Setup::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, CallFunc_Format_ReturnValue) == 0x0000A0, "Member 'BP_SpawnableDeployableItem_C_Setup::CallFunc_Format_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, CallFunc_Conv_SoftClassReferenceToString_ReturnValue) == 0x0000B8, "Member 'BP_SpawnableDeployableItem_C_Setup::CallFunc_Conv_SoftClassReferenceToString_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, CallFunc_Conv_ObjectToText_ReturnValue_1) == 0x0000C8, "Member 'BP_SpawnableDeployableItem_C_Setup::CallFunc_Conv_ObjectToText_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, CallFunc_Conv_StringToText_ReturnValue) == 0x0000E0, "Member 'BP_SpawnableDeployableItem_C_Setup::CallFunc_Conv_StringToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, K2Node_MakeStruct_FormatArgumentData_1) == 0x0000F8, "Member 'BP_SpawnableDeployableItem_C_Setup::K2Node_MakeStruct_FormatArgumentData_1' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, K2Node_MakeArray_Array_1) == 0x000138, "Member 'BP_SpawnableDeployableItem_C_Setup::K2Node_MakeArray_Array_1' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, CallFunc_Format_ReturnValue_1) == 0x000148, "Member 'BP_SpawnableDeployableItem_C_Setup::CallFunc_Format_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, CallFunc_Conv_NameToText_ReturnValue) == 0x000160, "Member 'BP_SpawnableDeployableItem_C_Setup::CallFunc_Conv_NameToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, CallFunc_GetDataTableRowFromName_OutRow) == 0x000178, "Member 'BP_SpawnableDeployableItem_C_Setup::CallFunc_GetDataTableRowFromName_OutRow' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, CallFunc_GetDataTableRowFromName_ReturnValue) == 0x0001E0, "Member 'BP_SpawnableDeployableItem_C_Setup::CallFunc_GetDataTableRowFromName_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, K2Node_MakeStruct_FormatArgumentData_2) == 0x0001E8, "Member 'BP_SpawnableDeployableItem_C_Setup::K2Node_MakeStruct_FormatArgumentData_2' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, CallFunc_Conv_ObjectToText_ReturnValue_2) == 0x000228, "Member 'BP_SpawnableDeployableItem_C_Setup::CallFunc_Conv_ObjectToText_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, K2Node_MakeStruct_FormatArgumentData_3) == 0x000240, "Member 'BP_SpawnableDeployableItem_C_Setup::K2Node_MakeStruct_FormatArgumentData_3' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, CallFunc_IsValid_ReturnValue_1) == 0x000280, "Member 'BP_SpawnableDeployableItem_C_Setup::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, K2Node_MakeArray_Array_2) == 0x000288, "Member 'BP_SpawnableDeployableItem_C_Setup::K2Node_MakeArray_Array_2' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, CallFunc_Format_ReturnValue_2) == 0x000298, "Member 'BP_SpawnableDeployableItem_C_Setup::CallFunc_Format_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, CallFunc_TryGetDeployableWithLayer_OutDeployable) == 0x0002B0, "Member 'BP_SpawnableDeployableItem_C_Setup::CallFunc_TryGetDeployableWithLayer_OutDeployable' has a wrong offset!");
static_assert(offsetof(BP_SpawnableDeployableItem_C_Setup, CallFunc_TryGetDeployableWithLayer_ReturnValue) == 0x0002D8, "Member 'BP_SpawnableDeployableItem_C_Setup::CallFunc_TryGetDeployableWithLayer_ReturnValue' has a wrong offset!");

}

