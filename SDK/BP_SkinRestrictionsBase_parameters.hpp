#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_SkinRestrictionsBase

#include "Basic.hpp"

#include "Squad_structs.hpp"
#include "SkinRestrictionsData_structs.hpp"
#include "ESQBiome_structs.hpp"


namespace SDK::Params
{

// Function BP_SkinRestrictionsBase.BP_SkinRestrictionsBase_C.IsValidForCurrentConditions
// 0x0370 (0x0370 - 0x0000)
struct BP_SkinRestrictionsBase_C_IsValidForCurrentConditions final
{
public:
	struct FSQItemSkinRestrictionParameters       Params_0;                                          // 0x0000(0x0038)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm, NoDestructor)
	bool                                          ReturnValue;                                       // 0x0038(0x0001)(Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D8E[0x7];                                     // 0x0039(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSkinRestrictionsData                  Restrictions;                                      // 0x0040(0x00A8)(Edit, BlueprintVisible, HasGetValueTypeHash)
	class UBP_SQFactionSetup_C*                   FacSetup;                                          // 0x00E8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TSoftObjectPtr<class UBP_SQFactionSetup_C>    CallFunc_Conv_ObjectToSoftObjectReference_ReturnValue; // 0x00F0(0x0028)(UObjectWrapper, HasGetValueTypeHash)
	TSet<TSoftObjectPtr<class UBP_SQFactionSetup_C>> K2Node_MakeSet_Set;                                // 0x0118(0x0050)()
	class UBP_SQFactionSetup_C*                   K2Node_DynamicCast_AsBP_SQFaction_Setup;           // 0x0168(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0170(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D8F[0x7];                                     // 0x0171(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSkinRestrictionsData                  CallFunc_GetDataTableRowFromName_OutRow;           // 0x0178(0x00A8)(HasGetValueTypeHash)
	bool                                          CallFunc_GetDataTableRowFromName_ReturnValue;      // 0x0220(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0221(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D90[0x6];                                     // 0x0222(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_SQLevel_C*                          K2Node_DynamicCast_AsBP_SQLevel;                   // 0x0228(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0230(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D91[0x7];                                     // 0x0231(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TSet<ESQBiome>                                K2Node_MakeSet_Set_1;                              // 0x0238(0x0050)()
	struct FSkinRestrictionsData                  K2Node_MakeStruct_SkinRestrictionsData;            // 0x0288(0x00A8)(HasGetValueTypeHash)
	TSoftObjectPtr<class UBP_SQFactionSetup_C>    CallFunc_Conv_ObjectToSoftObjectReference_ReturnValue_1; // 0x0330(0x0028)(UObjectWrapper, HasGetValueTypeHash)
	int32                                         CallFunc_Set_Length_ReturnValue;                   // 0x0358(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Set_Contains_ReturnValue;                 // 0x035C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_IntInt_ReturnValue;            // 0x035D(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D92[0x2];                                     // 0x035E(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Set_Length_ReturnValue_1;                 // 0x0360(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_BooleanOR_ReturnValue;                    // 0x0364(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_IntInt_ReturnValue_1;          // 0x0365(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Set_Contains_ReturnValue_1;               // 0x0366(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanOR_ReturnValue_1;                  // 0x0367(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue;                   // 0x0368(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions) == 0x000008, "Wrong alignment on BP_SkinRestrictionsBase_C_IsValidForCurrentConditions");
static_assert(sizeof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions) == 0x000370, "Wrong size on BP_SkinRestrictionsBase_C_IsValidForCurrentConditions");
static_assert(offsetof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions, Params_0) == 0x000000, "Member 'BP_SkinRestrictionsBase_C_IsValidForCurrentConditions::Params_0' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions, ReturnValue) == 0x000038, "Member 'BP_SkinRestrictionsBase_C_IsValidForCurrentConditions::ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions, Restrictions) == 0x000040, "Member 'BP_SkinRestrictionsBase_C_IsValidForCurrentConditions::Restrictions' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions, FacSetup) == 0x0000E8, "Member 'BP_SkinRestrictionsBase_C_IsValidForCurrentConditions::FacSetup' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions, CallFunc_Conv_ObjectToSoftObjectReference_ReturnValue) == 0x0000F0, "Member 'BP_SkinRestrictionsBase_C_IsValidForCurrentConditions::CallFunc_Conv_ObjectToSoftObjectReference_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions, K2Node_MakeSet_Set) == 0x000118, "Member 'BP_SkinRestrictionsBase_C_IsValidForCurrentConditions::K2Node_MakeSet_Set' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions, K2Node_DynamicCast_AsBP_SQFaction_Setup) == 0x000168, "Member 'BP_SkinRestrictionsBase_C_IsValidForCurrentConditions::K2Node_DynamicCast_AsBP_SQFaction_Setup' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions, K2Node_DynamicCast_bSuccess) == 0x000170, "Member 'BP_SkinRestrictionsBase_C_IsValidForCurrentConditions::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions, CallFunc_GetDataTableRowFromName_OutRow) == 0x000178, "Member 'BP_SkinRestrictionsBase_C_IsValidForCurrentConditions::CallFunc_GetDataTableRowFromName_OutRow' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions, CallFunc_GetDataTableRowFromName_ReturnValue) == 0x000220, "Member 'BP_SkinRestrictionsBase_C_IsValidForCurrentConditions::CallFunc_GetDataTableRowFromName_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions, CallFunc_IsValid_ReturnValue) == 0x000221, "Member 'BP_SkinRestrictionsBase_C_IsValidForCurrentConditions::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions, K2Node_DynamicCast_AsBP_SQLevel) == 0x000228, "Member 'BP_SkinRestrictionsBase_C_IsValidForCurrentConditions::K2Node_DynamicCast_AsBP_SQLevel' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions, K2Node_DynamicCast_bSuccess_1) == 0x000230, "Member 'BP_SkinRestrictionsBase_C_IsValidForCurrentConditions::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions, K2Node_MakeSet_Set_1) == 0x000238, "Member 'BP_SkinRestrictionsBase_C_IsValidForCurrentConditions::K2Node_MakeSet_Set_1' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions, K2Node_MakeStruct_SkinRestrictionsData) == 0x000288, "Member 'BP_SkinRestrictionsBase_C_IsValidForCurrentConditions::K2Node_MakeStruct_SkinRestrictionsData' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions, CallFunc_Conv_ObjectToSoftObjectReference_ReturnValue_1) == 0x000330, "Member 'BP_SkinRestrictionsBase_C_IsValidForCurrentConditions::CallFunc_Conv_ObjectToSoftObjectReference_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions, CallFunc_Set_Length_ReturnValue) == 0x000358, "Member 'BP_SkinRestrictionsBase_C_IsValidForCurrentConditions::CallFunc_Set_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions, CallFunc_Set_Contains_ReturnValue) == 0x00035C, "Member 'BP_SkinRestrictionsBase_C_IsValidForCurrentConditions::CallFunc_Set_Contains_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions, CallFunc_EqualEqual_IntInt_ReturnValue) == 0x00035D, "Member 'BP_SkinRestrictionsBase_C_IsValidForCurrentConditions::CallFunc_EqualEqual_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions, CallFunc_Set_Length_ReturnValue_1) == 0x000360, "Member 'BP_SkinRestrictionsBase_C_IsValidForCurrentConditions::CallFunc_Set_Length_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions, CallFunc_BooleanOR_ReturnValue) == 0x000364, "Member 'BP_SkinRestrictionsBase_C_IsValidForCurrentConditions::CallFunc_BooleanOR_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions, CallFunc_EqualEqual_IntInt_ReturnValue_1) == 0x000365, "Member 'BP_SkinRestrictionsBase_C_IsValidForCurrentConditions::CallFunc_EqualEqual_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions, CallFunc_Set_Contains_ReturnValue_1) == 0x000366, "Member 'BP_SkinRestrictionsBase_C_IsValidForCurrentConditions::CallFunc_Set_Contains_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions, CallFunc_BooleanOR_ReturnValue_1) == 0x000367, "Member 'BP_SkinRestrictionsBase_C_IsValidForCurrentConditions::CallFunc_BooleanOR_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_IsValidForCurrentConditions, CallFunc_BooleanAND_ReturnValue) == 0x000368, "Member 'BP_SkinRestrictionsBase_C_IsValidForCurrentConditions::CallFunc_BooleanAND_ReturnValue' has a wrong offset!");

// Function BP_SkinRestrictionsBase.BP_SkinRestrictionsBase_C.OverrideConflictingSkins
// 0x0458 (0x0458 - 0x0000)
struct BP_SkinRestrictionsBase_C_OverrideConflictingSkins final
{
public:
	struct FSQItemSkinRestrictionParameters       Params_0;                                          // 0x0000(0x0038)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm, NoDestructor)
	TArray<class FName>                           SavedEquippedSkins;                                // 0x0038(0x0010)(Edit, BlueprintVisible)
	class UBP_SQFactionSetup_C*                   FacSetup;                                          // 0x0048(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FSkinRestrictionsData                  Restrictions;                                      // 0x0050(0x00A8)(Edit, BlueprintVisible, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable;                     // 0x00F8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x00FC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FSkinRestrictionsData                  CallFunc_GetDataTableRowFromName_OutRow;           // 0x0100(0x00A8)(HasGetValueTypeHash)
	bool                                          CallFunc_GetDataTableRowFromName_ReturnValue;      // 0x01A8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D93[0x3];                                     // 0x01A9(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x01AC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x01B0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D94[0x7];                                     // 0x01B1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TSet<TSoftObjectPtr<class UBP_SQFactionSetup_C>> K2Node_MakeSet_Set;                                // 0x01B8(0x0050)()
	TSet<ESQBiome>                                K2Node_MakeSet_Set_1;                              // 0x0208(0x0050)()
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0258(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D95[0x7];                                     // 0x0259(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSkinRestrictionsData                  K2Node_MakeStruct_SkinRestrictionsData;            // 0x0260(0x00A8)(HasGetValueTypeHash)
	class FName                                   CallFunc_Array_Get_Item;                           // 0x0308(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x0310(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESQSkinEnableResult                           CallFunc_SetSkinEnabledForFaction_ReturnValue;     // 0x0314(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x0315(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D96[0x2];                                     // 0x0316(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	const class USQItemSkinCollection*            CallFunc_FindSkin_ReturnValue;                     // 0x0318(0x0008)(ConstParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_2;                    // 0x0320(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D97[0x7];                                     // 0x0321(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSkinRestrictionsData                  CallFunc_GetDataTableRowFromName_OutRow_1;         // 0x0328(0x00A8)(HasGetValueTypeHash)
	bool                                          CallFunc_GetDataTableRowFromName_ReturnValue_1;    // 0x03D0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_NameName_ReturnValue;          // 0x03D1(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D98[0x6];                                     // 0x03D2(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	TSet<ESQBiome>                                CallFunc_Set_Intersection_Result;                  // 0x03D8(0x0050)()
	int32                                         CallFunc_Set_Length_ReturnValue;                   // 0x0428(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2D99[0x4];                                     // 0x042C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class USQGameUserSettings*                    CallFunc_GetSquadGameUserSettings_ReturnValue;     // 0x0430(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Greater_IntInt_ReturnValue;               // 0x0438(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D9A[0x7];                                     // 0x0439(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSQSkinArray                           CallFunc_Map_Find_Value;                           // 0x0440(0x0010)()
	bool                                          CallFunc_Map_Find_ReturnValue;                     // 0x0450(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins) == 0x000008, "Wrong alignment on BP_SkinRestrictionsBase_C_OverrideConflictingSkins");
static_assert(sizeof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins) == 0x000458, "Wrong size on BP_SkinRestrictionsBase_C_OverrideConflictingSkins");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, Params_0) == 0x000000, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::Params_0' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, SavedEquippedSkins) == 0x000038, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::SavedEquippedSkins' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, FacSetup) == 0x000048, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::FacSetup' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, Restrictions) == 0x000050, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::Restrictions' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, Temp_int_Array_Index_Variable) == 0x0000F8, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, Temp_int_Loop_Counter_Variable) == 0x0000FC, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, CallFunc_GetDataTableRowFromName_OutRow) == 0x000100, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::CallFunc_GetDataTableRowFromName_OutRow' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, CallFunc_GetDataTableRowFromName_ReturnValue) == 0x0001A8, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::CallFunc_GetDataTableRowFromName_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, CallFunc_Add_IntInt_ReturnValue) == 0x0001AC, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, CallFunc_IsValid_ReturnValue) == 0x0001B0, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, K2Node_MakeSet_Set) == 0x0001B8, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::K2Node_MakeSet_Set' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, K2Node_MakeSet_Set_1) == 0x000208, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::K2Node_MakeSet_Set_1' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, CallFunc_IsValid_ReturnValue_1) == 0x000258, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, K2Node_MakeStruct_SkinRestrictionsData) == 0x000260, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::K2Node_MakeStruct_SkinRestrictionsData' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, CallFunc_Array_Get_Item) == 0x000308, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, CallFunc_Array_Length_ReturnValue) == 0x000310, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, CallFunc_SetSkinEnabledForFaction_ReturnValue) == 0x000314, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::CallFunc_SetSkinEnabledForFaction_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, CallFunc_Less_IntInt_ReturnValue) == 0x000315, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, CallFunc_FindSkin_ReturnValue) == 0x000318, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::CallFunc_FindSkin_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, CallFunc_IsValid_ReturnValue_2) == 0x000320, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::CallFunc_IsValid_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, CallFunc_GetDataTableRowFromName_OutRow_1) == 0x000328, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::CallFunc_GetDataTableRowFromName_OutRow_1' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, CallFunc_GetDataTableRowFromName_ReturnValue_1) == 0x0003D0, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::CallFunc_GetDataTableRowFromName_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, CallFunc_EqualEqual_NameName_ReturnValue) == 0x0003D1, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::CallFunc_EqualEqual_NameName_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, CallFunc_Set_Intersection_Result) == 0x0003D8, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::CallFunc_Set_Intersection_Result' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, CallFunc_Set_Length_ReturnValue) == 0x000428, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::CallFunc_Set_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, CallFunc_GetSquadGameUserSettings_ReturnValue) == 0x000430, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::CallFunc_GetSquadGameUserSettings_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, CallFunc_Greater_IntInt_ReturnValue) == 0x000438, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::CallFunc_Greater_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, CallFunc_Map_Find_Value) == 0x000440, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::CallFunc_Map_Find_Value' has a wrong offset!");
static_assert(offsetof(BP_SkinRestrictionsBase_C_OverrideConflictingSkins, CallFunc_Map_Find_ReturnValue) == 0x000450, "Member 'BP_SkinRestrictionsBase_C_OverrideConflictingSkins::CallFunc_Map_Find_ReturnValue' has a wrong offset!");

}

