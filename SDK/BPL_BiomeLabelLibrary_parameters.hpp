#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BPL_BiomeLabelLibrary

#include "Basic.hpp"

#include "Squad_structs.hpp"


namespace SDK::Params
{

// Function BPL_BiomeLabelLibrary.BPL_BiomeLabelLibrary_C.MakeLabelsForSkin
// 0x0278 (0x0278 - 0x0000)
struct BPL_BiomeLabelLibrary_C_MakeLabelsForSkin final
{
public:
	class USQItemSkinCollection*                  SkinData;                                          // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UObject*                                __WorldContext;                                    // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TArray<class UW_BiomeLabel_C*>                OutLabels;                                         // 0x0010(0x0010)(Parm, OutParm, ContainsInstancedReference)
	TArray<class UW_BiomeLabel_C*>                Labels;                                            // 0x0020(0x0010)(Edit, BlueprintVisible, ContainsInstancedReference)
	TArray<struct FSQSkinUIBadge>                 UIBadgeArray;                                      // 0x0030(0x0010)(Edit, BlueprintVisible)
	int32                                         Temp_int_Array_Index_Variable;                     // 0x0040(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_32E1[0x4];                                     // 0x0044(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class USQItemSkinSubsystem*                   CallFunc_GetGameInstanceSubsystem_ReturnValue;     // 0x0048(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQItemSkinSubsystem*                   CallFunc_GetGameInstanceSubsystem_ReturnValue_1;   // 0x0050(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UW_BiomeLabel_C*                        CallFunc_Create_ReturnValue;                       // 0x0058(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_SwitchEnum_CmpSuccess;                      // 0x0060(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_32E2[0x7];                                     // 0x0061(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<struct FSQSkinUIBadge>                 CallFunc_GetSkinUIBadgesForKeys_ReturnValue;       // 0x0068(0x0010)(ReferenceParm)
	struct FSQSkinUIBadge                         CallFunc_GetSkinUIBadgeForKey_ReturnValue;         // 0x0078(0x0070)()
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x00E8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_32E3[0x3];                                     // 0x00E9(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class FName                                   CallFunc_MakeLiteralName_ReturnValue;              // 0x00EC(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   CallFunc_MakeLiteralName_ReturnValue_1;            // 0x00F4(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_32E4[0x4];                                     // 0x00FC(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSQSkinUIBadge                         CallFunc_GetSkinUIBadgeForKey_ReturnValue_1;       // 0x0100(0x0070)()
	struct FSQSkinUIBadge                         CallFunc_GetSkinUIBadgeForKey_ReturnValue_2;       // 0x0170(0x0070)()
	int32                                         CallFunc_Array_Add_ReturnValue;                    // 0x01E0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Add_ReturnValue_1;                  // 0x01E4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Add_ReturnValue_2;                  // 0x01E8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Add_ReturnValue_3;                  // 0x01EC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x01F0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_32E5[0x4];                                     // 0x01F4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSQSkinUIBadge                         CallFunc_Array_Get_Item;                           // 0x01F8(0x0070)()
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0268(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x026C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x0270(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin) == 0x000008, "Wrong alignment on BPL_BiomeLabelLibrary_C_MakeLabelsForSkin");
static_assert(sizeof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin) == 0x000278, "Wrong size on BPL_BiomeLabelLibrary_C_MakeLabelsForSkin");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, SkinData) == 0x000000, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::SkinData' has a wrong offset!");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, __WorldContext) == 0x000008, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::__WorldContext' has a wrong offset!");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, OutLabels) == 0x000010, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::OutLabels' has a wrong offset!");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, Labels) == 0x000020, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::Labels' has a wrong offset!");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, UIBadgeArray) == 0x000030, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::UIBadgeArray' has a wrong offset!");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, Temp_int_Array_Index_Variable) == 0x000040, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, CallFunc_GetGameInstanceSubsystem_ReturnValue) == 0x000048, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::CallFunc_GetGameInstanceSubsystem_ReturnValue' has a wrong offset!");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, CallFunc_GetGameInstanceSubsystem_ReturnValue_1) == 0x000050, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::CallFunc_GetGameInstanceSubsystem_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, CallFunc_Create_ReturnValue) == 0x000058, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::CallFunc_Create_ReturnValue' has a wrong offset!");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, K2Node_SwitchEnum_CmpSuccess) == 0x000060, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::K2Node_SwitchEnum_CmpSuccess' has a wrong offset!");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, CallFunc_GetSkinUIBadgesForKeys_ReturnValue) == 0x000068, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::CallFunc_GetSkinUIBadgesForKeys_ReturnValue' has a wrong offset!");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, CallFunc_GetSkinUIBadgeForKey_ReturnValue) == 0x000078, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::CallFunc_GetSkinUIBadgeForKey_ReturnValue' has a wrong offset!");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, CallFunc_IsValid_ReturnValue) == 0x0000E8, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, CallFunc_MakeLiteralName_ReturnValue) == 0x0000EC, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::CallFunc_MakeLiteralName_ReturnValue' has a wrong offset!");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, CallFunc_MakeLiteralName_ReturnValue_1) == 0x0000F4, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::CallFunc_MakeLiteralName_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, CallFunc_GetSkinUIBadgeForKey_ReturnValue_1) == 0x000100, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::CallFunc_GetSkinUIBadgeForKey_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, CallFunc_GetSkinUIBadgeForKey_ReturnValue_2) == 0x000170, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::CallFunc_GetSkinUIBadgeForKey_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, CallFunc_Array_Add_ReturnValue) == 0x0001E0, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::CallFunc_Array_Add_ReturnValue' has a wrong offset!");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, CallFunc_Array_Add_ReturnValue_1) == 0x0001E4, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::CallFunc_Array_Add_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, CallFunc_Array_Add_ReturnValue_2) == 0x0001E8, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::CallFunc_Array_Add_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, CallFunc_Array_Add_ReturnValue_3) == 0x0001EC, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::CallFunc_Array_Add_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, Temp_int_Loop_Counter_Variable) == 0x0001F0, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, CallFunc_Array_Get_Item) == 0x0001F8, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, CallFunc_Add_IntInt_ReturnValue) == 0x000268, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, CallFunc_Array_Length_ReturnValue) == 0x00026C, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(BPL_BiomeLabelLibrary_C_MakeLabelsForSkin, CallFunc_Less_IntInt_ReturnValue) == 0x000270, "Member 'BPL_BiomeLabelLibrary_C_MakeLabelsForSkin::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");

}

