#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: LevelSelector

#include "Basic.hpp"


namespace SDK::Params
{

// Function LevelSelector.LevelSelector_C.Level Selected__DelegateSignature
// 0x0020 (0x0020 - 0x0000)
struct LevelSelector_C_Level_Selected__DelegateSignature final
{
public:
	class FString                                 LevelName;                                         // 0x0000(0x0010)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, HasGetValueTypeHash)
	class FString                                 Mode;                                              // 0x0010(0x0010)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, HasGetValueTypeHash)
};
static_assert(alignof(LevelSelector_C_Level_Selected__DelegateSignature) == 0x000008, "Wrong alignment on LevelSelector_C_Level_Selected__DelegateSignature");
static_assert(sizeof(LevelSelector_C_Level_Selected__DelegateSignature) == 0x000020, "Wrong size on LevelSelector_C_Level_Selected__DelegateSignature");
static_assert(offsetof(LevelSelector_C_Level_Selected__DelegateSignature, LevelName) == 0x000000, "Member 'LevelSelector_C_Level_Selected__DelegateSignature::LevelName' has a wrong offset!");
static_assert(offsetof(LevelSelector_C_Level_Selected__DelegateSignature, Mode) == 0x000010, "Member 'LevelSelector_C_Level_Selected__DelegateSignature::Mode' has a wrong offset!");

// Function LevelSelector.LevelSelector_C.ExecuteUbergraph_LevelSelector
// 0x0090 (0x0090 - 0x0000)
struct LevelSelector_C_ExecuteUbergraph_LevelSelector final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3514[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UUMGSequencePlayer*                     CallFunc_PlayAnimation_ReturnValue;                // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UUMGSequencePlayer*                     CallFunc_PlayAnimation_ReturnValue_1;              // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsAnimationPlaying_ReturnValue;           // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3515[0x7];                                     // 0x0019(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UGameInstance*                          CallFunc_GetGameInstance_ReturnValue;              // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3516[0x7];                                     // 0x0031(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ABP_MainMenu_PC_C*                      K2Node_DynamicCast_AsBP_Main_Menu_PC;              // 0x0038(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0040(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3517[0x7];                                     // 0x0041(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class USQGameInstance*                        K2Node_DynamicCast_AsSQGame_Instance;              // 0x0048(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3518[0x7];                                     // 0x0051(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FString                                 CallFunc_GetLogId_ReturnValue;                     // 0x0058(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	class FString                                 CallFunc_Concat_StrStr_ReturnValue;                // 0x0068(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	bool                                          K2Node_Event_IsDesignTime;                         // 0x0078(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3519[0x7];                                     // 0x0079(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class USQLayer*                               CallFunc_Map_Find_Value;                           // 0x0080(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Map_Find_ReturnValue;                     // 0x0088(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0089(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(LevelSelector_C_ExecuteUbergraph_LevelSelector) == 0x000008, "Wrong alignment on LevelSelector_C_ExecuteUbergraph_LevelSelector");
static_assert(sizeof(LevelSelector_C_ExecuteUbergraph_LevelSelector) == 0x000090, "Wrong size on LevelSelector_C_ExecuteUbergraph_LevelSelector");
static_assert(offsetof(LevelSelector_C_ExecuteUbergraph_LevelSelector, EntryPoint) == 0x000000, "Member 'LevelSelector_C_ExecuteUbergraph_LevelSelector::EntryPoint' has a wrong offset!");
static_assert(offsetof(LevelSelector_C_ExecuteUbergraph_LevelSelector, CallFunc_PlayAnimation_ReturnValue) == 0x000008, "Member 'LevelSelector_C_ExecuteUbergraph_LevelSelector::CallFunc_PlayAnimation_ReturnValue' has a wrong offset!");
static_assert(offsetof(LevelSelector_C_ExecuteUbergraph_LevelSelector, CallFunc_PlayAnimation_ReturnValue_1) == 0x000010, "Member 'LevelSelector_C_ExecuteUbergraph_LevelSelector::CallFunc_PlayAnimation_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(LevelSelector_C_ExecuteUbergraph_LevelSelector, CallFunc_IsAnimationPlaying_ReturnValue) == 0x000018, "Member 'LevelSelector_C_ExecuteUbergraph_LevelSelector::CallFunc_IsAnimationPlaying_ReturnValue' has a wrong offset!");
static_assert(offsetof(LevelSelector_C_ExecuteUbergraph_LevelSelector, CallFunc_GetGameInstance_ReturnValue) == 0x000020, "Member 'LevelSelector_C_ExecuteUbergraph_LevelSelector::CallFunc_GetGameInstance_ReturnValue' has a wrong offset!");
static_assert(offsetof(LevelSelector_C_ExecuteUbergraph_LevelSelector, CallFunc_GetOwningPlayer_ReturnValue) == 0x000028, "Member 'LevelSelector_C_ExecuteUbergraph_LevelSelector::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(LevelSelector_C_ExecuteUbergraph_LevelSelector, CallFunc_IsValid_ReturnValue) == 0x000030, "Member 'LevelSelector_C_ExecuteUbergraph_LevelSelector::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(LevelSelector_C_ExecuteUbergraph_LevelSelector, K2Node_DynamicCast_AsBP_Main_Menu_PC) == 0x000038, "Member 'LevelSelector_C_ExecuteUbergraph_LevelSelector::K2Node_DynamicCast_AsBP_Main_Menu_PC' has a wrong offset!");
static_assert(offsetof(LevelSelector_C_ExecuteUbergraph_LevelSelector, K2Node_DynamicCast_bSuccess) == 0x000040, "Member 'LevelSelector_C_ExecuteUbergraph_LevelSelector::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(LevelSelector_C_ExecuteUbergraph_LevelSelector, K2Node_DynamicCast_AsSQGame_Instance) == 0x000048, "Member 'LevelSelector_C_ExecuteUbergraph_LevelSelector::K2Node_DynamicCast_AsSQGame_Instance' has a wrong offset!");
static_assert(offsetof(LevelSelector_C_ExecuteUbergraph_LevelSelector, K2Node_DynamicCast_bSuccess_1) == 0x000050, "Member 'LevelSelector_C_ExecuteUbergraph_LevelSelector::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(LevelSelector_C_ExecuteUbergraph_LevelSelector, CallFunc_GetLogId_ReturnValue) == 0x000058, "Member 'LevelSelector_C_ExecuteUbergraph_LevelSelector::CallFunc_GetLogId_ReturnValue' has a wrong offset!");
static_assert(offsetof(LevelSelector_C_ExecuteUbergraph_LevelSelector, CallFunc_Concat_StrStr_ReturnValue) == 0x000068, "Member 'LevelSelector_C_ExecuteUbergraph_LevelSelector::CallFunc_Concat_StrStr_ReturnValue' has a wrong offset!");
static_assert(offsetof(LevelSelector_C_ExecuteUbergraph_LevelSelector, K2Node_Event_IsDesignTime) == 0x000078, "Member 'LevelSelector_C_ExecuteUbergraph_LevelSelector::K2Node_Event_IsDesignTime' has a wrong offset!");
static_assert(offsetof(LevelSelector_C_ExecuteUbergraph_LevelSelector, CallFunc_Map_Find_Value) == 0x000080, "Member 'LevelSelector_C_ExecuteUbergraph_LevelSelector::CallFunc_Map_Find_Value' has a wrong offset!");
static_assert(offsetof(LevelSelector_C_ExecuteUbergraph_LevelSelector, CallFunc_Map_Find_ReturnValue) == 0x000088, "Member 'LevelSelector_C_ExecuteUbergraph_LevelSelector::CallFunc_Map_Find_ReturnValue' has a wrong offset!");
static_assert(offsetof(LevelSelector_C_ExecuteUbergraph_LevelSelector, CallFunc_IsValid_ReturnValue_1) == 0x000089, "Member 'LevelSelector_C_ExecuteUbergraph_LevelSelector::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");

// Function LevelSelector.LevelSelector_C.PreConstruct
// 0x0001 (0x0001 - 0x0000)
struct LevelSelector_C_PreConstruct final
{
public:
	bool                                          IsDesignTime;                                      // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(LevelSelector_C_PreConstruct) == 0x000001, "Wrong alignment on LevelSelector_C_PreConstruct");
static_assert(sizeof(LevelSelector_C_PreConstruct) == 0x000001, "Wrong size on LevelSelector_C_PreConstruct");
static_assert(offsetof(LevelSelector_C_PreConstruct, IsDesignTime) == 0x000000, "Member 'LevelSelector_C_PreConstruct::IsDesignTime' has a wrong offset!");

}

