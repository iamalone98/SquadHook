#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: EmoteRadialEntry

#include "Basic.hpp"


namespace SDK::Params
{

// Function EmoteRadialEntry.EmoteRadialEntry_C.ExecuteUbergraph_EmoteRadialEntry
// 0x00A8 (0x00A8 - 0x0000)
struct EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3152[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UUMGSequencePlayer*                     CallFunc_PlayAnimationForward_ReturnValue;         // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UUMGSequencePlayer*                     CallFunc_PlayAnimationReverse_ReturnValue;         // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_EmotesMenu_RadialEntry_C*           K2Node_DynamicCast_AsBP_Emotes_Menu_Radial_Entry;  // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0028(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3153[0x7];                                     // 0x0029(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class URadialEntry_Tooltip_C*                 CallFunc_Create_ReturnValue;                       // 0x0030(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class URadialEntry_Tooltip_Emote_C*           K2Node_DynamicCast_AsRadial_Entry_Tooltip_Emote;   // 0x0038(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0040(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3154[0x7];                                     // 0x0041(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue_1;            // 0x0048(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerController*                    K2Node_DynamicCast_AsSQPlayer_Controller;          // 0x0050(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_2;                     // 0x0058(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3155[0x7];                                     // 0x0059(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_EmotesMenu_RadialEntry_C*           K2Node_DynamicCast_AsBP_Emotes_Menu_Radial_Entry_1; // 0x0060(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_3;                     // 0x0068(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_CanClick_bCanClick;                       // 0x0069(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3156[0x6];                                     // 0x006A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<class FString>                         CallFunc_CanClick_ReturnValue;                     // 0x0070(0x0010)(ReferenceParm)
	class FString                                 CallFunc_JoinStringArray_ReturnValue;              // 0x0080(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	class FText                                   CallFunc_Conv_StringToText_ReturnValue;            // 0x0090(0x0018)()
};
static_assert(alignof(EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry) == 0x000008, "Wrong alignment on EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry");
static_assert(sizeof(EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry) == 0x0000A8, "Wrong size on EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry");
static_assert(offsetof(EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry, EntryPoint) == 0x000000, "Member 'EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry::EntryPoint' has a wrong offset!");
static_assert(offsetof(EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry, CallFunc_PlayAnimationForward_ReturnValue) == 0x000008, "Member 'EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry::CallFunc_PlayAnimationForward_ReturnValue' has a wrong offset!");
static_assert(offsetof(EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry, CallFunc_PlayAnimationReverse_ReturnValue) == 0x000010, "Member 'EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry::CallFunc_PlayAnimationReverse_ReturnValue' has a wrong offset!");
static_assert(offsetof(EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry, CallFunc_GetOwningPlayer_ReturnValue) == 0x000018, "Member 'EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry, K2Node_DynamicCast_AsBP_Emotes_Menu_Radial_Entry) == 0x000020, "Member 'EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry::K2Node_DynamicCast_AsBP_Emotes_Menu_Radial_Entry' has a wrong offset!");
static_assert(offsetof(EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry, K2Node_DynamicCast_bSuccess) == 0x000028, "Member 'EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry, CallFunc_Create_ReturnValue) == 0x000030, "Member 'EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry::CallFunc_Create_ReturnValue' has a wrong offset!");
static_assert(offsetof(EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry, K2Node_DynamicCast_AsRadial_Entry_Tooltip_Emote) == 0x000038, "Member 'EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry::K2Node_DynamicCast_AsRadial_Entry_Tooltip_Emote' has a wrong offset!");
static_assert(offsetof(EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry, K2Node_DynamicCast_bSuccess_1) == 0x000040, "Member 'EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry, CallFunc_GetOwningPlayer_ReturnValue_1) == 0x000048, "Member 'EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry::CallFunc_GetOwningPlayer_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry, K2Node_DynamicCast_AsSQPlayer_Controller) == 0x000050, "Member 'EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry::K2Node_DynamicCast_AsSQPlayer_Controller' has a wrong offset!");
static_assert(offsetof(EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry, K2Node_DynamicCast_bSuccess_2) == 0x000058, "Member 'EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry::K2Node_DynamicCast_bSuccess_2' has a wrong offset!");
static_assert(offsetof(EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry, K2Node_DynamicCast_AsBP_Emotes_Menu_Radial_Entry_1) == 0x000060, "Member 'EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry::K2Node_DynamicCast_AsBP_Emotes_Menu_Radial_Entry_1' has a wrong offset!");
static_assert(offsetof(EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry, K2Node_DynamicCast_bSuccess_3) == 0x000068, "Member 'EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry::K2Node_DynamicCast_bSuccess_3' has a wrong offset!");
static_assert(offsetof(EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry, CallFunc_CanClick_bCanClick) == 0x000069, "Member 'EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry::CallFunc_CanClick_bCanClick' has a wrong offset!");
static_assert(offsetof(EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry, CallFunc_CanClick_ReturnValue) == 0x000070, "Member 'EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry::CallFunc_CanClick_ReturnValue' has a wrong offset!");
static_assert(offsetof(EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry, CallFunc_JoinStringArray_ReturnValue) == 0x000080, "Member 'EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry::CallFunc_JoinStringArray_ReturnValue' has a wrong offset!");
static_assert(offsetof(EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry, CallFunc_Conv_StringToText_ReturnValue) == 0x000090, "Member 'EmoteRadialEntry_C_ExecuteUbergraph_EmoteRadialEntry::CallFunc_Conv_StringToText_ReturnValue' has a wrong offset!");

}

