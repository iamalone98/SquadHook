#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: ModItem

#include "Basic.hpp"

#include "CoreUObject_structs.hpp"
#include "ModdingRuntime_structs.hpp"


namespace SDK::Params
{

// Function ModItem.ModItem_C.Mod Selected__DelegateSignature
// 0x00A0 (0x00A0 - 0x0000)
struct ModItem_C_Mod_Selected__DelegateSignature final
{
public:
	struct FModdingRuntimeModInfoDetails          Param_ModInfo;                                     // 0x0000(0x00A0)(BlueprintVisible, BlueprintReadOnly, Parm)
};
static_assert(alignof(ModItem_C_Mod_Selected__DelegateSignature) == 0x000008, "Wrong alignment on ModItem_C_Mod_Selected__DelegateSignature");
static_assert(sizeof(ModItem_C_Mod_Selected__DelegateSignature) == 0x0000A0, "Wrong size on ModItem_C_Mod_Selected__DelegateSignature");
static_assert(offsetof(ModItem_C_Mod_Selected__DelegateSignature, Param_ModInfo) == 0x000000, "Member 'ModItem_C_Mod_Selected__DelegateSignature::Param_ModInfo' has a wrong offset!");

// Function ModItem.ModItem_C.ExecuteUbergraph_ModItem
// 0x00D8 (0x00D8 - 0x0000)
struct ModItem_C_ExecuteUbergraph_ModItem final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_Variable;                                // 0x0004(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsAnimationPlaying_ReturnValue;           // 0x0005(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3207[0x2];                                     // 0x0006(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	struct FLinearColor                           Temp_struct_Variable;                              // 0x0008(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           Temp_struct_Variable_1;                            // 0x0018(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_Variable_1;                              // 0x0028(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3208[0x3];                                     // 0x0029(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FLinearColor                           K2Node_Select_Default;                             // 0x002C(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           Temp_struct_Variable_2;                            // 0x003C(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           Temp_struct_Variable_3;                            // 0x004C(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           K2Node_Select_Default_1;                           // 0x005C(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TDelegate<void(class UTexture2DDynamic* Texture)> K2Node_CreateDelegate_OutputDelegate;              // 0x006C(0x0010)(ZeroConstructor, NoDestructor)
	uint8                                         Pad_3209[0x4];                                     // 0x007C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UTexture2DDynamic*                      K2Node_CustomEvent_Texture_1;                      // 0x0080(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UTexture2DDynamic*                      K2Node_CustomEvent_Texture;                        // 0x0088(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TDelegate<void(class UTexture2DDynamic* Texture)> K2Node_CreateDelegate_OutputDelegate_1;            // 0x0090(0x0010)(ZeroConstructor, NoDestructor)
	class UTexture2DDynamic*                      Temp_object_Variable;                              // 0x00A0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_Event_IsDesignTime;                         // 0x00A8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_320A[0x7];                                     // 0x00A9(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UUMGSequencePlayer*                     CallFunc_PlayAnimation_ReturnValue;                // 0x00B0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UUMGSequencePlayer*                     CallFunc_PlayAnimation_ReturnValue_1;              // 0x00B8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAsyncTaskDownloadImage*                CallFunc_DownloadImage_ReturnValue;                // 0x00C0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x00C8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_ComponentBoundEvent_bSelected;              // 0x00C9(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_320B[0x6];                                     // 0x00CA(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class UMainMenu_Button_C*                     K2Node_ComponentBoundEvent_Button;                 // 0x00D0(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(ModItem_C_ExecuteUbergraph_ModItem) == 0x000008, "Wrong alignment on ModItem_C_ExecuteUbergraph_ModItem");
static_assert(sizeof(ModItem_C_ExecuteUbergraph_ModItem) == 0x0000D8, "Wrong size on ModItem_C_ExecuteUbergraph_ModItem");
static_assert(offsetof(ModItem_C_ExecuteUbergraph_ModItem, EntryPoint) == 0x000000, "Member 'ModItem_C_ExecuteUbergraph_ModItem::EntryPoint' has a wrong offset!");
static_assert(offsetof(ModItem_C_ExecuteUbergraph_ModItem, Temp_bool_Variable) == 0x000004, "Member 'ModItem_C_ExecuteUbergraph_ModItem::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(ModItem_C_ExecuteUbergraph_ModItem, CallFunc_IsAnimationPlaying_ReturnValue) == 0x000005, "Member 'ModItem_C_ExecuteUbergraph_ModItem::CallFunc_IsAnimationPlaying_ReturnValue' has a wrong offset!");
static_assert(offsetof(ModItem_C_ExecuteUbergraph_ModItem, Temp_struct_Variable) == 0x000008, "Member 'ModItem_C_ExecuteUbergraph_ModItem::Temp_struct_Variable' has a wrong offset!");
static_assert(offsetof(ModItem_C_ExecuteUbergraph_ModItem, Temp_struct_Variable_1) == 0x000018, "Member 'ModItem_C_ExecuteUbergraph_ModItem::Temp_struct_Variable_1' has a wrong offset!");
static_assert(offsetof(ModItem_C_ExecuteUbergraph_ModItem, Temp_bool_Variable_1) == 0x000028, "Member 'ModItem_C_ExecuteUbergraph_ModItem::Temp_bool_Variable_1' has a wrong offset!");
static_assert(offsetof(ModItem_C_ExecuteUbergraph_ModItem, K2Node_Select_Default) == 0x00002C, "Member 'ModItem_C_ExecuteUbergraph_ModItem::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(ModItem_C_ExecuteUbergraph_ModItem, Temp_struct_Variable_2) == 0x00003C, "Member 'ModItem_C_ExecuteUbergraph_ModItem::Temp_struct_Variable_2' has a wrong offset!");
static_assert(offsetof(ModItem_C_ExecuteUbergraph_ModItem, Temp_struct_Variable_3) == 0x00004C, "Member 'ModItem_C_ExecuteUbergraph_ModItem::Temp_struct_Variable_3' has a wrong offset!");
static_assert(offsetof(ModItem_C_ExecuteUbergraph_ModItem, K2Node_Select_Default_1) == 0x00005C, "Member 'ModItem_C_ExecuteUbergraph_ModItem::K2Node_Select_Default_1' has a wrong offset!");
static_assert(offsetof(ModItem_C_ExecuteUbergraph_ModItem, K2Node_CreateDelegate_OutputDelegate) == 0x00006C, "Member 'ModItem_C_ExecuteUbergraph_ModItem::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(ModItem_C_ExecuteUbergraph_ModItem, K2Node_CustomEvent_Texture_1) == 0x000080, "Member 'ModItem_C_ExecuteUbergraph_ModItem::K2Node_CustomEvent_Texture_1' has a wrong offset!");
static_assert(offsetof(ModItem_C_ExecuteUbergraph_ModItem, K2Node_CustomEvent_Texture) == 0x000088, "Member 'ModItem_C_ExecuteUbergraph_ModItem::K2Node_CustomEvent_Texture' has a wrong offset!");
static_assert(offsetof(ModItem_C_ExecuteUbergraph_ModItem, K2Node_CreateDelegate_OutputDelegate_1) == 0x000090, "Member 'ModItem_C_ExecuteUbergraph_ModItem::K2Node_CreateDelegate_OutputDelegate_1' has a wrong offset!");
static_assert(offsetof(ModItem_C_ExecuteUbergraph_ModItem, Temp_object_Variable) == 0x0000A0, "Member 'ModItem_C_ExecuteUbergraph_ModItem::Temp_object_Variable' has a wrong offset!");
static_assert(offsetof(ModItem_C_ExecuteUbergraph_ModItem, K2Node_Event_IsDesignTime) == 0x0000A8, "Member 'ModItem_C_ExecuteUbergraph_ModItem::K2Node_Event_IsDesignTime' has a wrong offset!");
static_assert(offsetof(ModItem_C_ExecuteUbergraph_ModItem, CallFunc_PlayAnimation_ReturnValue) == 0x0000B0, "Member 'ModItem_C_ExecuteUbergraph_ModItem::CallFunc_PlayAnimation_ReturnValue' has a wrong offset!");
static_assert(offsetof(ModItem_C_ExecuteUbergraph_ModItem, CallFunc_PlayAnimation_ReturnValue_1) == 0x0000B8, "Member 'ModItem_C_ExecuteUbergraph_ModItem::CallFunc_PlayAnimation_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(ModItem_C_ExecuteUbergraph_ModItem, CallFunc_DownloadImage_ReturnValue) == 0x0000C0, "Member 'ModItem_C_ExecuteUbergraph_ModItem::CallFunc_DownloadImage_ReturnValue' has a wrong offset!");
static_assert(offsetof(ModItem_C_ExecuteUbergraph_ModItem, CallFunc_IsValid_ReturnValue) == 0x0000C8, "Member 'ModItem_C_ExecuteUbergraph_ModItem::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(ModItem_C_ExecuteUbergraph_ModItem, K2Node_ComponentBoundEvent_bSelected) == 0x0000C9, "Member 'ModItem_C_ExecuteUbergraph_ModItem::K2Node_ComponentBoundEvent_bSelected' has a wrong offset!");
static_assert(offsetof(ModItem_C_ExecuteUbergraph_ModItem, K2Node_ComponentBoundEvent_Button) == 0x0000D0, "Member 'ModItem_C_ExecuteUbergraph_ModItem::K2Node_ComponentBoundEvent_Button' has a wrong offset!");

// Function ModItem.ModItem_C.BndEvt__ButtonLINK_K2Node_ComponentBoundEvent_119_OnClicked__DelegateSignature
// 0x0010 (0x0010 - 0x0000)
struct ModItem_C_BndEvt__ButtonLINK_K2Node_ComponentBoundEvent_119_OnClicked__DelegateSignature final
{
public:
	bool                                          bSelected;                                         // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_320C[0x7];                                     // 0x0001(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UMainMenu_Button_C*                     Button;                                            // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(ModItem_C_BndEvt__ButtonLINK_K2Node_ComponentBoundEvent_119_OnClicked__DelegateSignature) == 0x000008, "Wrong alignment on ModItem_C_BndEvt__ButtonLINK_K2Node_ComponentBoundEvent_119_OnClicked__DelegateSignature");
static_assert(sizeof(ModItem_C_BndEvt__ButtonLINK_K2Node_ComponentBoundEvent_119_OnClicked__DelegateSignature) == 0x000010, "Wrong size on ModItem_C_BndEvt__ButtonLINK_K2Node_ComponentBoundEvent_119_OnClicked__DelegateSignature");
static_assert(offsetof(ModItem_C_BndEvt__ButtonLINK_K2Node_ComponentBoundEvent_119_OnClicked__DelegateSignature, bSelected) == 0x000000, "Member 'ModItem_C_BndEvt__ButtonLINK_K2Node_ComponentBoundEvent_119_OnClicked__DelegateSignature::bSelected' has a wrong offset!");
static_assert(offsetof(ModItem_C_BndEvt__ButtonLINK_K2Node_ComponentBoundEvent_119_OnClicked__DelegateSignature, Button) == 0x000008, "Member 'ModItem_C_BndEvt__ButtonLINK_K2Node_ComponentBoundEvent_119_OnClicked__DelegateSignature::Button' has a wrong offset!");

// Function ModItem.ModItem_C.PreConstruct
// 0x0001 (0x0001 - 0x0000)
struct ModItem_C_PreConstruct final
{
public:
	bool                                          IsDesignTime;                                      // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(ModItem_C_PreConstruct) == 0x000001, "Wrong alignment on ModItem_C_PreConstruct");
static_assert(sizeof(ModItem_C_PreConstruct) == 0x000001, "Wrong size on ModItem_C_PreConstruct");
static_assert(offsetof(ModItem_C_PreConstruct, IsDesignTime) == 0x000000, "Member 'ModItem_C_PreConstruct::IsDesignTime' has a wrong offset!");

// Function ModItem.ModItem_C.OnSuccess_8A86417A45928AEC81E697912B573E34
// 0x0008 (0x0008 - 0x0000)
struct ModItem_C_OnSuccess_8A86417A45928AEC81E697912B573E34 final
{
public:
	class UTexture2DDynamic*                      Param_Texture;                                     // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(ModItem_C_OnSuccess_8A86417A45928AEC81E697912B573E34) == 0x000008, "Wrong alignment on ModItem_C_OnSuccess_8A86417A45928AEC81E697912B573E34");
static_assert(sizeof(ModItem_C_OnSuccess_8A86417A45928AEC81E697912B573E34) == 0x000008, "Wrong size on ModItem_C_OnSuccess_8A86417A45928AEC81E697912B573E34");
static_assert(offsetof(ModItem_C_OnSuccess_8A86417A45928AEC81E697912B573E34, Param_Texture) == 0x000000, "Member 'ModItem_C_OnSuccess_8A86417A45928AEC81E697912B573E34::Param_Texture' has a wrong offset!");

// Function ModItem.ModItem_C.OnFail_8A86417A45928AEC81E697912B573E34
// 0x0008 (0x0008 - 0x0000)
struct ModItem_C_OnFail_8A86417A45928AEC81E697912B573E34 final
{
public:
	class UTexture2DDynamic*                      Param_Texture;                                     // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(ModItem_C_OnFail_8A86417A45928AEC81E697912B573E34) == 0x000008, "Wrong alignment on ModItem_C_OnFail_8A86417A45928AEC81E697912B573E34");
static_assert(sizeof(ModItem_C_OnFail_8A86417A45928AEC81E697912B573E34) == 0x000008, "Wrong size on ModItem_C_OnFail_8A86417A45928AEC81E697912B573E34");
static_assert(offsetof(ModItem_C_OnFail_8A86417A45928AEC81E697912B573E34, Param_Texture) == 0x000000, "Member 'ModItem_C_OnFail_8A86417A45928AEC81E697912B573E34::Param_Texture' has a wrong offset!");

// Function ModItem.ModItem_C.Refresh Mod
// 0x0090 (0x0090 - 0x0000)
struct ModItem_C_Refresh_Mod final
{
public:
	int32                                         Temp_int_Array_Index_Variable;                     // 0x0000(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x0004(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0008(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_320D[0x4];                                     // 0x000C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UMod_DescriptionTooltip_C*              CallFunc_Create_ReturnValue;                       // 0x0010(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_MapRangeClamped_ReturnValue;              // 0x0018(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_320E[0x4];                                     // 0x001C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Conv_StringToText_ReturnValue;            // 0x0020(0x0018)()
	int32                                         CallFunc_FTrunc_ReturnValue;                       // 0x0038(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_LessEqual_IntInt_ReturnValue;             // 0x003C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_320F[0x3];                                     // 0x003D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Conv_StringToText_ReturnValue_1;          // 0x0040(0x0018)()
	struct FLinearColor                           CallFunc_SelectColor_ReturnValue;                  // 0x0058(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TArray<class UImage*>                         K2Node_MakeArray_Array;                            // 0x0068(0x0010)(ReferenceParm, ContainsInstancedReference)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x0078(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3210[0x4];                                     // 0x007C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UImage*                                 CallFunc_Array_Get_Item;                           // 0x0080(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x0088(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(ModItem_C_Refresh_Mod) == 0x000008, "Wrong alignment on ModItem_C_Refresh_Mod");
static_assert(sizeof(ModItem_C_Refresh_Mod) == 0x000090, "Wrong size on ModItem_C_Refresh_Mod");
static_assert(offsetof(ModItem_C_Refresh_Mod, Temp_int_Array_Index_Variable) == 0x000000, "Member 'ModItem_C_Refresh_Mod::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(ModItem_C_Refresh_Mod, Temp_int_Loop_Counter_Variable) == 0x000004, "Member 'ModItem_C_Refresh_Mod::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(ModItem_C_Refresh_Mod, CallFunc_Add_IntInt_ReturnValue) == 0x000008, "Member 'ModItem_C_Refresh_Mod::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(ModItem_C_Refresh_Mod, CallFunc_Create_ReturnValue) == 0x000010, "Member 'ModItem_C_Refresh_Mod::CallFunc_Create_ReturnValue' has a wrong offset!");
static_assert(offsetof(ModItem_C_Refresh_Mod, CallFunc_MapRangeClamped_ReturnValue) == 0x000018, "Member 'ModItem_C_Refresh_Mod::CallFunc_MapRangeClamped_ReturnValue' has a wrong offset!");
static_assert(offsetof(ModItem_C_Refresh_Mod, CallFunc_Conv_StringToText_ReturnValue) == 0x000020, "Member 'ModItem_C_Refresh_Mod::CallFunc_Conv_StringToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(ModItem_C_Refresh_Mod, CallFunc_FTrunc_ReturnValue) == 0x000038, "Member 'ModItem_C_Refresh_Mod::CallFunc_FTrunc_ReturnValue' has a wrong offset!");
static_assert(offsetof(ModItem_C_Refresh_Mod, CallFunc_LessEqual_IntInt_ReturnValue) == 0x00003C, "Member 'ModItem_C_Refresh_Mod::CallFunc_LessEqual_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(ModItem_C_Refresh_Mod, CallFunc_Conv_StringToText_ReturnValue_1) == 0x000040, "Member 'ModItem_C_Refresh_Mod::CallFunc_Conv_StringToText_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(ModItem_C_Refresh_Mod, CallFunc_SelectColor_ReturnValue) == 0x000058, "Member 'ModItem_C_Refresh_Mod::CallFunc_SelectColor_ReturnValue' has a wrong offset!");
static_assert(offsetof(ModItem_C_Refresh_Mod, K2Node_MakeArray_Array) == 0x000068, "Member 'ModItem_C_Refresh_Mod::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(ModItem_C_Refresh_Mod, CallFunc_Array_Length_ReturnValue) == 0x000078, "Member 'ModItem_C_Refresh_Mod::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(ModItem_C_Refresh_Mod, CallFunc_Array_Get_Item) == 0x000080, "Member 'ModItem_C_Refresh_Mod::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(ModItem_C_Refresh_Mod, CallFunc_Less_IntInt_ReturnValue) == 0x000088, "Member 'ModItem_C_Refresh_Mod::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");

}

