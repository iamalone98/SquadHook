#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_FlagCapturedEvent

#include "Basic.hpp"

#include "CoreUObject_structs.hpp"
#include "SlateCore_structs.hpp"


namespace SDK::Params
{

// Function W_FlagCapturedEvent.W_FlagCapturedEvent_C.ExecuteUbergraph_W_FlagCapturedEvent
// 0x00B0 (0x00B0 - 0x0000)
struct W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4966[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   K2Node_CustomEvent_Flag_Name;                      // 0x0008(0x0018)()
	uint8                                         K2Node_CustomEvent_New_Owning_Team;                // 0x0020(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         K2Node_CustomEvent_Last_Owning_Team;               // 0x0021(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4967[0x6];                                     // 0x0022(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class UMaterialInstanceDynamic*               CallFunc_GetDynamicMaterial_ReturnValue;           // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FText                                   CallFunc_TextToUpper_ReturnValue;                  // 0x0030(0x0018)()
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x0048(0x0038)(IsPlainOldData, NoDestructor)
	float                                         K2Node_Event_InDeltaTime;                          // 0x0080(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetAnimationCurrentTime_ReturnValue;      // 0x0084(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsAnimationPlaying_ReturnValue;           // 0x0088(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4968[0x3];                                     // 0x0089(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Add_FloatFloat_ReturnValue;               // 0x008C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue;            // 0x0090(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_FClamp_ReturnValue;                       // 0x0094(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetEndTime_ReturnValue;                   // 0x0098(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4969[0x4];                                     // 0x009C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UUMGSequencePlayer*                     CallFunc_PlayAnimation_ReturnValue;                // 0x00A0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Add_FloatFloat_ReturnValue_1;             // 0x00A8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent) == 0x000008, "Wrong alignment on W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent");
static_assert(sizeof(W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent) == 0x0000B0, "Wrong size on W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent");
static_assert(offsetof(W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent, EntryPoint) == 0x000000, "Member 'W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent, K2Node_CustomEvent_Flag_Name) == 0x000008, "Member 'W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent::K2Node_CustomEvent_Flag_Name' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent, K2Node_CustomEvent_New_Owning_Team) == 0x000020, "Member 'W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent::K2Node_CustomEvent_New_Owning_Team' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent, K2Node_CustomEvent_Last_Owning_Team) == 0x000021, "Member 'W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent::K2Node_CustomEvent_Last_Owning_Team' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent, CallFunc_GetDynamicMaterial_ReturnValue) == 0x000028, "Member 'W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent::CallFunc_GetDynamicMaterial_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent, CallFunc_TextToUpper_ReturnValue) == 0x000030, "Member 'W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent::CallFunc_TextToUpper_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent, K2Node_Event_MyGeometry) == 0x000048, "Member 'W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent, K2Node_Event_InDeltaTime) == 0x000080, "Member 'W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent::K2Node_Event_InDeltaTime' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent, CallFunc_GetAnimationCurrentTime_ReturnValue) == 0x000084, "Member 'W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent::CallFunc_GetAnimationCurrentTime_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent, CallFunc_IsAnimationPlaying_ReturnValue) == 0x000088, "Member 'W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent::CallFunc_IsAnimationPlaying_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent, CallFunc_Add_FloatFloat_ReturnValue) == 0x00008C, "Member 'W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent::CallFunc_Add_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent, CallFunc_Divide_FloatFloat_ReturnValue) == 0x000090, "Member 'W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent::CallFunc_Divide_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent, CallFunc_FClamp_ReturnValue) == 0x000094, "Member 'W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent::CallFunc_FClamp_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent, CallFunc_GetEndTime_ReturnValue) == 0x000098, "Member 'W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent::CallFunc_GetEndTime_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent, CallFunc_PlayAnimation_ReturnValue) == 0x0000A0, "Member 'W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent::CallFunc_PlayAnimation_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent, CallFunc_Add_FloatFloat_ReturnValue_1) == 0x0000A8, "Member 'W_FlagCapturedEvent_C_ExecuteUbergraph_W_FlagCapturedEvent::CallFunc_Add_FloatFloat_ReturnValue_1' has a wrong offset!");

// Function W_FlagCapturedEvent.W_FlagCapturedEvent_C.Tick
// 0x003C (0x003C - 0x0000)
struct W_FlagCapturedEvent_C_Tick final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	float                                         InDeltaTime;                                       // 0x0038(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_FlagCapturedEvent_C_Tick) == 0x000004, "Wrong alignment on W_FlagCapturedEvent_C_Tick");
static_assert(sizeof(W_FlagCapturedEvent_C_Tick) == 0x00003C, "Wrong size on W_FlagCapturedEvent_C_Tick");
static_assert(offsetof(W_FlagCapturedEvent_C_Tick, MyGeometry) == 0x000000, "Member 'W_FlagCapturedEvent_C_Tick::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Tick, InDeltaTime) == 0x000038, "Member 'W_FlagCapturedEvent_C_Tick::InDeltaTime' has a wrong offset!");

// Function W_FlagCapturedEvent.W_FlagCapturedEvent_C.Play Capture Animation
// 0x0020 (0x0020 - 0x0000)
struct W_FlagCapturedEvent_C_Play_Capture_Animation final
{
public:
	class FText                                   Flag_Name;                                         // 0x0000(0x0018)(BlueprintVisible, BlueprintReadOnly, Parm)
	uint8                                         New_Owning_Team;                                   // 0x0018(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Last_Owning_Team;                                  // 0x0019(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_FlagCapturedEvent_C_Play_Capture_Animation) == 0x000008, "Wrong alignment on W_FlagCapturedEvent_C_Play_Capture_Animation");
static_assert(sizeof(W_FlagCapturedEvent_C_Play_Capture_Animation) == 0x000020, "Wrong size on W_FlagCapturedEvent_C_Play_Capture_Animation");
static_assert(offsetof(W_FlagCapturedEvent_C_Play_Capture_Animation, Flag_Name) == 0x000000, "Member 'W_FlagCapturedEvent_C_Play_Capture_Animation::Flag_Name' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Play_Capture_Animation, New_Owning_Team) == 0x000018, "Member 'W_FlagCapturedEvent_C_Play_Capture_Animation::New_Owning_Team' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Play_Capture_Animation, Last_Owning_Team) == 0x000019, "Member 'W_FlagCapturedEvent_C_Play_Capture_Animation::Last_Owning_Team' has a wrong offset!");

// Function W_FlagCapturedEvent.W_FlagCapturedEvent_C.Setup Fill Image
// 0x0038 (0x0038 - 0x0000)
struct W_FlagCapturedEvent_C_Setup_Fill_Image final
{
public:
	class ASQPlayerController*                    CallFunc_GetSquadPlayerController_Return_Value;    // 0x0000(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_GetTeam_ReturnValue;                      // 0x0008(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_EqualEqual_ByteByte_ReturnValue;          // 0x000C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         CallFunc_Conv_IntToByte_ReturnValue;               // 0x000D(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_EqualEqual_ByteByte_ReturnValue_1;        // 0x000E(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_496A[0x1];                                     // 0x000F(0x0001)(Fixing Size After Last Property [ Dumper-7 ])
	class UUMGSequencePlayer*                     CallFunc_PlayAnimation_ReturnValue;                // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           CallFunc_SelectColor_ReturnValue;                  // 0x0018(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           CallFunc_SelectColor_ReturnValue_1;                // 0x0028(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_FlagCapturedEvent_C_Setup_Fill_Image) == 0x000008, "Wrong alignment on W_FlagCapturedEvent_C_Setup_Fill_Image");
static_assert(sizeof(W_FlagCapturedEvent_C_Setup_Fill_Image) == 0x000038, "Wrong size on W_FlagCapturedEvent_C_Setup_Fill_Image");
static_assert(offsetof(W_FlagCapturedEvent_C_Setup_Fill_Image, CallFunc_GetSquadPlayerController_Return_Value) == 0x000000, "Member 'W_FlagCapturedEvent_C_Setup_Fill_Image::CallFunc_GetSquadPlayerController_Return_Value' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Setup_Fill_Image, CallFunc_GetTeam_ReturnValue) == 0x000008, "Member 'W_FlagCapturedEvent_C_Setup_Fill_Image::CallFunc_GetTeam_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Setup_Fill_Image, CallFunc_EqualEqual_ByteByte_ReturnValue) == 0x00000C, "Member 'W_FlagCapturedEvent_C_Setup_Fill_Image::CallFunc_EqualEqual_ByteByte_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Setup_Fill_Image, CallFunc_Conv_IntToByte_ReturnValue) == 0x00000D, "Member 'W_FlagCapturedEvent_C_Setup_Fill_Image::CallFunc_Conv_IntToByte_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Setup_Fill_Image, CallFunc_EqualEqual_ByteByte_ReturnValue_1) == 0x00000E, "Member 'W_FlagCapturedEvent_C_Setup_Fill_Image::CallFunc_EqualEqual_ByteByte_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Setup_Fill_Image, CallFunc_PlayAnimation_ReturnValue) == 0x000010, "Member 'W_FlagCapturedEvent_C_Setup_Fill_Image::CallFunc_PlayAnimation_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Setup_Fill_Image, CallFunc_SelectColor_ReturnValue) == 0x000018, "Member 'W_FlagCapturedEvent_C_Setup_Fill_Image::CallFunc_SelectColor_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Setup_Fill_Image, CallFunc_SelectColor_ReturnValue_1) == 0x000028, "Member 'W_FlagCapturedEvent_C_Setup_Fill_Image::CallFunc_SelectColor_ReturnValue_1' has a wrong offset!");

// Function W_FlagCapturedEvent.W_FlagCapturedEvent_C.Set State Text
// 0x00A0 (0x00A0 - 0x0000)
struct W_FlagCapturedEvent_C_Set_State_Text final
{
public:
	bool                                          Temp_bool_Variable;                                // 0x0000(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_496B[0x7];                                     // 0x0001(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   Temp_text_Variable;                                // 0x0008(0x0018)()
	class FText                                   Temp_text_Variable_1;                              // 0x0020(0x0018)()
	bool                                          Temp_bool_Variable_1;                              // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_496C[0x7];                                     // 0x0039(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   Temp_text_Variable_2;                              // 0x0040(0x0018)()
	bool                                          CallFunc_EqualEqual_ByteByte_ReturnValue;          // 0x0058(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_496D[0x7];                                     // 0x0059(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQPlayerController*                    CallFunc_GetSquadPlayerController_Return_Value;    // 0x0060(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_GetTeam_ReturnValue;                      // 0x0068(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         CallFunc_Conv_IntToByte_ReturnValue;               // 0x006C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_EqualEqual_ByteByte_ReturnValue_1;        // 0x006D(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_496E[0x2];                                     // 0x006E(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   K2Node_Select_Default;                             // 0x0070(0x0018)()
	class FText                                   K2Node_Select_Default_1;                           // 0x0088(0x0018)()
};
static_assert(alignof(W_FlagCapturedEvent_C_Set_State_Text) == 0x000008, "Wrong alignment on W_FlagCapturedEvent_C_Set_State_Text");
static_assert(sizeof(W_FlagCapturedEvent_C_Set_State_Text) == 0x0000A0, "Wrong size on W_FlagCapturedEvent_C_Set_State_Text");
static_assert(offsetof(W_FlagCapturedEvent_C_Set_State_Text, Temp_bool_Variable) == 0x000000, "Member 'W_FlagCapturedEvent_C_Set_State_Text::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Set_State_Text, Temp_text_Variable) == 0x000008, "Member 'W_FlagCapturedEvent_C_Set_State_Text::Temp_text_Variable' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Set_State_Text, Temp_text_Variable_1) == 0x000020, "Member 'W_FlagCapturedEvent_C_Set_State_Text::Temp_text_Variable_1' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Set_State_Text, Temp_bool_Variable_1) == 0x000038, "Member 'W_FlagCapturedEvent_C_Set_State_Text::Temp_bool_Variable_1' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Set_State_Text, Temp_text_Variable_2) == 0x000040, "Member 'W_FlagCapturedEvent_C_Set_State_Text::Temp_text_Variable_2' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Set_State_Text, CallFunc_EqualEqual_ByteByte_ReturnValue) == 0x000058, "Member 'W_FlagCapturedEvent_C_Set_State_Text::CallFunc_EqualEqual_ByteByte_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Set_State_Text, CallFunc_GetSquadPlayerController_Return_Value) == 0x000060, "Member 'W_FlagCapturedEvent_C_Set_State_Text::CallFunc_GetSquadPlayerController_Return_Value' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Set_State_Text, CallFunc_GetTeam_ReturnValue) == 0x000068, "Member 'W_FlagCapturedEvent_C_Set_State_Text::CallFunc_GetTeam_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Set_State_Text, CallFunc_Conv_IntToByte_ReturnValue) == 0x00006C, "Member 'W_FlagCapturedEvent_C_Set_State_Text::CallFunc_Conv_IntToByte_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Set_State_Text, CallFunc_EqualEqual_ByteByte_ReturnValue_1) == 0x00006D, "Member 'W_FlagCapturedEvent_C_Set_State_Text::CallFunc_EqualEqual_ByteByte_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Set_State_Text, K2Node_Select_Default) == 0x000070, "Member 'W_FlagCapturedEvent_C_Set_State_Text::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Set_State_Text, K2Node_Select_Default_1) == 0x000088, "Member 'W_FlagCapturedEvent_C_Set_State_Text::K2Node_Select_Default_1' has a wrong offset!");

// Function W_FlagCapturedEvent.W_FlagCapturedEvent_C.Set Owner Flag Image
// 0x0058 (0x0058 - 0x0000)
struct W_FlagCapturedEvent_C_Set_Owner_Flag_Image final
{
public:
	int32                                         CallFunc_Conv_ByteToInt_ReturnValue;               // 0x0000(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_496F[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQGameState*                           CallFunc_GetSquadGameState_Return_Value;           // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4970[0x7];                                     // 0x0011(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQTeamState*                           CallFunc_Array_Get_Item;                           // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQFaction*                             CallFunc_GetFaction_ReturnValue;                   // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TSoftObjectPtr<class UTexture2D>              CallFunc_TryGetFlagForMap_OutTexture;              // 0x0028(0x0028)(UObjectWrapper, HasGetValueTypeHash)
	bool                                          CallFunc_TryGetFlagForMap_ReturnValue;             // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_FlagCapturedEvent_C_Set_Owner_Flag_Image) == 0x000008, "Wrong alignment on W_FlagCapturedEvent_C_Set_Owner_Flag_Image");
static_assert(sizeof(W_FlagCapturedEvent_C_Set_Owner_Flag_Image) == 0x000058, "Wrong size on W_FlagCapturedEvent_C_Set_Owner_Flag_Image");
static_assert(offsetof(W_FlagCapturedEvent_C_Set_Owner_Flag_Image, CallFunc_Conv_ByteToInt_ReturnValue) == 0x000000, "Member 'W_FlagCapturedEvent_C_Set_Owner_Flag_Image::CallFunc_Conv_ByteToInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Set_Owner_Flag_Image, CallFunc_GetSquadGameState_Return_Value) == 0x000008, "Member 'W_FlagCapturedEvent_C_Set_Owner_Flag_Image::CallFunc_GetSquadGameState_Return_Value' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Set_Owner_Flag_Image, CallFunc_IsValid_ReturnValue) == 0x000010, "Member 'W_FlagCapturedEvent_C_Set_Owner_Flag_Image::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Set_Owner_Flag_Image, CallFunc_Array_Get_Item) == 0x000018, "Member 'W_FlagCapturedEvent_C_Set_Owner_Flag_Image::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Set_Owner_Flag_Image, CallFunc_GetFaction_ReturnValue) == 0x000020, "Member 'W_FlagCapturedEvent_C_Set_Owner_Flag_Image::CallFunc_GetFaction_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Set_Owner_Flag_Image, CallFunc_TryGetFlagForMap_OutTexture) == 0x000028, "Member 'W_FlagCapturedEvent_C_Set_Owner_Flag_Image::CallFunc_TryGetFlagForMap_OutTexture' has a wrong offset!");
static_assert(offsetof(W_FlagCapturedEvent_C_Set_Owner_Flag_Image, CallFunc_TryGetFlagForMap_ReturnValue) == 0x000050, "Member 'W_FlagCapturedEvent_C_Set_Owner_Flag_Image::CallFunc_TryGetFlagForMap_ReturnValue' has a wrong offset!");

}
