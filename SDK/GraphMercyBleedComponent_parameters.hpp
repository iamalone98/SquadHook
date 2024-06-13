#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: GraphMercyBleedComponent

#include "Basic.hpp"


namespace SDK::Params
{

// Function GraphMercyBleedComponent.GraphMercyBleedComponent_C.ExecuteUbergraph_GraphMercyBleedComponent
// 0x0058 (0x0058 - 0x0000)
struct GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2DF6[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class AActor*                                 CallFunc_GetOwner_ReturnValue;                     // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_HasAuthority_ReturnValue;                 // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2DF7[0x3];                                     // 0x0011(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate;              // 0x0014(0x0010)(ZeroConstructor, NoDestructor)
	uint8                                         Pad_2DF8[0x4];                                     // 0x0024(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class AActor*                                 CallFunc_GetOwner_ReturnValue_1;                   // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQUndirectedGraph*                     K2Node_DynamicCast_AsSQUndirected_Graph;           // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2DF9[0x3];                                     // 0x0039(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         K2Node_Event_DeltaSeconds;                         // 0x003C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetComponentTickInterval_ReturnValue;     // 0x0040(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_NotEqual_FloatFloat_ReturnValue;          // 0x0044(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2DFA[0x3];                                     // 0x0045(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class AActor*                                 CallFunc_GetOwner_ReturnValue_2;                   // 0x0048(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_HasAuthority_ReturnValue_1;               // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent) == 0x000008, "Wrong alignment on GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent");
static_assert(sizeof(GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent) == 0x000058, "Wrong size on GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent");
static_assert(offsetof(GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent, EntryPoint) == 0x000000, "Member 'GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent::EntryPoint' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent, CallFunc_GetOwner_ReturnValue) == 0x000008, "Member 'GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent::CallFunc_GetOwner_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent, CallFunc_HasAuthority_ReturnValue) == 0x000010, "Member 'GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent::CallFunc_HasAuthority_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent, K2Node_CreateDelegate_OutputDelegate) == 0x000014, "Member 'GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent, CallFunc_GetOwner_ReturnValue_1) == 0x000028, "Member 'GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent::CallFunc_GetOwner_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent, K2Node_DynamicCast_AsSQUndirected_Graph) == 0x000030, "Member 'GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent::K2Node_DynamicCast_AsSQUndirected_Graph' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent, K2Node_DynamicCast_bSuccess) == 0x000038, "Member 'GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent, K2Node_Event_DeltaSeconds) == 0x00003C, "Member 'GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent::K2Node_Event_DeltaSeconds' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent, CallFunc_GetComponentTickInterval_ReturnValue) == 0x000040, "Member 'GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent::CallFunc_GetComponentTickInterval_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent, CallFunc_NotEqual_FloatFloat_ReturnValue) == 0x000044, "Member 'GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent::CallFunc_NotEqual_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent, CallFunc_GetOwner_ReturnValue_2) == 0x000048, "Member 'GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent::CallFunc_GetOwner_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent, CallFunc_HasAuthority_ReturnValue_1) == 0x000050, "Member 'GraphMercyBleedComponent_C_ExecuteUbergraph_GraphMercyBleedComponent::CallFunc_HasAuthority_ReturnValue_1' has a wrong offset!");

// Function GraphMercyBleedComponent.GraphMercyBleedComponent_C.ReceiveTick
// 0x0004 (0x0004 - 0x0000)
struct GraphMercyBleedComponent_C_ReceiveTick final
{
public:
	float                                         DeltaSeconds;                                      // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(GraphMercyBleedComponent_C_ReceiveTick) == 0x000004, "Wrong alignment on GraphMercyBleedComponent_C_ReceiveTick");
static_assert(sizeof(GraphMercyBleedComponent_C_ReceiveTick) == 0x000004, "Wrong size on GraphMercyBleedComponent_C_ReceiveTick");
static_assert(offsetof(GraphMercyBleedComponent_C_ReceiveTick, DeltaSeconds) == 0x000000, "Member 'GraphMercyBleedComponent_C_ReceiveTick::DeltaSeconds' has a wrong offset!");

// Function GraphMercyBleedComponent.GraphMercyBleedComponent_C.TickBleed
// 0x0058 (0x0058 - 0x0000)
struct GraphMercyBleedComponent_C_TickBleed final
{
public:
	int32                                         CachedTickets;                                     // 0x0000(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x0004(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0008(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable;                     // 0x000C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_Variable;                                // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2DFB[0x3];                                     // 0x0011(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Greater_IntInt_ReturnValue;               // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2DFC[0x7];                                     // 0x0019(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQGameState*                           CallFunc_GetSquadGameState_Return_Value;           // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue_1;               // 0x0028(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2DFD[0x4];                                     // 0x002C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQTeamState*                           CallFunc_Array_Get_Item;                           // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2DFE[0x3];                                     // 0x0039(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_GetTickets_ReturnValue;                   // 0x003C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0040(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Array_Contains_ReturnValue;               // 0x0041(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2DFF[0x2];                                     // 0x0042(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         K2Node_Select_Default;                             // 0x0044(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue_1;                 // 0x0048(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_NotEqual_IntInt_ReturnValue;              // 0x004C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2E00[0x3];                                     // 0x004D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Clamp_ReturnValue;                        // 0x0050(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(GraphMercyBleedComponent_C_TickBleed) == 0x000008, "Wrong alignment on GraphMercyBleedComponent_C_TickBleed");
static_assert(sizeof(GraphMercyBleedComponent_C_TickBleed) == 0x000058, "Wrong size on GraphMercyBleedComponent_C_TickBleed");
static_assert(offsetof(GraphMercyBleedComponent_C_TickBleed, CachedTickets) == 0x000000, "Member 'GraphMercyBleedComponent_C_TickBleed::CachedTickets' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_TickBleed, Temp_int_Loop_Counter_Variable) == 0x000004, "Member 'GraphMercyBleedComponent_C_TickBleed::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_TickBleed, CallFunc_Add_IntInt_ReturnValue) == 0x000008, "Member 'GraphMercyBleedComponent_C_TickBleed::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_TickBleed, Temp_int_Array_Index_Variable) == 0x00000C, "Member 'GraphMercyBleedComponent_C_TickBleed::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_TickBleed, Temp_bool_Variable) == 0x000010, "Member 'GraphMercyBleedComponent_C_TickBleed::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_TickBleed, CallFunc_Array_Length_ReturnValue) == 0x000014, "Member 'GraphMercyBleedComponent_C_TickBleed::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_TickBleed, CallFunc_Greater_IntInt_ReturnValue) == 0x000018, "Member 'GraphMercyBleedComponent_C_TickBleed::CallFunc_Greater_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_TickBleed, CallFunc_GetSquadGameState_Return_Value) == 0x000020, "Member 'GraphMercyBleedComponent_C_TickBleed::CallFunc_GetSquadGameState_Return_Value' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_TickBleed, CallFunc_Array_Length_ReturnValue_1) == 0x000028, "Member 'GraphMercyBleedComponent_C_TickBleed::CallFunc_Array_Length_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_TickBleed, CallFunc_Array_Get_Item) == 0x000030, "Member 'GraphMercyBleedComponent_C_TickBleed::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_TickBleed, CallFunc_Less_IntInt_ReturnValue) == 0x000038, "Member 'GraphMercyBleedComponent_C_TickBleed::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_TickBleed, CallFunc_GetTickets_ReturnValue) == 0x00003C, "Member 'GraphMercyBleedComponent_C_TickBleed::CallFunc_GetTickets_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_TickBleed, CallFunc_IsValid_ReturnValue) == 0x000040, "Member 'GraphMercyBleedComponent_C_TickBleed::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_TickBleed, CallFunc_Array_Contains_ReturnValue) == 0x000041, "Member 'GraphMercyBleedComponent_C_TickBleed::CallFunc_Array_Contains_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_TickBleed, K2Node_Select_Default) == 0x000044, "Member 'GraphMercyBleedComponent_C_TickBleed::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_TickBleed, CallFunc_Add_IntInt_ReturnValue_1) == 0x000048, "Member 'GraphMercyBleedComponent_C_TickBleed::CallFunc_Add_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_TickBleed, CallFunc_NotEqual_IntInt_ReturnValue) == 0x00004C, "Member 'GraphMercyBleedComponent_C_TickBleed::CallFunc_NotEqual_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_TickBleed, CallFunc_Clamp_ReturnValue) == 0x000050, "Member 'GraphMercyBleedComponent_C_TickBleed::CallFunc_Clamp_ReturnValue' has a wrong offset!");

// Function GraphMercyBleedComponent.GraphMercyBleedComponent_C.CountCaptureZonesByTeam
// 0x0078 (0x0078 - 0x0000)
struct GraphMercyBleedComponent_C_CountCaptureZonesByTeam final
{
public:
	TArray<class USQGraphNodeComponent*>          Nodes;                                             // 0x0000(0x0010)(Edit, BlueprintVisible, ContainsInstancedReference)
	int32                                         Temp_int_Variable;                                 // 0x0010(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable_1;                  // 0x0018(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x001C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue_1;                 // 0x0020(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable;                     // 0x0024(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable_1;                   // 0x0028(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_MakeLiteralInt_ReturnValue;               // 0x002C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x0030(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2E01[0x4];                                     // 0x0034(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class USQGraphNodeComponent*                  CallFunc_Array_Get_Item;                           // 0x0038(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x0040(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2E02[0x7];                                     // 0x0041(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class USQCaptureZoneComponent*                K2Node_DynamicCast_AsSQCapture_Zone_Component;     // 0x0048(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2E03[0x3];                                     // 0x0051(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Conv_ByteToInt_ReturnValue;               // 0x0054(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue_1;               // 0x0058(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue_1;                // 0x005C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2E04[0x3];                                     // 0x005D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class AActor*                                 CallFunc_GetOwner_ReturnValue;                     // 0x0060(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQUndirectedGraph*                     K2Node_DynamicCast_AsSQUndirected_Graph;           // 0x0068(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0070(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Array_IsValidIndex_ReturnValue;           // 0x0071(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2E05[0x2];                                     // 0x0072(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Add_IntInt_ReturnValue_2;                 // 0x0074(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(GraphMercyBleedComponent_C_CountCaptureZonesByTeam) == 0x000008, "Wrong alignment on GraphMercyBleedComponent_C_CountCaptureZonesByTeam");
static_assert(sizeof(GraphMercyBleedComponent_C_CountCaptureZonesByTeam) == 0x000078, "Wrong size on GraphMercyBleedComponent_C_CountCaptureZonesByTeam");
static_assert(offsetof(GraphMercyBleedComponent_C_CountCaptureZonesByTeam, Nodes) == 0x000000, "Member 'GraphMercyBleedComponent_C_CountCaptureZonesByTeam::Nodes' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_CountCaptureZonesByTeam, Temp_int_Variable) == 0x000010, "Member 'GraphMercyBleedComponent_C_CountCaptureZonesByTeam::Temp_int_Variable' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_CountCaptureZonesByTeam, Temp_int_Loop_Counter_Variable) == 0x000014, "Member 'GraphMercyBleedComponent_C_CountCaptureZonesByTeam::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_CountCaptureZonesByTeam, Temp_int_Loop_Counter_Variable_1) == 0x000018, "Member 'GraphMercyBleedComponent_C_CountCaptureZonesByTeam::Temp_int_Loop_Counter_Variable_1' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_CountCaptureZonesByTeam, CallFunc_Add_IntInt_ReturnValue) == 0x00001C, "Member 'GraphMercyBleedComponent_C_CountCaptureZonesByTeam::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_CountCaptureZonesByTeam, CallFunc_Add_IntInt_ReturnValue_1) == 0x000020, "Member 'GraphMercyBleedComponent_C_CountCaptureZonesByTeam::CallFunc_Add_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_CountCaptureZonesByTeam, Temp_int_Array_Index_Variable) == 0x000024, "Member 'GraphMercyBleedComponent_C_CountCaptureZonesByTeam::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_CountCaptureZonesByTeam, Temp_int_Array_Index_Variable_1) == 0x000028, "Member 'GraphMercyBleedComponent_C_CountCaptureZonesByTeam::Temp_int_Array_Index_Variable_1' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_CountCaptureZonesByTeam, CallFunc_MakeLiteralInt_ReturnValue) == 0x00002C, "Member 'GraphMercyBleedComponent_C_CountCaptureZonesByTeam::CallFunc_MakeLiteralInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_CountCaptureZonesByTeam, CallFunc_Array_Length_ReturnValue) == 0x000030, "Member 'GraphMercyBleedComponent_C_CountCaptureZonesByTeam::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_CountCaptureZonesByTeam, CallFunc_Array_Get_Item) == 0x000038, "Member 'GraphMercyBleedComponent_C_CountCaptureZonesByTeam::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_CountCaptureZonesByTeam, CallFunc_Less_IntInt_ReturnValue) == 0x000040, "Member 'GraphMercyBleedComponent_C_CountCaptureZonesByTeam::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_CountCaptureZonesByTeam, K2Node_DynamicCast_AsSQCapture_Zone_Component) == 0x000048, "Member 'GraphMercyBleedComponent_C_CountCaptureZonesByTeam::K2Node_DynamicCast_AsSQCapture_Zone_Component' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_CountCaptureZonesByTeam, K2Node_DynamicCast_bSuccess) == 0x000050, "Member 'GraphMercyBleedComponent_C_CountCaptureZonesByTeam::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_CountCaptureZonesByTeam, CallFunc_Conv_ByteToInt_ReturnValue) == 0x000054, "Member 'GraphMercyBleedComponent_C_CountCaptureZonesByTeam::CallFunc_Conv_ByteToInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_CountCaptureZonesByTeam, CallFunc_Array_Length_ReturnValue_1) == 0x000058, "Member 'GraphMercyBleedComponent_C_CountCaptureZonesByTeam::CallFunc_Array_Length_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_CountCaptureZonesByTeam, CallFunc_Less_IntInt_ReturnValue_1) == 0x00005C, "Member 'GraphMercyBleedComponent_C_CountCaptureZonesByTeam::CallFunc_Less_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_CountCaptureZonesByTeam, CallFunc_GetOwner_ReturnValue) == 0x000060, "Member 'GraphMercyBleedComponent_C_CountCaptureZonesByTeam::CallFunc_GetOwner_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_CountCaptureZonesByTeam, K2Node_DynamicCast_AsSQUndirected_Graph) == 0x000068, "Member 'GraphMercyBleedComponent_C_CountCaptureZonesByTeam::K2Node_DynamicCast_AsSQUndirected_Graph' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_CountCaptureZonesByTeam, K2Node_DynamicCast_bSuccess_1) == 0x000070, "Member 'GraphMercyBleedComponent_C_CountCaptureZonesByTeam::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_CountCaptureZonesByTeam, CallFunc_Array_IsValidIndex_ReturnValue) == 0x000071, "Member 'GraphMercyBleedComponent_C_CountCaptureZonesByTeam::CallFunc_Array_IsValidIndex_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_CountCaptureZonesByTeam, CallFunc_Add_IntInt_ReturnValue_2) == 0x000074, "Member 'GraphMercyBleedComponent_C_CountCaptureZonesByTeam::CallFunc_Add_IntInt_ReturnValue_2' has a wrong offset!");

// Function GraphMercyBleedComponent.GraphMercyBleedComponent_C.FindLosers
// 0x001C (0x001C - 0x0000)
struct GraphMercyBleedComponent_C_FindLosers final
{
public:
	int32                                         Temp_int_Variable;                                 // 0x0000(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0004(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Add_ReturnValue;                    // 0x0008(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsLoser_ReturnValue;                      // 0x000C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_IntInt_ReturnValue;            // 0x000D(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Array_IsValidIndex_ReturnValue;           // 0x000E(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2E06[0x1];                                     // 0x000F(0x0001)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x0010(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Subtract_IntInt_ReturnValue;              // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_LessEqual_IntInt_ReturnValue;             // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(GraphMercyBleedComponent_C_FindLosers) == 0x000004, "Wrong alignment on GraphMercyBleedComponent_C_FindLosers");
static_assert(sizeof(GraphMercyBleedComponent_C_FindLosers) == 0x00001C, "Wrong size on GraphMercyBleedComponent_C_FindLosers");
static_assert(offsetof(GraphMercyBleedComponent_C_FindLosers, Temp_int_Variable) == 0x000000, "Member 'GraphMercyBleedComponent_C_FindLosers::Temp_int_Variable' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_FindLosers, CallFunc_Add_IntInt_ReturnValue) == 0x000004, "Member 'GraphMercyBleedComponent_C_FindLosers::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_FindLosers, CallFunc_Array_Add_ReturnValue) == 0x000008, "Member 'GraphMercyBleedComponent_C_FindLosers::CallFunc_Array_Add_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_FindLosers, CallFunc_IsLoser_ReturnValue) == 0x00000C, "Member 'GraphMercyBleedComponent_C_FindLosers::CallFunc_IsLoser_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_FindLosers, CallFunc_EqualEqual_IntInt_ReturnValue) == 0x00000D, "Member 'GraphMercyBleedComponent_C_FindLosers::CallFunc_EqualEqual_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_FindLosers, CallFunc_Array_IsValidIndex_ReturnValue) == 0x00000E, "Member 'GraphMercyBleedComponent_C_FindLosers::CallFunc_Array_IsValidIndex_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_FindLosers, CallFunc_Array_Length_ReturnValue) == 0x000010, "Member 'GraphMercyBleedComponent_C_FindLosers::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_FindLosers, CallFunc_Subtract_IntInt_ReturnValue) == 0x000014, "Member 'GraphMercyBleedComponent_C_FindLosers::CallFunc_Subtract_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_FindLosers, CallFunc_LessEqual_IntInt_ReturnValue) == 0x000018, "Member 'GraphMercyBleedComponent_C_FindLosers::CallFunc_LessEqual_IntInt_ReturnValue' has a wrong offset!");

// Function GraphMercyBleedComponent.GraphMercyBleedComponent_C.IsLoser
// 0x000C (0x000C - 0x0000)
struct GraphMercyBleedComponent_C_IsLoser final
{
public:
	int32                                         CaptureZones;                                      // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Team;                                              // 0x0004(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          ReturnValue;                                       // 0x0008(0x0001)(Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_IntInt_ReturnValue;            // 0x0009(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(GraphMercyBleedComponent_C_IsLoser) == 0x000004, "Wrong alignment on GraphMercyBleedComponent_C_IsLoser");
static_assert(sizeof(GraphMercyBleedComponent_C_IsLoser) == 0x00000C, "Wrong size on GraphMercyBleedComponent_C_IsLoser");
static_assert(offsetof(GraphMercyBleedComponent_C_IsLoser, CaptureZones) == 0x000000, "Member 'GraphMercyBleedComponent_C_IsLoser::CaptureZones' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_IsLoser, Team) == 0x000004, "Member 'GraphMercyBleedComponent_C_IsLoser::Team' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_IsLoser, ReturnValue) == 0x000008, "Member 'GraphMercyBleedComponent_C_IsLoser::ReturnValue' has a wrong offset!");
static_assert(offsetof(GraphMercyBleedComponent_C_IsLoser, CallFunc_EqualEqual_IntInt_ReturnValue) == 0x000009, "Member 'GraphMercyBleedComponent_C_IsLoser::CallFunc_EqualEqual_IntInt_ReturnValue' has a wrong offset!");

}

