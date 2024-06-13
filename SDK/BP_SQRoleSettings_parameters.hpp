#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_SQRoleSettings

#include "Basic.hpp"

#include "SQRoleVersion_structs.hpp"
#include "SQRoleGroup_structs.hpp"
#include "FSQRoleEntry_structs.hpp"
#include "SQRoleGroupingStrategy_structs.hpp"
#include "SQRoleTags_structs.hpp"


namespace SDK::Params
{

// Function BP_SQRoleSettings.BP_SQRoleSettings_C.IsConcernedByStrategy
// 0x0108 (0x0108 - 0x0000)
struct BP_SQRoleSettings_C_IsConcernedByStrategy final
{
public:
	struct FSQRoleGroupingStrategy                InGroupingStrategy;                                // 0x0000(0x00A0)(BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)
	bool                                          Param_IsConcernedByStrategy;                       // 0x00A0(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4A28[0x7];                                     // 0x00A1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TSet<ESQRoleTags>                             CallFunc_Set_Intersection_Result;                  // 0x00A8(0x0050)()
	int32                                         CallFunc_Set_Length_ReturnValue;                   // 0x00F8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Set_Length_ReturnValue_1;                 // 0x00FC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_EqualEqual_IntInt_ReturnValue;            // 0x0100(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_IntInt_ReturnValue_1;          // 0x0101(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_SQRoleSettings_C_IsConcernedByStrategy) == 0x000008, "Wrong alignment on BP_SQRoleSettings_C_IsConcernedByStrategy");
static_assert(sizeof(BP_SQRoleSettings_C_IsConcernedByStrategy) == 0x000108, "Wrong size on BP_SQRoleSettings_C_IsConcernedByStrategy");
static_assert(offsetof(BP_SQRoleSettings_C_IsConcernedByStrategy, InGroupingStrategy) == 0x000000, "Member 'BP_SQRoleSettings_C_IsConcernedByStrategy::InGroupingStrategy' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_IsConcernedByStrategy, Param_IsConcernedByStrategy) == 0x0000A0, "Member 'BP_SQRoleSettings_C_IsConcernedByStrategy::Param_IsConcernedByStrategy' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_IsConcernedByStrategy, CallFunc_Set_Intersection_Result) == 0x0000A8, "Member 'BP_SQRoleSettings_C_IsConcernedByStrategy::CallFunc_Set_Intersection_Result' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_IsConcernedByStrategy, CallFunc_Set_Length_ReturnValue) == 0x0000F8, "Member 'BP_SQRoleSettings_C_IsConcernedByStrategy::CallFunc_Set_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_IsConcernedByStrategy, CallFunc_Set_Length_ReturnValue_1) == 0x0000FC, "Member 'BP_SQRoleSettings_C_IsConcernedByStrategy::CallFunc_Set_Length_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_IsConcernedByStrategy, CallFunc_EqualEqual_IntInt_ReturnValue) == 0x000100, "Member 'BP_SQRoleSettings_C_IsConcernedByStrategy::CallFunc_EqualEqual_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_IsConcernedByStrategy, CallFunc_EqualEqual_IntInt_ReturnValue_1) == 0x000101, "Member 'BP_SQRoleSettings_C_IsConcernedByStrategy::CallFunc_EqualEqual_IntInt_ReturnValue_1' has a wrong offset!");

// Function BP_SQRoleSettings.BP_SQRoleSettings_C.HasTag
// 0x0003 (0x0003 - 0x0000)
struct BP_SQRoleSettings_C_HasTag final
{
public:
	ESQRoleTags                                   In_Tag;                                            // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Out_Has_Tag;                                       // 0x0001(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Set_Contains_ReturnValue;                 // 0x0002(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_SQRoleSettings_C_HasTag) == 0x000001, "Wrong alignment on BP_SQRoleSettings_C_HasTag");
static_assert(sizeof(BP_SQRoleSettings_C_HasTag) == 0x000003, "Wrong size on BP_SQRoleSettings_C_HasTag");
static_assert(offsetof(BP_SQRoleSettings_C_HasTag, In_Tag) == 0x000000, "Member 'BP_SQRoleSettings_C_HasTag::In_Tag' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_HasTag, Out_Has_Tag) == 0x000001, "Member 'BP_SQRoleSettings_C_HasTag::Out_Has_Tag' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_HasTag, CallFunc_Set_Contains_ReturnValue) == 0x000002, "Member 'BP_SQRoleSettings_C_HasTag::CallFunc_Set_Contains_ReturnValue' has a wrong offset!");

// Function BP_SQRoleSettings.BP_SQRoleSettings_C.HasTags
// 0x0030 (0x0030 - 0x0000)
struct BP_SQRoleSettings_C_HasTags final
{
public:
	TArray<ESQRoleTags>                           In_Tags;                                           // 0x0000(0x0010)(BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
	bool                                          In_All;                                            // 0x0010(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          Out_Has_Tags;                                      // 0x0011(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4A29[0x2];                                     // 0x0012(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable;                     // 0x0018(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x001C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESQRoleTags                                   CallFunc_Array_Get_Item;                           // 0x0020(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x0021(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4A2A[0x2];                                     // 0x0022(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0024(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Set_Contains_ReturnValue;                 // 0x0028(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_SQRoleSettings_C_HasTags) == 0x000008, "Wrong alignment on BP_SQRoleSettings_C_HasTags");
static_assert(sizeof(BP_SQRoleSettings_C_HasTags) == 0x000030, "Wrong size on BP_SQRoleSettings_C_HasTags");
static_assert(offsetof(BP_SQRoleSettings_C_HasTags, In_Tags) == 0x000000, "Member 'BP_SQRoleSettings_C_HasTags::In_Tags' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_HasTags, In_All) == 0x000010, "Member 'BP_SQRoleSettings_C_HasTags::In_All' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_HasTags, Out_Has_Tags) == 0x000011, "Member 'BP_SQRoleSettings_C_HasTags::Out_Has_Tags' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_HasTags, CallFunc_Array_Length_ReturnValue) == 0x000014, "Member 'BP_SQRoleSettings_C_HasTags::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_HasTags, Temp_int_Array_Index_Variable) == 0x000018, "Member 'BP_SQRoleSettings_C_HasTags::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_HasTags, Temp_int_Loop_Counter_Variable) == 0x00001C, "Member 'BP_SQRoleSettings_C_HasTags::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_HasTags, CallFunc_Array_Get_Item) == 0x000020, "Member 'BP_SQRoleSettings_C_HasTags::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_HasTags, CallFunc_Less_IntInt_ReturnValue) == 0x000021, "Member 'BP_SQRoleSettings_C_HasTags::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_HasTags, CallFunc_Add_IntInt_ReturnValue) == 0x000024, "Member 'BP_SQRoleSettings_C_HasTags::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_HasTags, CallFunc_Set_Contains_ReturnValue) == 0x000028, "Member 'BP_SQRoleSettings_C_HasTags::CallFunc_Set_Contains_ReturnValue' has a wrong offset!");

// Function BP_SQRoleSettings.BP_SQRoleSettings_C.GetGroup
// 0x0004 (0x0004 - 0x0000)
struct BP_SQRoleSettings_C_GetGroup final
{
public:
	ESQRoleGroup                                  Out_Group;                                         // 0x0000(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_HasTag_Out_Has_Tag;                       // 0x0001(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_HasTag_Out_Has_Tag_1;                     // 0x0002(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_HasTag_Out_Has_Tag_2;                     // 0x0003(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_SQRoleSettings_C_GetGroup) == 0x000001, "Wrong alignment on BP_SQRoleSettings_C_GetGroup");
static_assert(sizeof(BP_SQRoleSettings_C_GetGroup) == 0x000004, "Wrong size on BP_SQRoleSettings_C_GetGroup");
static_assert(offsetof(BP_SQRoleSettings_C_GetGroup, Out_Group) == 0x000000, "Member 'BP_SQRoleSettings_C_GetGroup::Out_Group' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_GetGroup, CallFunc_HasTag_Out_Has_Tag) == 0x000001, "Member 'BP_SQRoleSettings_C_GetGroup::CallFunc_HasTag_Out_Has_Tag' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_GetGroup, CallFunc_HasTag_Out_Has_Tag_1) == 0x000002, "Member 'BP_SQRoleSettings_C_GetGroup::CallFunc_HasTag_Out_Has_Tag_1' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_GetGroup, CallFunc_HasTag_Out_Has_Tag_2) == 0x000003, "Member 'BP_SQRoleSettings_C_GetGroup::CallFunc_HasTag_Out_Has_Tag_2' has a wrong offset!");

// Function BP_SQRoleSettings.BP_SQRoleSettings_C.GetRoleEntry
// 0x0190 (0x0190 - 0x0000)
struct BP_SQRoleSettings_C_GetRoleEntry final
{
public:
	bool                                          Success;                                           // 0x0000(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4A2B[0x7];                                     // 0x0001(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FFSQRoleEntry                          RoleEntry;                                         // 0x0008(0x00C0)(Parm, OutParm, HasGetValueTypeHash)
	struct FFSQRoleEntry                          CallFunc_GetDataTableRowFromName_OutRow;           // 0x00C8(0x00C0)(HasGetValueTypeHash)
	bool                                          CallFunc_GetDataTableRowFromName_ReturnValue;      // 0x0188(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_SQRoleSettings_C_GetRoleEntry) == 0x000008, "Wrong alignment on BP_SQRoleSettings_C_GetRoleEntry");
static_assert(sizeof(BP_SQRoleSettings_C_GetRoleEntry) == 0x000190, "Wrong size on BP_SQRoleSettings_C_GetRoleEntry");
static_assert(offsetof(BP_SQRoleSettings_C_GetRoleEntry, Success) == 0x000000, "Member 'BP_SQRoleSettings_C_GetRoleEntry::Success' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_GetRoleEntry, RoleEntry) == 0x000008, "Member 'BP_SQRoleSettings_C_GetRoleEntry::RoleEntry' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_GetRoleEntry, CallFunc_GetDataTableRowFromName_OutRow) == 0x0000C8, "Member 'BP_SQRoleSettings_C_GetRoleEntry::CallFunc_GetDataTableRowFromName_OutRow' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_GetRoleEntry, CallFunc_GetDataTableRowFromName_ReturnValue) == 0x000188, "Member 'BP_SQRoleSettings_C_GetRoleEntry::CallFunc_GetDataTableRowFromName_ReturnValue' has a wrong offset!");

// Function BP_SQRoleSettings.BP_SQRoleSettings_C.CanPlaceRallyPointWithMinimumTeamMate
// 0x0004 (0x0004 - 0x0000)
struct BP_SQRoleSettings_C_CanPlaceRallyPointWithMinimumTeamMate final
{
public:
	bool                                          ReturnValue;                                       // 0x0000(0x0001)(Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsSquadLeader_ReturnValue;                // 0x0001(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_ByteByte_ReturnValue;          // 0x0002(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue;                   // 0x0003(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_SQRoleSettings_C_CanPlaceRallyPointWithMinimumTeamMate) == 0x000001, "Wrong alignment on BP_SQRoleSettings_C_CanPlaceRallyPointWithMinimumTeamMate");
static_assert(sizeof(BP_SQRoleSettings_C_CanPlaceRallyPointWithMinimumTeamMate) == 0x000004, "Wrong size on BP_SQRoleSettings_C_CanPlaceRallyPointWithMinimumTeamMate");
static_assert(offsetof(BP_SQRoleSettings_C_CanPlaceRallyPointWithMinimumTeamMate, ReturnValue) == 0x000000, "Member 'BP_SQRoleSettings_C_CanPlaceRallyPointWithMinimumTeamMate::ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_CanPlaceRallyPointWithMinimumTeamMate, CallFunc_IsSquadLeader_ReturnValue) == 0x000001, "Member 'BP_SQRoleSettings_C_CanPlaceRallyPointWithMinimumTeamMate::CallFunc_IsSquadLeader_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_CanPlaceRallyPointWithMinimumTeamMate, CallFunc_EqualEqual_ByteByte_ReturnValue) == 0x000002, "Member 'BP_SQRoleSettings_C_CanPlaceRallyPointWithMinimumTeamMate::CallFunc_EqualEqual_ByteByte_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_CanPlaceRallyPointWithMinimumTeamMate, CallFunc_BooleanAND_ReturnValue) == 0x000003, "Member 'BP_SQRoleSettings_C_CanPlaceRallyPointWithMinimumTeamMate::CallFunc_BooleanAND_ReturnValue' has a wrong offset!");

// Function BP_SQRoleSettings.BP_SQRoleSettings_C.CanSeeHealthStatus
// 0x0003 (0x0003 - 0x0000)
struct BP_SQRoleSettings_C_CanSeeHealthStatus final
{
public:
	bool                                          ReturnValue;                                       // 0x0000(0x0001)(Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)
	ESQRoleTags                                   Temp_byte_Variable;                                // 0x0001(0x0001)(ConstParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Set_Contains_ReturnValue;                 // 0x0002(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_SQRoleSettings_C_CanSeeHealthStatus) == 0x000001, "Wrong alignment on BP_SQRoleSettings_C_CanSeeHealthStatus");
static_assert(sizeof(BP_SQRoleSettings_C_CanSeeHealthStatus) == 0x000003, "Wrong size on BP_SQRoleSettings_C_CanSeeHealthStatus");
static_assert(offsetof(BP_SQRoleSettings_C_CanSeeHealthStatus, ReturnValue) == 0x000000, "Member 'BP_SQRoleSettings_C_CanSeeHealthStatus::ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_CanSeeHealthStatus, Temp_byte_Variable) == 0x000001, "Member 'BP_SQRoleSettings_C_CanSeeHealthStatus::Temp_byte_Variable' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_CanSeeHealthStatus, CallFunc_Set_Contains_ReturnValue) == 0x000002, "Member 'BP_SQRoleSettings_C_CanSeeHealthStatus::CallFunc_Set_Contains_ReturnValue' has a wrong offset!");

// Function BP_SQRoleSettings.BP_SQRoleSettings_C.IsMedic
// 0x0003 (0x0003 - 0x0000)
struct BP_SQRoleSettings_C_IsMedic final
{
public:
	bool                                          ReturnValue;                                       // 0x0000(0x0001)(Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)
	ESQRoleTags                                   Temp_byte_Variable;                                // 0x0001(0x0001)(ConstParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Set_Contains_ReturnValue;                 // 0x0002(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_SQRoleSettings_C_IsMedic) == 0x000001, "Wrong alignment on BP_SQRoleSettings_C_IsMedic");
static_assert(sizeof(BP_SQRoleSettings_C_IsMedic) == 0x000003, "Wrong size on BP_SQRoleSettings_C_IsMedic");
static_assert(offsetof(BP_SQRoleSettings_C_IsMedic, ReturnValue) == 0x000000, "Member 'BP_SQRoleSettings_C_IsMedic::ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_IsMedic, Temp_byte_Variable) == 0x000001, "Member 'BP_SQRoleSettings_C_IsMedic::Temp_byte_Variable' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_IsMedic, CallFunc_Set_Contains_ReturnValue) == 0x000002, "Member 'BP_SQRoleSettings_C_IsMedic::CallFunc_Set_Contains_ReturnValue' has a wrong offset!");

// Function BP_SQRoleSettings.BP_SQRoleSettings_C.IsSquadLeader
// 0x0003 (0x0003 - 0x0000)
struct BP_SQRoleSettings_C_IsSquadLeader final
{
public:
	bool                                          ReturnValue;                                       // 0x0000(0x0001)(Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)
	ESQRoleTags                                   Temp_byte_Variable;                                // 0x0001(0x0001)(ConstParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Set_Contains_ReturnValue;                 // 0x0002(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_SQRoleSettings_C_IsSquadLeader) == 0x000001, "Wrong alignment on BP_SQRoleSettings_C_IsSquadLeader");
static_assert(sizeof(BP_SQRoleSettings_C_IsSquadLeader) == 0x000003, "Wrong size on BP_SQRoleSettings_C_IsSquadLeader");
static_assert(offsetof(BP_SQRoleSettings_C_IsSquadLeader, ReturnValue) == 0x000000, "Member 'BP_SQRoleSettings_C_IsSquadLeader::ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_IsSquadLeader, Temp_byte_Variable) == 0x000001, "Member 'BP_SQRoleSettings_C_IsSquadLeader::Temp_byte_Variable' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_IsSquadLeader, CallFunc_Set_Contains_ReturnValue) == 0x000002, "Member 'BP_SQRoleSettings_C_IsSquadLeader::CallFunc_Set_Contains_ReturnValue' has a wrong offset!");

// Function BP_SQRoleSettings.BP_SQRoleSettings_C.IsRecruit
// 0x0003 (0x0003 - 0x0000)
struct BP_SQRoleSettings_C_IsRecruit final
{
public:
	bool                                          Out_IsRecruit;                                     // 0x0000(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	ESQRoleTags                                   Temp_byte_Variable;                                // 0x0001(0x0001)(ConstParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Set_Contains_ReturnValue;                 // 0x0002(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_SQRoleSettings_C_IsRecruit) == 0x000001, "Wrong alignment on BP_SQRoleSettings_C_IsRecruit");
static_assert(sizeof(BP_SQRoleSettings_C_IsRecruit) == 0x000003, "Wrong size on BP_SQRoleSettings_C_IsRecruit");
static_assert(offsetof(BP_SQRoleSettings_C_IsRecruit, Out_IsRecruit) == 0x000000, "Member 'BP_SQRoleSettings_C_IsRecruit::Out_IsRecruit' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_IsRecruit, Temp_byte_Variable) == 0x000001, "Member 'BP_SQRoleSettings_C_IsRecruit::Temp_byte_Variable' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_IsRecruit, CallFunc_Set_Contains_ReturnValue) == 0x000002, "Member 'BP_SQRoleSettings_C_IsRecruit::CallFunc_Set_Contains_ReturnValue' has a wrong offset!");

// Function BP_SQRoleSettings.BP_SQRoleSettings_C.CanEnterSeat
// 0x0010 (0x0010 - 0x0000)
struct BP_SQRoleSettings_C_CanEnterSeat final
{
public:
	class USQVehicleSeatComponent*                Seat;                                              // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          ReturnValue;                                       // 0x0008(0x0001)(Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_ByteByte_ReturnValue;          // 0x0009(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_SwitchEnum_CmpSuccess;                      // 0x000A(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_ByteByte_ReturnValue_1;        // 0x000B(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_SQRoleSettings_C_CanEnterSeat) == 0x000008, "Wrong alignment on BP_SQRoleSettings_C_CanEnterSeat");
static_assert(sizeof(BP_SQRoleSettings_C_CanEnterSeat) == 0x000010, "Wrong size on BP_SQRoleSettings_C_CanEnterSeat");
static_assert(offsetof(BP_SQRoleSettings_C_CanEnterSeat, Seat) == 0x000000, "Member 'BP_SQRoleSettings_C_CanEnterSeat::Seat' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_CanEnterSeat, ReturnValue) == 0x000008, "Member 'BP_SQRoleSettings_C_CanEnterSeat::ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_CanEnterSeat, CallFunc_EqualEqual_ByteByte_ReturnValue) == 0x000009, "Member 'BP_SQRoleSettings_C_CanEnterSeat::CallFunc_EqualEqual_ByteByte_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_CanEnterSeat, K2Node_SwitchEnum_CmpSuccess) == 0x00000A, "Member 'BP_SQRoleSettings_C_CanEnterSeat::K2Node_SwitchEnum_CmpSuccess' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_CanEnterSeat, CallFunc_EqualEqual_ByteByte_ReturnValue_1) == 0x00000B, "Member 'BP_SQRoleSettings_C_CanEnterSeat::CallFunc_EqualEqual_ByteByte_ReturnValue_1' has a wrong offset!");

// Function BP_SQRoleSettings.BP_SQRoleSettings_C.TryGetSoldierWithLayer
// 0x00E0 (0x00E0 - 0x0000)
struct BP_SQRoleSettings_C_TryGetSoldierWithLayer final
{
public:
	const class USQLayer*                         InLayer;                                           // 0x0000(0x0008)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TSoftClassPtr<class UClass>                   OutSoldier;                                        // 0x0008(0x0028)(Parm, OutParm, UObjectWrapper, HasGetValueTypeHash)
	bool                                          ReturnValue;                                       // 0x0030(0x0001)(Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4A2C[0x7];                                     // 0x0031(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<TSoftClassPtr<class UClass>>           MatchingRoles;                                     // 0x0038(0x0010)(Edit, BlueprintVisible)
	int32                                         Temp_int_Array_Index_Variable;                     // 0x0048(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x004C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4A2D[0x3];                                     // 0x004D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_SQLevel_C*                          K2Node_DynamicCast_AsBP_SQLevel;                   // 0x0050(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0058(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4A2E[0x3];                                     // 0x0059(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x005C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0060(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x0064(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_RandomInteger_ReturnValue;                // 0x0068(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Greater_IntInt_ReturnValue;               // 0x006C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_IntInt_ReturnValue;            // 0x006D(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4A2F[0x2];                                     // 0x006E(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_SelectInt_ReturnValue;                    // 0x0070(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4A30[0x4];                                     // 0x0074(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	TSoftClassPtr<class UClass>                   CallFunc_Array_Get_Item;                           // 0x0078(0x0028)(HasGetValueTypeHash)
	struct FSQRoleVersion                         CallFunc_Array_Get_Item_1;                         // 0x00A0(0x0030)(HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue_1;               // 0x00D0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x00D4(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4A31[0x3];                                     // 0x00D5(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Array_Add_ReturnValue;                    // 0x00D8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_EqualEqual_ByteByte_ReturnValue;          // 0x00DC(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_SQRoleSettings_C_TryGetSoldierWithLayer) == 0x000008, "Wrong alignment on BP_SQRoleSettings_C_TryGetSoldierWithLayer");
static_assert(sizeof(BP_SQRoleSettings_C_TryGetSoldierWithLayer) == 0x0000E0, "Wrong size on BP_SQRoleSettings_C_TryGetSoldierWithLayer");
static_assert(offsetof(BP_SQRoleSettings_C_TryGetSoldierWithLayer, InLayer) == 0x000000, "Member 'BP_SQRoleSettings_C_TryGetSoldierWithLayer::InLayer' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_TryGetSoldierWithLayer, OutSoldier) == 0x000008, "Member 'BP_SQRoleSettings_C_TryGetSoldierWithLayer::OutSoldier' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_TryGetSoldierWithLayer, ReturnValue) == 0x000030, "Member 'BP_SQRoleSettings_C_TryGetSoldierWithLayer::ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_TryGetSoldierWithLayer, MatchingRoles) == 0x000038, "Member 'BP_SQRoleSettings_C_TryGetSoldierWithLayer::MatchingRoles' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_TryGetSoldierWithLayer, Temp_int_Array_Index_Variable) == 0x000048, "Member 'BP_SQRoleSettings_C_TryGetSoldierWithLayer::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_TryGetSoldierWithLayer, CallFunc_IsValid_ReturnValue) == 0x00004C, "Member 'BP_SQRoleSettings_C_TryGetSoldierWithLayer::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_TryGetSoldierWithLayer, K2Node_DynamicCast_AsBP_SQLevel) == 0x000050, "Member 'BP_SQRoleSettings_C_TryGetSoldierWithLayer::K2Node_DynamicCast_AsBP_SQLevel' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_TryGetSoldierWithLayer, K2Node_DynamicCast_bSuccess) == 0x000058, "Member 'BP_SQRoleSettings_C_TryGetSoldierWithLayer::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_TryGetSoldierWithLayer, Temp_int_Loop_Counter_Variable) == 0x00005C, "Member 'BP_SQRoleSettings_C_TryGetSoldierWithLayer::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_TryGetSoldierWithLayer, CallFunc_Add_IntInt_ReturnValue) == 0x000060, "Member 'BP_SQRoleSettings_C_TryGetSoldierWithLayer::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_TryGetSoldierWithLayer, CallFunc_Array_Length_ReturnValue) == 0x000064, "Member 'BP_SQRoleSettings_C_TryGetSoldierWithLayer::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_TryGetSoldierWithLayer, CallFunc_RandomInteger_ReturnValue) == 0x000068, "Member 'BP_SQRoleSettings_C_TryGetSoldierWithLayer::CallFunc_RandomInteger_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_TryGetSoldierWithLayer, CallFunc_Greater_IntInt_ReturnValue) == 0x00006C, "Member 'BP_SQRoleSettings_C_TryGetSoldierWithLayer::CallFunc_Greater_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_TryGetSoldierWithLayer, CallFunc_EqualEqual_IntInt_ReturnValue) == 0x00006D, "Member 'BP_SQRoleSettings_C_TryGetSoldierWithLayer::CallFunc_EqualEqual_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_TryGetSoldierWithLayer, CallFunc_SelectInt_ReturnValue) == 0x000070, "Member 'BP_SQRoleSettings_C_TryGetSoldierWithLayer::CallFunc_SelectInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_TryGetSoldierWithLayer, CallFunc_Array_Get_Item) == 0x000078, "Member 'BP_SQRoleSettings_C_TryGetSoldierWithLayer::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_TryGetSoldierWithLayer, CallFunc_Array_Get_Item_1) == 0x0000A0, "Member 'BP_SQRoleSettings_C_TryGetSoldierWithLayer::CallFunc_Array_Get_Item_1' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_TryGetSoldierWithLayer, CallFunc_Array_Length_ReturnValue_1) == 0x0000D0, "Member 'BP_SQRoleSettings_C_TryGetSoldierWithLayer::CallFunc_Array_Length_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_TryGetSoldierWithLayer, CallFunc_Less_IntInt_ReturnValue) == 0x0000D4, "Member 'BP_SQRoleSettings_C_TryGetSoldierWithLayer::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_TryGetSoldierWithLayer, CallFunc_Array_Add_ReturnValue) == 0x0000D8, "Member 'BP_SQRoleSettings_C_TryGetSoldierWithLayer::CallFunc_Array_Add_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_TryGetSoldierWithLayer, CallFunc_EqualEqual_ByteByte_ReturnValue) == 0x0000DC, "Member 'BP_SQRoleSettings_C_TryGetSoldierWithLayer::CallFunc_EqualEqual_ByteByte_ReturnValue' has a wrong offset!");

// Function BP_SQRoleSettings.BP_SQRoleSettings_C.GetRoleDisplayName
// 0x0108 (0x0108 - 0x0000)
struct BP_SQRoleSettings_C_GetRoleDisplayName final
{
public:
	class FString                                 CurrentRoleDisplayName;                            // 0x0000(0x0010)(Parm, OutParm, ZeroConstructor, HasGetValueTypeHash)
	struct FFSQRoleEntry                          RoleEntry;                                         // 0x0010(0x00C0)(Edit, BlueprintVisible, HasGetValueTypeHash)
	class FName                                   RowName;                                           // 0x00D0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UDataTable*                             DataTable;                                         // 0x00D8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FString                                 RoleName;                                          // 0x00E0(0x0010)(Edit, BlueprintVisible, ZeroConstructor, HasGetValueTypeHash)
	bool                                          CallFunc_NotEqual_NameName_ReturnValue;            // 0x00F0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4A32[0x7];                                     // 0x00F1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FString                                 CallFunc_Conv_NameToString_ReturnValue;            // 0x00F8(0x0010)(ZeroConstructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_SQRoleSettings_C_GetRoleDisplayName) == 0x000008, "Wrong alignment on BP_SQRoleSettings_C_GetRoleDisplayName");
static_assert(sizeof(BP_SQRoleSettings_C_GetRoleDisplayName) == 0x000108, "Wrong size on BP_SQRoleSettings_C_GetRoleDisplayName");
static_assert(offsetof(BP_SQRoleSettings_C_GetRoleDisplayName, CurrentRoleDisplayName) == 0x000000, "Member 'BP_SQRoleSettings_C_GetRoleDisplayName::CurrentRoleDisplayName' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_GetRoleDisplayName, RoleEntry) == 0x000010, "Member 'BP_SQRoleSettings_C_GetRoleDisplayName::RoleEntry' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_GetRoleDisplayName, RowName) == 0x0000D0, "Member 'BP_SQRoleSettings_C_GetRoleDisplayName::RowName' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_GetRoleDisplayName, DataTable) == 0x0000D8, "Member 'BP_SQRoleSettings_C_GetRoleDisplayName::DataTable' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_GetRoleDisplayName, RoleName) == 0x0000E0, "Member 'BP_SQRoleSettings_C_GetRoleDisplayName::RoleName' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_GetRoleDisplayName, CallFunc_NotEqual_NameName_ReturnValue) == 0x0000F0, "Member 'BP_SQRoleSettings_C_GetRoleDisplayName::CallFunc_NotEqual_NameName_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQRoleSettings_C_GetRoleDisplayName, CallFunc_Conv_NameToString_ReturnValue) == 0x0000F8, "Member 'BP_SQRoleSettings_C_GetRoleDisplayName::CallFunc_Conv_NameToString_ReturnValue' has a wrong offset!");

}

