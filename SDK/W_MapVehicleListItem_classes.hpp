#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_MapVehicleListItem

#include "Basic.hpp"

#include "S_VehicleListData_structs.hpp"
#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "UMG_structs.hpp"
#include "UMG_classes.hpp"
#include "ESQIntelligence_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_MapVehicleListItem.W_MapVehicleListItem_C
// 0x0150 (0x03B0 - 0x0260)
class UW_MapVehicleListItem_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UImage*                                 AmphibiousIcon;                                    // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UScaleBox*                              AmphibiousScaleBox;                                // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USizeBox*                               Area_Count;                                        // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USizeBox*                               Area_Tickets;                                      // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USizeBox*                               Area_Timer;                                        // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Icon;                                              // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Available;                                      // 0x0298(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Name;                                           // 0x02A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Slash;                                          // 0x02A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Specifics;                                      // 0x02B0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Tickets;                                        // 0x02B8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Timer;                                          // 0x02C0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Used;                                           // 0x02C8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	struct FS_VehicleListData                     Vehicle_List_Data;                                 // 0x02D0(0x0090)(Edit, BlueprintVisible, ContainsInstancedReference, ExposeOnSpawn, HasGetValueTypeHash)
	bool                                          Enemy;                                             // 0x0360(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn)
	uint8                                         Pad_4367[0x3];                                     // 0x0361(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         LocalPlayerTeamId;                                 // 0x0364(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	int32                                         CachedUsed;                                        // 0x0368(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CachedAvailable;                                   // 0x036C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FDateTime                              Cached_NextAvailable;                              // 0x0370(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, NoDestructor, HasGetValueTypeHash)
	struct FDataTableRowHandle                    CachedReason;                                      // 0x0378(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance, NoDestructor)
	class FText                                   TimerText;                                         // 0x0388(0x0018)(Edit, BlueprintVisible, DisableEditOnInstance)
	bool                                          IsSingleUse;                                       // 0x03A0(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4368[0x7];                                     // 0x03A1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTimerHandle                           UpdateTimerHandle;                                 // 0x03A8(0x0008)(Edit, BlueprintVisible, DisableEditOnInstance, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_W_MapVehicleListItem(int32 EntryPoint);
	void Construct();
	void UpdateStatus(const struct FSQAvailabilityState_Vehicle& State);
	void UpdateTimer();
	void GetDefaultSpawnDelay(struct FTimespan* Delay);
	void UpdateUsed(int32 Used);
	void UpdateAvailable(int32 Available, class USQAvailability* Target);
	void UpdateDelay(const struct FDateTime& NextAvailability);
	void UpdateUnavailabilityReason(const struct FDataTableRowHandle& Reason);
	void ShouldShowDetails(ESQIntelligence Intel, bool* ShowDetails);
	void GetNextAvailabilityTimer(class FText* OutText);
	void HasTimer(bool* Param_HasTimer);
	void UpdateCollapsing(int32 In_ModifierPct, bool* Out_Collapsed);
	void ToHumanReadableTime(const struct FTimespan& InTimespan, class FText* Result);
	void Init_Delay(bool* Out_Should_Update_Timer);
	void Finalize_Layout();
	void UpdateDepletedSingleUse(class USQAvailability* In_Availability, const struct FSQAvailabilityState& In_State);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_MapVehicleListItem_C">();
	}
	static class UW_MapVehicleListItem_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_MapVehicleListItem_C>();
	}
};
static_assert(alignof(UW_MapVehicleListItem_C) == 0x000008, "Wrong alignment on UW_MapVehicleListItem_C");
static_assert(sizeof(UW_MapVehicleListItem_C) == 0x0003B0, "Wrong size on UW_MapVehicleListItem_C");
static_assert(offsetof(UW_MapVehicleListItem_C, UberGraphFrame) == 0x000260, "Member 'UW_MapVehicleListItem_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_MapVehicleListItem_C, AmphibiousIcon) == 0x000268, "Member 'UW_MapVehicleListItem_C::AmphibiousIcon' has a wrong offset!");
static_assert(offsetof(UW_MapVehicleListItem_C, AmphibiousScaleBox) == 0x000270, "Member 'UW_MapVehicleListItem_C::AmphibiousScaleBox' has a wrong offset!");
static_assert(offsetof(UW_MapVehicleListItem_C, Area_Count) == 0x000278, "Member 'UW_MapVehicleListItem_C::Area_Count' has a wrong offset!");
static_assert(offsetof(UW_MapVehicleListItem_C, Area_Tickets) == 0x000280, "Member 'UW_MapVehicleListItem_C::Area_Tickets' has a wrong offset!");
static_assert(offsetof(UW_MapVehicleListItem_C, Area_Timer) == 0x000288, "Member 'UW_MapVehicleListItem_C::Area_Timer' has a wrong offset!");
static_assert(offsetof(UW_MapVehicleListItem_C, Icon) == 0x000290, "Member 'UW_MapVehicleListItem_C::Icon' has a wrong offset!");
static_assert(offsetof(UW_MapVehicleListItem_C, TB_Available) == 0x000298, "Member 'UW_MapVehicleListItem_C::TB_Available' has a wrong offset!");
static_assert(offsetof(UW_MapVehicleListItem_C, TB_Name) == 0x0002A0, "Member 'UW_MapVehicleListItem_C::TB_Name' has a wrong offset!");
static_assert(offsetof(UW_MapVehicleListItem_C, TB_Slash) == 0x0002A8, "Member 'UW_MapVehicleListItem_C::TB_Slash' has a wrong offset!");
static_assert(offsetof(UW_MapVehicleListItem_C, TB_Specifics) == 0x0002B0, "Member 'UW_MapVehicleListItem_C::TB_Specifics' has a wrong offset!");
static_assert(offsetof(UW_MapVehicleListItem_C, TB_Tickets) == 0x0002B8, "Member 'UW_MapVehicleListItem_C::TB_Tickets' has a wrong offset!");
static_assert(offsetof(UW_MapVehicleListItem_C, TB_Timer) == 0x0002C0, "Member 'UW_MapVehicleListItem_C::TB_Timer' has a wrong offset!");
static_assert(offsetof(UW_MapVehicleListItem_C, TB_Used) == 0x0002C8, "Member 'UW_MapVehicleListItem_C::TB_Used' has a wrong offset!");
static_assert(offsetof(UW_MapVehicleListItem_C, Vehicle_List_Data) == 0x0002D0, "Member 'UW_MapVehicleListItem_C::Vehicle_List_Data' has a wrong offset!");
static_assert(offsetof(UW_MapVehicleListItem_C, Enemy) == 0x000360, "Member 'UW_MapVehicleListItem_C::Enemy' has a wrong offset!");
static_assert(offsetof(UW_MapVehicleListItem_C, LocalPlayerTeamId) == 0x000364, "Member 'UW_MapVehicleListItem_C::LocalPlayerTeamId' has a wrong offset!");
static_assert(offsetof(UW_MapVehicleListItem_C, CachedUsed) == 0x000368, "Member 'UW_MapVehicleListItem_C::CachedUsed' has a wrong offset!");
static_assert(offsetof(UW_MapVehicleListItem_C, CachedAvailable) == 0x00036C, "Member 'UW_MapVehicleListItem_C::CachedAvailable' has a wrong offset!");
static_assert(offsetof(UW_MapVehicleListItem_C, Cached_NextAvailable) == 0x000370, "Member 'UW_MapVehicleListItem_C::Cached_NextAvailable' has a wrong offset!");
static_assert(offsetof(UW_MapVehicleListItem_C, CachedReason) == 0x000378, "Member 'UW_MapVehicleListItem_C::CachedReason' has a wrong offset!");
static_assert(offsetof(UW_MapVehicleListItem_C, TimerText) == 0x000388, "Member 'UW_MapVehicleListItem_C::TimerText' has a wrong offset!");
static_assert(offsetof(UW_MapVehicleListItem_C, IsSingleUse) == 0x0003A0, "Member 'UW_MapVehicleListItem_C::IsSingleUse' has a wrong offset!");
static_assert(offsetof(UW_MapVehicleListItem_C, UpdateTimerHandle) == 0x0003A8, "Member 'UW_MapVehicleListItem_C::UpdateTimerHandle' has a wrong offset!");

}

