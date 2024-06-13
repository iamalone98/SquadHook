#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_SQLevel

#include "Basic.hpp"

#include "ESQBiome_structs.hpp"
#include "SQETheatersOfOperations_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_SQLevel.BP_SQLevel_C
// 0x0008 (0x00B8 - 0x00B0)
class UBP_SQLevel_C final : public USQLevel
{
public:
	ESQBiome                                      Biome;                                             // 0x00B0(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESQETheatersOfOperations                      TheaterOfOperations;                               // 0x00B1(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void TryGetLevelEntry(bool* Success, struct FSQLevelEntry* LevelEntry) const;
	bool TryGetLoadingScreen(TSoftObjectPtr<class UTexture2D>* OutLoadingScreen, const struct FVector2D& InViewportSize) const;
	bool TryGetDescription(class FText* OutDescription) const;
	bool TryGetDisplayName(class FText* OutDisplayName) const;
	bool TryGetLoadingMusic(class USoundBase** OutLoadingMusic) const;
	bool CanFactionOperate(class USQFactionSetup* FactionSetup, class USQLayer* Layer) const;
	class FName GetBiomeId() const;

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_SQLevel_C">();
	}
	static class UBP_SQLevel_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_SQLevel_C>();
	}
};
static_assert(alignof(UBP_SQLevel_C) == 0x000008, "Wrong alignment on UBP_SQLevel_C");
static_assert(sizeof(UBP_SQLevel_C) == 0x0000B8, "Wrong size on UBP_SQLevel_C");
static_assert(offsetof(UBP_SQLevel_C, Biome) == 0x0000B0, "Member 'UBP_SQLevel_C::Biome' has a wrong offset!");
static_assert(offsetof(UBP_SQLevel_C, TheaterOfOperations) == 0x0000B1, "Member 'UBP_SQLevel_C::TheaterOfOperations' has a wrong offset!");

}

