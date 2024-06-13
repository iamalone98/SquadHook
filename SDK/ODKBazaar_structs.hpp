#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: ODKBazaar

#include "Basic.hpp"


namespace SDK
{

// Enum ODKBazaar.EBundleCategory
// NumValues: 0x0004
enum class EBundleCategory : uint8
{
	All                                      = 0,
	WeaponSkins                              = 1,
	Emotes                                   = 2,
	EBundleCategory_MAX                      = 3,
};

// Enum ODKBazaar.EBazaarProvider
// NumValues: 0x0005
enum class EBazaarProvider : uint8
{
	Debug                                    = 0,
	Steam                                    = 1,
	PlayFab                                  = 2,
	Multi                                    = 3,
	EBazaarProvider_MAX                      = 4,
};

// Enum ODKBazaar.EODKItemSourceTypes
// NumValues: 0x0007
enum class EODKItemSourceTypes : uint8
{
	None                                     = 0,
	Free                                     = 1,
	Steam                                    = 2,
	SteamTest                                = 3,
	PlayFab                                  = 4,
	PlayFabTest                              = 5,
	EODKItemSourceTypes_MAX                  = 6,
};

// ScriptStruct ODKBazaar.ODKBazaarPurchaseCompletedData
// 0x0010 (0x0010 - 0x0000)
struct FODKBazaarPurchaseCompletedData final
{
public:
	TArray<class UODKBazaarBundle*>               NewBundles;                                        // 0x0000(0x0010)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, NativeAccessSpecifierPublic)
};
static_assert(alignof(FODKBazaarPurchaseCompletedData) == 0x000008, "Wrong alignment on FODKBazaarPurchaseCompletedData");
static_assert(sizeof(FODKBazaarPurchaseCompletedData) == 0x000010, "Wrong size on FODKBazaarPurchaseCompletedData");
static_assert(offsetof(FODKBazaarPurchaseCompletedData, NewBundles) == 0x000000, "Member 'FODKBazaarPurchaseCompletedData::NewBundles' has a wrong offset!");

// ScriptStruct ODKBazaar.ODKBazaarCacheCompletedData
// 0x0020 (0x0020 - 0x0000)
struct FODKBazaarCacheCompletedData final
{
public:
	TArray<class FName>                           Items;                                             // 0x0000(0x0010)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, NativeAccessSpecifierPublic)
	class FString                                 PlayerId;                                          // 0x0010(0x0010)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
};
static_assert(alignof(FODKBazaarCacheCompletedData) == 0x000008, "Wrong alignment on FODKBazaarCacheCompletedData");
static_assert(sizeof(FODKBazaarCacheCompletedData) == 0x000020, "Wrong size on FODKBazaarCacheCompletedData");
static_assert(offsetof(FODKBazaarCacheCompletedData, Items) == 0x000000, "Member 'FODKBazaarCacheCompletedData::Items' has a wrong offset!");
static_assert(offsetof(FODKBazaarCacheCompletedData, PlayerId) == 0x000010, "Member 'FODKBazaarCacheCompletedData::PlayerId' has a wrong offset!");

// ScriptStruct ODKBazaar.ODKBazaarOwnershipCache
// 0x0050 (0x0050 - 0x0000)
struct alignas(0x08) FODKBazaarOwnershipCache final
{
public:
	uint8                                         Pad_1BE5[0x50];                                    // 0x0000(0x0050)(Fixing Struct Size After Last Property [ Dumper-7 ])
};
static_assert(alignof(FODKBazaarOwnershipCache) == 0x000008, "Wrong alignment on FODKBazaarOwnershipCache");
static_assert(sizeof(FODKBazaarOwnershipCache) == 0x000050, "Wrong size on FODKBazaarOwnershipCache");

// ScriptStruct ODKBazaar.ODKBazaarStoreCache
// 0x0010 (0x0010 - 0x0000)
struct FODKBazaarStoreCache final
{
public:
	TArray<class FString>                         PresentedBundles;                                  // 0x0000(0x0010)(Edit, ZeroConstructor, NativeAccessSpecifierPublic)
};
static_assert(alignof(FODKBazaarStoreCache) == 0x000008, "Wrong alignment on FODKBazaarStoreCache");
static_assert(sizeof(FODKBazaarStoreCache) == 0x000010, "Wrong size on FODKBazaarStoreCache");
static_assert(offsetof(FODKBazaarStoreCache, PresentedBundles) == 0x000000, "Member 'FODKBazaarStoreCache::PresentedBundles' has a wrong offset!");

}
