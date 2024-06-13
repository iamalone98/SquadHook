#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: ODKBazaar

#include "Basic.hpp"

#include "CoreUObject_classes.hpp"
#include "Engine_classes.hpp"
#include "ODKBazaar_structs.hpp"


namespace SDK
{

// Class ODKBazaar.BazaarOwnershipInterface
// 0x0000 (0x0028 - 0x0028)
class IBazaarOwnershipInterface final : public IInterface
{
public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"BazaarOwnershipInterface">();
	}
	static class IBazaarOwnershipInterface* GetDefaultObj()
	{
		return GetDefaultObjImpl<IBazaarOwnershipInterface>();
	}
};
static_assert(alignof(IBazaarOwnershipInterface) == 0x000008, "Wrong alignment on IBazaarOwnershipInterface");
static_assert(sizeof(IBazaarOwnershipInterface) == 0x000028, "Wrong size on IBazaarOwnershipInterface");

// Class ODKBazaar.BazaarStoreInterface
// 0x0000 (0x0028 - 0x0028)
class IBazaarStoreInterface final : public IInterface
{
public:
	void OnPurchaseCompleteImpl(const struct FODKBazaarPurchaseCompletedData& PurchaseData);

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"BazaarStoreInterface">();
	}
	static class IBazaarStoreInterface* GetDefaultObj()
	{
		return GetDefaultObjImpl<IBazaarStoreInterface>();
	}
};
static_assert(alignof(IBazaarStoreInterface) == 0x000008, "Wrong alignment on IBazaarStoreInterface");
static_assert(sizeof(IBazaarStoreInterface) == 0x000028, "Wrong size on IBazaarStoreInterface");

// Class ODKBazaar.ODKBazaarBPLibrary
// 0x0000 (0x0028 - 0x0028)
class UODKBazaarBPLibrary final : public UBlueprintFunctionLibrary
{
public:
	static void ODKBazaarCheckForNewPurchases();
	static bool ODKBazaarIsItemIdOwned(const struct FUniqueNetIdRepl& PlayerId, const class FName& Param);
	static bool ODKBazaarIsItemOwned(const struct FUniqueNetIdRepl& PlayerId, const class UODKBazaarItem* Param);
	static void ODKBazaarOpenPlatformStore(const class UODKBazaarItem* Param);

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"ODKBazaarBPLibrary">();
	}
	static class UODKBazaarBPLibrary* GetDefaultObj()
	{
		return GetDefaultObjImpl<UODKBazaarBPLibrary>();
	}
};
static_assert(alignof(UODKBazaarBPLibrary) == 0x000008, "Wrong alignment on UODKBazaarBPLibrary");
static_assert(sizeof(UODKBazaarBPLibrary) == 0x000028, "Wrong size on UODKBazaarBPLibrary");

// Class ODKBazaar.ODKBazaarItem
// 0x00B0 (0x00E0 - 0x0030)
class UODKBazaarItem : public UDataAsset
{
public:
	class FName                                   ItemId;                                            // 0x0030(0x0008)(Edit, BlueprintVisible, BlueprintReadOnly, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	class FText                                   ItemName;                                          // 0x0038(0x0018)(Edit, BlueprintVisible, BlueprintReadOnly, DisableEditOnInstance, NativeAccessSpecifierPublic)
	class FText                                   ItemDescription;                                   // 0x0050(0x0018)(Edit, BlueprintVisible, BlueprintReadOnly, DisableEditOnInstance, NativeAccessSpecifierPublic)
	TSoftObjectPtr<class UTexture2D>              ItemIcon;                                          // 0x0068(0x0028)(Edit, BlueprintVisible, BlueprintReadOnly, DisableEditOnInstance, UObjectWrapper, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	TMap<EODKItemSourceTypes, class FName>        SourceID;                                          // 0x0090(0x0050)(Edit, DisableEditOnInstance, NativeAccessSpecifierPublic)

public:
	void RegenerateItemID();

	bool IsOwnedLocally() const;

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"ODKBazaarItem">();
	}
	static class UODKBazaarItem* GetDefaultObj()
	{
		return GetDefaultObjImpl<UODKBazaarItem>();
	}
};
static_assert(alignof(UODKBazaarItem) == 0x000008, "Wrong alignment on UODKBazaarItem");
static_assert(sizeof(UODKBazaarItem) == 0x0000E0, "Wrong size on UODKBazaarItem");
static_assert(offsetof(UODKBazaarItem, ItemId) == 0x000030, "Member 'UODKBazaarItem::ItemId' has a wrong offset!");
static_assert(offsetof(UODKBazaarItem, ItemName) == 0x000038, "Member 'UODKBazaarItem::ItemName' has a wrong offset!");
static_assert(offsetof(UODKBazaarItem, ItemDescription) == 0x000050, "Member 'UODKBazaarItem::ItemDescription' has a wrong offset!");
static_assert(offsetof(UODKBazaarItem, ItemIcon) == 0x000068, "Member 'UODKBazaarItem::ItemIcon' has a wrong offset!");
static_assert(offsetof(UODKBazaarItem, SourceID) == 0x000090, "Member 'UODKBazaarItem::SourceID' has a wrong offset!");

// Class ODKBazaar.ODKBazaarBundle
// 0x0038 (0x0118 - 0x00E0)
class UODKBazaarBundle final : public UODKBazaarItem
{
public:
	TArray<class UODKBazaarItem*>                 Items;                                             // 0x00E0(0x0010)(Edit, BlueprintVisible, BlueprintReadOnly, ZeroConstructor, DisableEditOnInstance, NativeAccessSpecifierPublic)
	bool                                          bIsOnSale;                                         // 0x00F0(0x0001)(Edit, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	uint8                                         Pad_1BE8[0x7];                                     // 0x00F1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   PurchaseText;                                      // 0x00F8(0x0018)(Edit, BlueprintVisible, BlueprintReadOnly, DisableEditOnInstance, NativeAccessSpecifierPublic)
	EBundleCategory                               BundleCategory;                                    // 0x0110(0x0001)(Edit, BlueprintVisible, BlueprintReadOnly, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	uint8                                         Pad_1BE9[0x7];                                     // 0x0111(0x0007)(Fixing Struct Size After Last Property [ Dumper-7 ])

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"ODKBazaarBundle">();
	}
	static class UODKBazaarBundle* GetDefaultObj()
	{
		return GetDefaultObjImpl<UODKBazaarBundle>();
	}
};
static_assert(alignof(UODKBazaarBundle) == 0x000008, "Wrong alignment on UODKBazaarBundle");
static_assert(sizeof(UODKBazaarBundle) == 0x000118, "Wrong size on UODKBazaarBundle");
static_assert(offsetof(UODKBazaarBundle, Items) == 0x0000E0, "Member 'UODKBazaarBundle::Items' has a wrong offset!");
static_assert(offsetof(UODKBazaarBundle, bIsOnSale) == 0x0000F0, "Member 'UODKBazaarBundle::bIsOnSale' has a wrong offset!");
static_assert(offsetof(UODKBazaarBundle, PurchaseText) == 0x0000F8, "Member 'UODKBazaarBundle::PurchaseText' has a wrong offset!");
static_assert(offsetof(UODKBazaarBundle, BundleCategory) == 0x000110, "Member 'UODKBazaarBundle::BundleCategory' has a wrong offset!");

// Class ODKBazaar.ODKBazaarDB
// 0x0020 (0x0050 - 0x0030)
class UODKBazaarDB final : public UDataAsset
{
public:
	TArray<class UODKBazaarBundle*>               Bundles;                                           // 0x0030(0x0010)(Edit, ZeroConstructor, DisableEditOnInstance, NativeAccessSpecifierPublic)
	TArray<class UODKBazaarItem*>                 Items;                                             // 0x0040(0x0010)(Edit, ZeroConstructor, DisableEditOnInstance, NativeAccessSpecifierPublic)

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"ODKBazaarDB">();
	}
	static class UODKBazaarDB* GetDefaultObj()
	{
		return GetDefaultObjImpl<UODKBazaarDB>();
	}
};
static_assert(alignof(UODKBazaarDB) == 0x000008, "Wrong alignment on UODKBazaarDB");
static_assert(sizeof(UODKBazaarDB) == 0x000050, "Wrong size on UODKBazaarDB");
static_assert(offsetof(UODKBazaarDB, Bundles) == 0x000030, "Member 'UODKBazaarDB::Bundles' has a wrong offset!");
static_assert(offsetof(UODKBazaarDB, Items) == 0x000040, "Member 'UODKBazaarDB::Items' has a wrong offset!");

// Class ODKBazaar.ODKBazaarSettings
// 0x0040 (0x0068 - 0x0028)
class UODKBazaarSettings final : public UObject
{
public:
	TSoftObjectPtr<class UODKBazaarDB>            Bazaar;                                            // 0x0028(0x0028)(Edit, Config, DisableEditOnInstance, UObjectWrapper, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	EBazaarProvider                               StoreProvider;                                     // 0x0050(0x0001)(Edit, ZeroConstructor, Config, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	EBazaarProvider                               OwnershipProvider;                                 // 0x0051(0x0001)(Edit, ZeroConstructor, Config, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	uint8                                         Pad_1BEA[0x6];                                     // 0x0052(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class FString                                 TestAppId;                                         // 0x0058(0x0010)(Edit, ZeroConstructor, Config, DisableEditOnInstance, HasGetValueTypeHash, NativeAccessSpecifierPublic)

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"ODKBazaarSettings">();
	}
	static class UODKBazaarSettings* GetDefaultObj()
	{
		return GetDefaultObjImpl<UODKBazaarSettings>();
	}
};
static_assert(alignof(UODKBazaarSettings) == 0x000008, "Wrong alignment on UODKBazaarSettings");
static_assert(sizeof(UODKBazaarSettings) == 0x000068, "Wrong size on UODKBazaarSettings");
static_assert(offsetof(UODKBazaarSettings, Bazaar) == 0x000028, "Member 'UODKBazaarSettings::Bazaar' has a wrong offset!");
static_assert(offsetof(UODKBazaarSettings, StoreProvider) == 0x000050, "Member 'UODKBazaarSettings::StoreProvider' has a wrong offset!");
static_assert(offsetof(UODKBazaarSettings, OwnershipProvider) == 0x000051, "Member 'UODKBazaarSettings::OwnershipProvider' has a wrong offset!");
static_assert(offsetof(UODKBazaarSettings, TestAppId) == 0x000058, "Member 'UODKBazaarSettings::TestAppId' has a wrong offset!");

// Class ODKBazaar.ODKBazaarSubsystem
// 0x0028 (0x0058 - 0x0030)
class UODKBazaarSubsystem final : public UGameInstanceSubsystem
{
public:
	class UODKBazaarDB*                           BazaarData;                                        // 0x0030(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, IsPlainOldData, NoDestructor, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected)
	TScriptInterface<class IBazaarStoreInterface> StoreProvider;                                     // 0x0038(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, UObjectWrapper, NativeAccessSpecifierPrivate)
	TScriptInterface<class IBazaarOwnershipInterface> OwnershipProvider;                                 // 0x0048(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, UObjectWrapper, NativeAccessSpecifierPrivate)

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"ODKBazaarSubsystem">();
	}
	static class UODKBazaarSubsystem* GetDefaultObj()
	{
		return GetDefaultObjImpl<UODKBazaarSubsystem>();
	}
};
static_assert(alignof(UODKBazaarSubsystem) == 0x000008, "Wrong alignment on UODKBazaarSubsystem");
static_assert(sizeof(UODKBazaarSubsystem) == 0x000058, "Wrong size on UODKBazaarSubsystem");
static_assert(offsetof(UODKBazaarSubsystem, BazaarData) == 0x000030, "Member 'UODKBazaarSubsystem::BazaarData' has a wrong offset!");
static_assert(offsetof(UODKBazaarSubsystem, StoreProvider) == 0x000038, "Member 'UODKBazaarSubsystem::StoreProvider' has a wrong offset!");
static_assert(offsetof(UODKBazaarSubsystem, OwnershipProvider) == 0x000048, "Member 'UODKBazaarSubsystem::OwnershipProvider' has a wrong offset!");

// Class ODKBazaar.ODKBazaarUtils
// 0x0000 (0x0028 - 0x0028)
class UODKBazaarUtils final : public UObject
{
public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"ODKBazaarUtils">();
	}
	static class UODKBazaarUtils* GetDefaultObj()
	{
		return GetDefaultObjImpl<UODKBazaarUtils>();
	}
};
static_assert(alignof(UODKBazaarUtils) == 0x000008, "Wrong alignment on UODKBazaarUtils");
static_assert(sizeof(UODKBazaarUtils) == 0x000028, "Wrong size on UODKBazaarUtils");

// Class ODKBazaar.ODKEditorBazaarProvider
// 0x0080 (0x00A8 - 0x0028)
class UODKEditorBazaarProvider final : public UObject
{
public:
	uint8                                         Pad_1BEB[0x80];                                    // 0x0028(0x0080)(Fixing Struct Size After Last Property [ Dumper-7 ])

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"ODKEditorBazaarProvider">();
	}
	static class UODKEditorBazaarProvider* GetDefaultObj()
	{
		return GetDefaultObjImpl<UODKEditorBazaarProvider>();
	}
};
static_assert(alignof(UODKEditorBazaarProvider) == 0x000008, "Wrong alignment on UODKEditorBazaarProvider");
static_assert(sizeof(UODKEditorBazaarProvider) == 0x0000A8, "Wrong size on UODKEditorBazaarProvider");

// Class ODKBazaar.ODKMultiOwnershipProvider
// 0x0020 (0x0048 - 0x0028)
class UODKMultiOwnershipProvider final : public UObject
{
public:
	uint8                                         Pad_1BEC[0x10];                                    // 0x0028(0x0010)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<TScriptInterface<class IBazaarOwnershipInterface>> OwnershipProviders;                                // 0x0038(0x0010)(ZeroConstructor, UObjectWrapper, NativeAccessSpecifierPrivate)

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"ODKMultiOwnershipProvider">();
	}
	static class UODKMultiOwnershipProvider* GetDefaultObj()
	{
		return GetDefaultObjImpl<UODKMultiOwnershipProvider>();
	}
};
static_assert(alignof(UODKMultiOwnershipProvider) == 0x000008, "Wrong alignment on UODKMultiOwnershipProvider");
static_assert(sizeof(UODKMultiOwnershipProvider) == 0x000048, "Wrong size on UODKMultiOwnershipProvider");
static_assert(offsetof(UODKMultiOwnershipProvider, OwnershipProviders) == 0x000038, "Member 'UODKMultiOwnershipProvider::OwnershipProviders' has a wrong offset!");

// Class ODKBazaar.ODKPlayFabOwnershipProvider
// 0x0188 (0x01B0 - 0x0028)
class UODKPlayFabOwnershipProvider final : public UObject
{
public:
	uint8                                         Pad_1BED[0x188];                                   // 0x0028(0x0188)(Fixing Struct Size After Last Property [ Dumper-7 ])

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"ODKPlayFabOwnershipProvider">();
	}
	static class UODKPlayFabOwnershipProvider* GetDefaultObj()
	{
		return GetDefaultObjImpl<UODKPlayFabOwnershipProvider>();
	}
};
static_assert(alignof(UODKPlayFabOwnershipProvider) == 0x000008, "Wrong alignment on UODKPlayFabOwnershipProvider");
static_assert(sizeof(UODKPlayFabOwnershipProvider) == 0x0001B0, "Wrong size on UODKPlayFabOwnershipProvider");

// Class ODKBazaar.ODKSteamOwnershipProvider
// 0x00D8 (0x0100 - 0x0028)
class UODKSteamOwnershipProvider final : public UObject
{
public:
	uint8                                         Pad_1BEE[0xD8];                                    // 0x0028(0x00D8)(Fixing Struct Size After Last Property [ Dumper-7 ])

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"ODKSteamOwnershipProvider">();
	}
	static class UODKSteamOwnershipProvider* GetDefaultObj()
	{
		return GetDefaultObjImpl<UODKSteamOwnershipProvider>();
	}
};
static_assert(alignof(UODKSteamOwnershipProvider) == 0x000008, "Wrong alignment on UODKSteamOwnershipProvider");
static_assert(sizeof(UODKSteamOwnershipProvider) == 0x000100, "Wrong size on UODKSteamOwnershipProvider");

// Class ODKBazaar.ODKSteamStoreProvider
// 0x0030 (0x0058 - 0x0028)
class UODKSteamStoreProvider final : public UObject
{
public:
	uint8                                         Pad_1BEF[0x30];                                    // 0x0028(0x0030)(Fixing Struct Size After Last Property [ Dumper-7 ])

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"ODKSteamStoreProvider">();
	}
	static class UODKSteamStoreProvider* GetDefaultObj()
	{
		return GetDefaultObjImpl<UODKSteamStoreProvider>();
	}
};
static_assert(alignof(UODKSteamStoreProvider) == 0x000008, "Wrong alignment on UODKSteamStoreProvider");
static_assert(sizeof(UODKSteamStoreProvider) == 0x000058, "Wrong size on UODKSteamStoreProvider");

}
