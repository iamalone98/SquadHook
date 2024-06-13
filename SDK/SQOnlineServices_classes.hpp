#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SQOnlineServices

#include "Basic.hpp"

#include "CoreUObject_classes.hpp"
#include "Engine_classes.hpp"


namespace SDK
{

// Class SQOnlineServices.SQOnlineServicesOnlineUser
// 0x0010 (0x0038 - 0x0028)
class USQOnlineServicesOnlineUser : public UObject
{
public:
	uint8                                         Pad_1BF2[0x10];                                    // 0x0028(0x0010)(Fixing Struct Size After Last Property [ Dumper-7 ])

public:
	class FString GetPlatform();

	TArray<class FString> GetRelatedIds() const;
	class FString GetSteamID() const;
	struct FUniqueNetIdRepl GetUniqueID() const;
	class FString GetUserName() const;

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"SQOnlineServicesOnlineUser">();
	}
	static class USQOnlineServicesOnlineUser* GetDefaultObj()
	{
		return GetDefaultObjImpl<USQOnlineServicesOnlineUser>();
	}
};
static_assert(alignof(USQOnlineServicesOnlineUser) == 0x000008, "Wrong alignment on USQOnlineServicesOnlineUser");
static_assert(sizeof(USQOnlineServicesOnlineUser) == 0x000038, "Wrong size on USQOnlineServicesOnlineUser");

// Class SQOnlineServices.SQOnlineServicesBlockedUser
// 0x0000 (0x0038 - 0x0038)
class USQOnlineServicesBlockedUser final : public USQOnlineServicesOnlineUser
{
public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"SQOnlineServicesBlockedUser">();
	}
	static class USQOnlineServicesBlockedUser* GetDefaultObj()
	{
		return GetDefaultObjImpl<USQOnlineServicesBlockedUser>();
	}
};
static_assert(alignof(USQOnlineServicesBlockedUser) == 0x000008, "Wrong alignment on USQOnlineServicesBlockedUser");
static_assert(sizeof(USQOnlineServicesBlockedUser) == 0x000038, "Wrong size on USQOnlineServicesBlockedUser");

// Class SQOnlineServices.SQOnlineServicesBPLibrary
// 0x0000 (0x0028 - 0x0028)
class USQOnlineServicesBPLibrary final : public UBlueprintFunctionLibrary
{
public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"SQOnlineServicesBPLibrary">();
	}
	static class USQOnlineServicesBPLibrary* GetDefaultObj()
	{
		return GetDefaultObjImpl<USQOnlineServicesBPLibrary>();
	}
};
static_assert(alignof(USQOnlineServicesBPLibrary) == 0x000008, "Wrong alignment on USQOnlineServicesBPLibrary");
static_assert(sizeof(USQOnlineServicesBPLibrary) == 0x000028, "Wrong size on USQOnlineServicesBPLibrary");

// Class SQOnlineServices.SQOnlineServicesEAC
// 0x0028 (0x0050 - 0x0028)
class USQOnlineServicesEAC final : public UObject
{
public:
	uint8                                         Pad_1BF3[0x28];                                    // 0x0028(0x0028)(Fixing Struct Size After Last Property [ Dumper-7 ])

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"SQOnlineServicesEAC">();
	}
	static class USQOnlineServicesEAC* GetDefaultObj()
	{
		return GetDefaultObjImpl<USQOnlineServicesEAC>();
	}
};
static_assert(alignof(USQOnlineServicesEAC) == 0x000008, "Wrong alignment on USQOnlineServicesEAC");
static_assert(sizeof(USQOnlineServicesEAC) == 0x000050, "Wrong size on USQOnlineServicesEAC");

// Class SQOnlineServices.SQOnlineServicesFriends
// 0x00B8 (0x00E0 - 0x0028)
class USQOnlineServicesFriends final : public UObject
{
public:
	FMulticastInlineDelegateProperty_             OnFriendsUpdated;                                  // 0x0028(0x0010)(ZeroConstructor, InstancedReference, BlueprintAssignable, NativeAccessSpecifierPublic)
	FMulticastInlineDelegateProperty_             OnFriendRequestAccepted;                           // 0x0038(0x0010)(ZeroConstructor, InstancedReference, BlueprintAssignable, NativeAccessSpecifierPublic)
	FMulticastInlineDelegateProperty_             OnFriendRequestRejected;                           // 0x0048(0x0010)(ZeroConstructor, InstancedReference, BlueprintAssignable, NativeAccessSpecifierPublic)
	FMulticastInlineDelegateProperty_             OnFriendRequestReceived;                           // 0x0058(0x0010)(ZeroConstructor, InstancedReference, BlueprintAssignable, NativeAccessSpecifierPublic)
	FMulticastInlineDelegateProperty_             OnRecentPlayersUpdated;                            // 0x0068(0x0010)(ZeroConstructor, InstancedReference, BlueprintAssignable, NativeAccessSpecifierPublic)
	uint8                                         Pad_1BF4[0x68];                                    // 0x0078(0x0068)(Fixing Struct Size After Last Property [ Dumper-7 ])

public:
	void AcceptFriendRequest(const struct FUniqueNetIdRepl& FriendId);
	void RejectFriendRequest(const struct FUniqueNetIdRepl& FriendId);
	void RequestRecentPlayers();
	void RequestUpdateFriends();
	void SendFriendRequest(const struct FUniqueNetIdRepl& FriendId);

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"SQOnlineServicesFriends">();
	}
	static class USQOnlineServicesFriends* GetDefaultObj()
	{
		return GetDefaultObjImpl<USQOnlineServicesFriends>();
	}
};
static_assert(alignof(USQOnlineServicesFriends) == 0x000008, "Wrong alignment on USQOnlineServicesFriends");
static_assert(sizeof(USQOnlineServicesFriends) == 0x0000E0, "Wrong size on USQOnlineServicesFriends");
static_assert(offsetof(USQOnlineServicesFriends, OnFriendsUpdated) == 0x000028, "Member 'USQOnlineServicesFriends::OnFriendsUpdated' has a wrong offset!");
static_assert(offsetof(USQOnlineServicesFriends, OnFriendRequestAccepted) == 0x000038, "Member 'USQOnlineServicesFriends::OnFriendRequestAccepted' has a wrong offset!");
static_assert(offsetof(USQOnlineServicesFriends, OnFriendRequestRejected) == 0x000048, "Member 'USQOnlineServicesFriends::OnFriendRequestRejected' has a wrong offset!");
static_assert(offsetof(USQOnlineServicesFriends, OnFriendRequestReceived) == 0x000058, "Member 'USQOnlineServicesFriends::OnFriendRequestReceived' has a wrong offset!");
static_assert(offsetof(USQOnlineServicesFriends, OnRecentPlayersUpdated) == 0x000068, "Member 'USQOnlineServicesFriends::OnRecentPlayersUpdated' has a wrong offset!");

// Class SQOnlineServices.SQOnlineServicesFriendUser
// 0x0000 (0x0038 - 0x0038)
class USQOnlineServicesFriendUser final : public USQOnlineServicesOnlineUser
{
public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"SQOnlineServicesFriendUser">();
	}
	static class USQOnlineServicesFriendUser* GetDefaultObj()
	{
		return GetDefaultObjImpl<USQOnlineServicesFriendUser>();
	}
};
static_assert(alignof(USQOnlineServicesFriendUser) == 0x000008, "Wrong alignment on USQOnlineServicesFriendUser");
static_assert(sizeof(USQOnlineServicesFriendUser) == 0x000038, "Wrong size on USQOnlineServicesFriendUser");

// Class SQOnlineServices.SQOnlineServicesLocalUser
// 0x0000 (0x0038 - 0x0038)
class USQOnlineServicesLocalUser final : public USQOnlineServicesOnlineUser
{
public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"SQOnlineServicesLocalUser">();
	}
	static class USQOnlineServicesLocalUser* GetDefaultObj()
	{
		return GetDefaultObjImpl<USQOnlineServicesLocalUser>();
	}
};
static_assert(alignof(USQOnlineServicesLocalUser) == 0x000008, "Wrong alignment on USQOnlineServicesLocalUser");
static_assert(sizeof(USQOnlineServicesLocalUser) == 0x000038, "Wrong size on USQOnlineServicesLocalUser");

// Class SQOnlineServices.SQOnlineServicesParty
// 0x0058 (0x0080 - 0x0028)
class USQOnlineServicesParty final : public UObject
{
public:
	FMulticastInlineDelegateProperty_             OnPartyJoined;                                     // 0x0028(0x0010)(ZeroConstructor, InstancedReference, BlueprintAssignable, NativeAccessSpecifierPublic)
	FMulticastInlineDelegateProperty_             OnPartyLeft;                                       // 0x0038(0x0010)(ZeroConstructor, InstancedReference, BlueprintAssignable, NativeAccessSpecifierPublic)
	FMulticastInlineDelegateProperty_             OnPartyMemberKicked;                               // 0x0048(0x0010)(ZeroConstructor, InstancedReference, BlueprintAssignable, NativeAccessSpecifierPublic)
	FMulticastInlineDelegateProperty_             OnPartyMemberPromoted;                             // 0x0058(0x0010)(ZeroConstructor, InstancedReference, BlueprintAssignable, NativeAccessSpecifierPublic)
	uint8                                         Pad_1BF5[0x10];                                    // 0x0068(0x0010)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         MaxPartySize;                                      // 0x0078(0x0004)(BlueprintVisible, ZeroConstructor, Config, IsPlainOldData, NoDestructor, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected)
	uint8                                         Pad_1BF6[0x4];                                     // 0x007C(0x0004)(Fixing Struct Size After Last Property [ Dumper-7 ])

public:
	void CreateParty();
	class USQOnlineServicesPartyUser* GetPartyLeader();
	TArray<class USQOnlineServicesPartyUser*> GetPartyMembers();
	bool IsPartyLeader(const struct FUniqueNetIdRepl& PartyMember);
	bool IsPartyUserLeader(const class USQOnlineServicesPartyUser* PartyMember);
	void KickPlayer(const struct FUniqueNetIdRepl& Player);
	void LeaveParty();
	void PromoteLeader(const struct FUniqueNetIdRepl& Player);

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"SQOnlineServicesParty">();
	}
	static class USQOnlineServicesParty* GetDefaultObj()
	{
		return GetDefaultObjImpl<USQOnlineServicesParty>();
	}
};
static_assert(alignof(USQOnlineServicesParty) == 0x000008, "Wrong alignment on USQOnlineServicesParty");
static_assert(sizeof(USQOnlineServicesParty) == 0x000080, "Wrong size on USQOnlineServicesParty");
static_assert(offsetof(USQOnlineServicesParty, OnPartyJoined) == 0x000028, "Member 'USQOnlineServicesParty::OnPartyJoined' has a wrong offset!");
static_assert(offsetof(USQOnlineServicesParty, OnPartyLeft) == 0x000038, "Member 'USQOnlineServicesParty::OnPartyLeft' has a wrong offset!");
static_assert(offsetof(USQOnlineServicesParty, OnPartyMemberKicked) == 0x000048, "Member 'USQOnlineServicesParty::OnPartyMemberKicked' has a wrong offset!");
static_assert(offsetof(USQOnlineServicesParty, OnPartyMemberPromoted) == 0x000058, "Member 'USQOnlineServicesParty::OnPartyMemberPromoted' has a wrong offset!");
static_assert(offsetof(USQOnlineServicesParty, MaxPartySize) == 0x000078, "Member 'USQOnlineServicesParty::MaxPartySize' has a wrong offset!");

// Class SQOnlineServices.SQOnlineServicesPartyUser
// 0x0000 (0x0038 - 0x0038)
class USQOnlineServicesPartyUser final : public USQOnlineServicesOnlineUser
{
public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"SQOnlineServicesPartyUser">();
	}
	static class USQOnlineServicesPartyUser* GetDefaultObj()
	{
		return GetDefaultObjImpl<USQOnlineServicesPartyUser>();
	}
};
static_assert(alignof(USQOnlineServicesPartyUser) == 0x000008, "Wrong alignment on USQOnlineServicesPartyUser");
static_assert(sizeof(USQOnlineServicesPartyUser) == 0x000038, "Wrong size on USQOnlineServicesPartyUser");

// Class SQOnlineServices.SQOnlineServicesPingSubsystem
// 0x0138 (0x0168 - 0x0030)
class USQOnlineServicesPingSubsystem final : public UGameInstanceSubsystem
{
public:
	uint8                                         Pad_1BF9[0x138];                                   // 0x0030(0x0138)(Fixing Struct Size After Last Property [ Dumper-7 ])

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"SQOnlineServicesPingSubsystem">();
	}
	static class USQOnlineServicesPingSubsystem* GetDefaultObj()
	{
		return GetDefaultObjImpl<USQOnlineServicesPingSubsystem>();
	}
};
static_assert(alignof(USQOnlineServicesPingSubsystem) == 0x000008, "Wrong alignment on USQOnlineServicesPingSubsystem");
static_assert(sizeof(USQOnlineServicesPingSubsystem) == 0x000168, "Wrong size on USQOnlineServicesPingSubsystem");

// Class SQOnlineServices.SQOnlineServicesRecentUser
// 0x0000 (0x0038 - 0x0038)
class USQOnlineServicesRecentUser final : public USQOnlineServicesOnlineUser
{
public:
	class FString GetLastSeenString();

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"SQOnlineServicesRecentUser">();
	}
	static class USQOnlineServicesRecentUser* GetDefaultObj()
	{
		return GetDefaultObjImpl<USQOnlineServicesRecentUser>();
	}
};
static_assert(alignof(USQOnlineServicesRecentUser) == 0x000008, "Wrong alignment on USQOnlineServicesRecentUser");
static_assert(sizeof(USQOnlineServicesRecentUser) == 0x000038, "Wrong size on USQOnlineServicesRecentUser");

// Class SQOnlineServices.SQOnlineServicesSession
// 0x0000 (0x0028 - 0x0028)
class USQOnlineServicesSession final : public UObject
{
public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"SQOnlineServicesSession">();
	}
	static class USQOnlineServicesSession* GetDefaultObj()
	{
		return GetDefaultObjImpl<USQOnlineServicesSession>();
	}
};
static_assert(alignof(USQOnlineServicesSession) == 0x000008, "Wrong alignment on USQOnlineServicesSession");
static_assert(sizeof(USQOnlineServicesSession) == 0x000028, "Wrong size on USQOnlineServicesSession");

// Class SQOnlineServices.SQOnlineServicesSubsystem
// 0x0048 (0x0078 - 0x0030)
class USQOnlineServicesSubsystem final : public UGameInstanceSubsystem
{
public:
	uint8                                         Pad_1BFA[0x20];                                    // 0x0030(0x0020)(Fixing Size After Last Property [ Dumper-7 ])
	class USQOnlineServicesLocalUser*             LocalUser;                                         // 0x0050(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected)
	class USQOnlineServicesFriends*               FriendsService;                                    // 0x0058(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected)
	class USQOnlineServicesParty*                 PartyService;                                      // 0x0060(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected)
	class USQOnlineServicesSession*               SessionService;                                    // 0x0068(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected)
	class USQOnlineServicesEAC*                   EACService;                                        // 0x0070(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected)

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"SQOnlineServicesSubsystem">();
	}
	static class USQOnlineServicesSubsystem* GetDefaultObj()
	{
		return GetDefaultObjImpl<USQOnlineServicesSubsystem>();
	}
};
static_assert(alignof(USQOnlineServicesSubsystem) == 0x000008, "Wrong alignment on USQOnlineServicesSubsystem");
static_assert(sizeof(USQOnlineServicesSubsystem) == 0x000078, "Wrong size on USQOnlineServicesSubsystem");
static_assert(offsetof(USQOnlineServicesSubsystem, LocalUser) == 0x000050, "Member 'USQOnlineServicesSubsystem::LocalUser' has a wrong offset!");
static_assert(offsetof(USQOnlineServicesSubsystem, FriendsService) == 0x000058, "Member 'USQOnlineServicesSubsystem::FriendsService' has a wrong offset!");
static_assert(offsetof(USQOnlineServicesSubsystem, PartyService) == 0x000060, "Member 'USQOnlineServicesSubsystem::PartyService' has a wrong offset!");
static_assert(offsetof(USQOnlineServicesSubsystem, SessionService) == 0x000068, "Member 'USQOnlineServicesSubsystem::SessionService' has a wrong offset!");
static_assert(offsetof(USQOnlineServicesSubsystem, EACService) == 0x000070, "Member 'USQOnlineServicesSubsystem::EACService' has a wrong offset!");

// Class SQOnlineServices.SQOnlineServicesUpdateSessionManager
// 0x0078 (0x00A8 - 0x0030)
class USQOnlineServicesUpdateSessionManager final : public UGameInstanceSubsystem
{
public:
	uint8                                         Pad_1BFB[0x78];                                    // 0x0030(0x0078)(Fixing Struct Size After Last Property [ Dumper-7 ])

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"SQOnlineServicesUpdateSessionManager">();
	}
	static class USQOnlineServicesUpdateSessionManager* GetDefaultObj()
	{
		return GetDefaultObjImpl<USQOnlineServicesUpdateSessionManager>();
	}
};
static_assert(alignof(USQOnlineServicesUpdateSessionManager) == 0x000008, "Wrong alignment on USQOnlineServicesUpdateSessionManager");
static_assert(sizeof(USQOnlineServicesUpdateSessionManager) == 0x0000A8, "Wrong size on USQOnlineServicesUpdateSessionManager");

}
