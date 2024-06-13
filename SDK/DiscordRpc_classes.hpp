#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: DiscordRpc

#include "Basic.hpp"

#include "CoreUObject_classes.hpp"
#include "DiscordRpc_structs.hpp"


namespace SDK
{

// Class DiscordRpc.DiscordRpc
// 0x0120 (0x0148 - 0x0028)
class UDiscordRpc final : public UObject
{
public:
	bool                                          IsConnected;                                       // 0x0028(0x0001)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	uint8                                         Pad_17D1[0x7];                                     // 0x0029(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	FMulticastInlineDelegateProperty_             OnConnected;                                       // 0x0030(0x0010)(ZeroConstructor, InstancedReference, BlueprintAssignable, NativeAccessSpecifierPublic)
	FMulticastInlineDelegateProperty_             OnDisconnected;                                    // 0x0040(0x0010)(ZeroConstructor, InstancedReference, BlueprintAssignable, NativeAccessSpecifierPublic)
	FMulticastInlineDelegateProperty_             OnErrored;                                         // 0x0050(0x0010)(ZeroConstructor, InstancedReference, BlueprintAssignable, NativeAccessSpecifierPublic)
	FMulticastInlineDelegateProperty_             OnJoin;                                            // 0x0060(0x0010)(ZeroConstructor, InstancedReference, BlueprintAssignable, NativeAccessSpecifierPublic)
	FMulticastInlineDelegateProperty_             OnSpectate;                                        // 0x0070(0x0010)(ZeroConstructor, InstancedReference, BlueprintAssignable, NativeAccessSpecifierPublic)
	FMulticastInlineDelegateProperty_             OnJoinRequest;                                     // 0x0080(0x0010)(ZeroConstructor, InstancedReference, BlueprintAssignable, NativeAccessSpecifierPublic)
	struct FDiscordRichPresence                   RichPresence;                                      // 0x0090(0x00B8)(BlueprintVisible, NativeAccessSpecifierPublic)

public:
	void ClearPresence();
	void Initialize(const class FString& ApplicationId, bool AutoRegister, const class FString& OptionalSteamId);
	void Respond(const class FString& UserId, int32 Reply);
	void RunCallbacks();
	void Shutdown();
	void UpdatePresence();

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"DiscordRpc">();
	}
	static class UDiscordRpc* GetDefaultObj()
	{
		return GetDefaultObjImpl<UDiscordRpc>();
	}
};
static_assert(alignof(UDiscordRpc) == 0x000008, "Wrong alignment on UDiscordRpc");
static_assert(sizeof(UDiscordRpc) == 0x000148, "Wrong size on UDiscordRpc");
static_assert(offsetof(UDiscordRpc, IsConnected) == 0x000028, "Member 'UDiscordRpc::IsConnected' has a wrong offset!");
static_assert(offsetof(UDiscordRpc, OnConnected) == 0x000030, "Member 'UDiscordRpc::OnConnected' has a wrong offset!");
static_assert(offsetof(UDiscordRpc, OnDisconnected) == 0x000040, "Member 'UDiscordRpc::OnDisconnected' has a wrong offset!");
static_assert(offsetof(UDiscordRpc, OnErrored) == 0x000050, "Member 'UDiscordRpc::OnErrored' has a wrong offset!");
static_assert(offsetof(UDiscordRpc, OnJoin) == 0x000060, "Member 'UDiscordRpc::OnJoin' has a wrong offset!");
static_assert(offsetof(UDiscordRpc, OnSpectate) == 0x000070, "Member 'UDiscordRpc::OnSpectate' has a wrong offset!");
static_assert(offsetof(UDiscordRpc, OnJoinRequest) == 0x000080, "Member 'UDiscordRpc::OnJoinRequest' has a wrong offset!");
static_assert(offsetof(UDiscordRpc, RichPresence) == 0x000090, "Member 'UDiscordRpc::RichPresence' has a wrong offset!");

}

