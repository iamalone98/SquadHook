#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: ODKWakeSim

#include "Basic.hpp"

#include "Engine_classes.hpp"


namespace SDK
{

// Class ODKWakeSim.WakeSim
// 0x0090 (0x0950 - 0x08C0)
class UWakeSim : public USceneCaptureComponent2D
{
public:
	bool                                          bStartEnabled;                                     // 0x08B8(0x0001)(Edit, BlueprintVisible, BlueprintReadOnly, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	uint8                                         UpdateRate;                                        // 0x08B9(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	uint8                                         Pad_1BD9[0x2];                                     // 0x08BA(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         SimResolution;                                     // 0x08BC(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	int32                                         CaptureResolution;                                 // 0x08C0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	uint8                                         MaxPhases;                                         // 0x08C4(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	uint8                                         CurrentPhase;                                      // 0x08C5(0x0001)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	uint8                                         Pad_1BDA[0x2];                                     // 0x08C6(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         Range;                                             // 0x08C8(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	float                                         Decay;                                             // 0x08CC(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	float                                         Offset;                                            // 0x08D0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	uint8                                         Pad_1BDB[0x4];                                     // 0x08D4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<class UTextureRenderTarget2D*>         SimPhases;                                         // 0x08D8(0x0010)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, NativeAccessSpecifierPublic)
	class UTextureRenderTarget2D*                 RenderTargetOutput;                                // 0x08E8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	class UMaterialParameterCollection*           MaterialCollection;                                // 0x08F0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	class FName                                   LocationScaleParamName;                            // 0x08F8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	class UMaterial*                              CaptureDepthMaterial;                              // 0x0900(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	class UMaterial*                              ProjectDepthMaterial;                              // 0x0908(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	class UMaterial*                              SampleOffsetMaterial;                              // 0x0910(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	class UMaterial*                              CreateNormalMaterial;                              // 0x0918(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	class UMaterialInstanceDynamic*               ProjectDepthMID;                                   // 0x0920(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	class UMaterialInstanceDynamic*               SampleOffsetMID;                                   // 0x0928(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	class UMaterialInstanceDynamic*               CreateNormalMID;                                   // 0x0930(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	uint8                                         Pad_1BDC[0x18];                                    // 0x0938(0x0018)(Fixing Struct Size After Last Property [ Dumper-7 ])

public:
	bool AreSourceMaterialsValid();
	void ClearData();
	void CyclePhase();
	class UTextureRenderTarget2D* GetNPhasesOld(uint8 Age);
	class UTextureRenderTarget2D* GetPhase();
	void OnEndSimulation();
	void OnStartSimulation();
	void PopulateData();
	void StartSimulation();
	void StopSimulation(bool bClearSimData);

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"WakeSim">();
	}
	static class UWakeSim* GetDefaultObj()
	{
		return GetDefaultObjImpl<UWakeSim>();
	}
};
static_assert(alignof(UWakeSim) == 0x000010, "Wrong alignment on UWakeSim");
static_assert(sizeof(UWakeSim) == 0x000950, "Wrong size on UWakeSim");
static_assert(offsetof(UWakeSim, bStartEnabled) == 0x0008B8, "Member 'UWakeSim::bStartEnabled' has a wrong offset!");
static_assert(offsetof(UWakeSim, UpdateRate) == 0x0008B9, "Member 'UWakeSim::UpdateRate' has a wrong offset!");
static_assert(offsetof(UWakeSim, SimResolution) == 0x0008BC, "Member 'UWakeSim::SimResolution' has a wrong offset!");
static_assert(offsetof(UWakeSim, CaptureResolution) == 0x0008C0, "Member 'UWakeSim::CaptureResolution' has a wrong offset!");
static_assert(offsetof(UWakeSim, MaxPhases) == 0x0008C4, "Member 'UWakeSim::MaxPhases' has a wrong offset!");
static_assert(offsetof(UWakeSim, CurrentPhase) == 0x0008C5, "Member 'UWakeSim::CurrentPhase' has a wrong offset!");
static_assert(offsetof(UWakeSim, Range) == 0x0008C8, "Member 'UWakeSim::Range' has a wrong offset!");
static_assert(offsetof(UWakeSim, Decay) == 0x0008CC, "Member 'UWakeSim::Decay' has a wrong offset!");
static_assert(offsetof(UWakeSim, Offset) == 0x0008D0, "Member 'UWakeSim::Offset' has a wrong offset!");
static_assert(offsetof(UWakeSim, SimPhases) == 0x0008D8, "Member 'UWakeSim::SimPhases' has a wrong offset!");
static_assert(offsetof(UWakeSim, RenderTargetOutput) == 0x0008E8, "Member 'UWakeSim::RenderTargetOutput' has a wrong offset!");
static_assert(offsetof(UWakeSim, MaterialCollection) == 0x0008F0, "Member 'UWakeSim::MaterialCollection' has a wrong offset!");
static_assert(offsetof(UWakeSim, LocationScaleParamName) == 0x0008F8, "Member 'UWakeSim::LocationScaleParamName' has a wrong offset!");
static_assert(offsetof(UWakeSim, CaptureDepthMaterial) == 0x000900, "Member 'UWakeSim::CaptureDepthMaterial' has a wrong offset!");
static_assert(offsetof(UWakeSim, ProjectDepthMaterial) == 0x000908, "Member 'UWakeSim::ProjectDepthMaterial' has a wrong offset!");
static_assert(offsetof(UWakeSim, SampleOffsetMaterial) == 0x000910, "Member 'UWakeSim::SampleOffsetMaterial' has a wrong offset!");
static_assert(offsetof(UWakeSim, CreateNormalMaterial) == 0x000918, "Member 'UWakeSim::CreateNormalMaterial' has a wrong offset!");
static_assert(offsetof(UWakeSim, ProjectDepthMID) == 0x000920, "Member 'UWakeSim::ProjectDepthMID' has a wrong offset!");
static_assert(offsetof(UWakeSim, SampleOffsetMID) == 0x000928, "Member 'UWakeSim::SampleOffsetMID' has a wrong offset!");
static_assert(offsetof(UWakeSim, CreateNormalMID) == 0x000930, "Member 'UWakeSim::CreateNormalMID' has a wrong offset!");

}
