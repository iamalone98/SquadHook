#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: VariantManagerContent

#include "Basic.hpp"

#include "CoreUObject_structs.hpp"
#include "CoreUObject_classes.hpp"
#include "Engine_classes.hpp"
#include "VariantManagerContent_structs.hpp"


namespace SDK
{

// Class VariantManagerContent.LevelVariantSets
// 0x0068 (0x0090 - 0x0028)
class ULevelVariantSets final : public UObject
{
public:
	class UClass*                                 DirectorClass;                                     // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
	TArray<class UVariantSet*>                    VariantSets;                                       // 0x0030(0x0010)(ZeroConstructor, NativeAccessSpecifierPrivate)
	uint8                                         Pad_24A0[0x50];                                    // 0x0040(0x0050)(Fixing Struct Size After Last Property [ Dumper-7 ])

public:
	int32 GetNumVariantSets();
	class UVariantSet* GetVariantSet(int32 VariantSetIndex);
	class UVariantSet* GetVariantSetByName(const class FString& VariantSetName);

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"LevelVariantSets">();
	}
	static class ULevelVariantSets* GetDefaultObj()
	{
		return GetDefaultObjImpl<ULevelVariantSets>();
	}
};
static_assert(alignof(ULevelVariantSets) == 0x000008, "Wrong alignment on ULevelVariantSets");
static_assert(sizeof(ULevelVariantSets) == 0x000090, "Wrong size on ULevelVariantSets");
static_assert(offsetof(ULevelVariantSets, DirectorClass) == 0x000028, "Member 'ULevelVariantSets::DirectorClass' has a wrong offset!");
static_assert(offsetof(ULevelVariantSets, VariantSets) == 0x000030, "Member 'ULevelVariantSets::VariantSets' has a wrong offset!");

// Class VariantManagerContent.LevelVariantSetsActor
// 0x0068 (0x0290 - 0x0228)
class ALevelVariantSetsActor final : public AActor
{
public:
	struct FSoftObjectPath                        LevelVariantSets;                                  // 0x0228(0x0018)(Edit, BlueprintVisible, BlueprintReadOnly, ZeroConstructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	TMap<class UClass*, class ULevelVariantSetsFunctionDirector*> DirectorInstances;                                 // 0x0240(0x0050)(Transient, NativeAccessSpecifierPrivate)

public:
	class ULevelVariantSets* GetLevelVariantSets(bool bLoad);
	void SetLevelVariantSets(class ULevelVariantSets* InVariantSets);
	bool SwitchOnVariantByIndex(int32 VariantSetIndex, int32 VariantIndex);
	bool SwitchOnVariantByName(const class FString& VariantSetName, const class FString& VariantName);

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"LevelVariantSetsActor">();
	}
	static class ALevelVariantSetsActor* GetDefaultObj()
	{
		return GetDefaultObjImpl<ALevelVariantSetsActor>();
	}
};
static_assert(alignof(ALevelVariantSetsActor) == 0x000008, "Wrong alignment on ALevelVariantSetsActor");
static_assert(sizeof(ALevelVariantSetsActor) == 0x000290, "Wrong size on ALevelVariantSetsActor");
static_assert(offsetof(ALevelVariantSetsActor, LevelVariantSets) == 0x000228, "Member 'ALevelVariantSetsActor::LevelVariantSets' has a wrong offset!");
static_assert(offsetof(ALevelVariantSetsActor, DirectorInstances) == 0x000240, "Member 'ALevelVariantSetsActor::DirectorInstances' has a wrong offset!");

// Class VariantManagerContent.LevelVariantSetsFunctionDirector
// 0x0018 (0x0040 - 0x0028)
class ULevelVariantSetsFunctionDirector final : public UObject
{
public:
	uint8                                         Pad_24A5[0x18];                                    // 0x0028(0x0018)(Fixing Struct Size After Last Property [ Dumper-7 ])

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"LevelVariantSetsFunctionDirector">();
	}
	static class ULevelVariantSetsFunctionDirector* GetDefaultObj()
	{
		return GetDefaultObjImpl<ULevelVariantSetsFunctionDirector>();
	}
};
static_assert(alignof(ULevelVariantSetsFunctionDirector) == 0x000008, "Wrong alignment on ULevelVariantSetsFunctionDirector");
static_assert(sizeof(ULevelVariantSetsFunctionDirector) == 0x000040, "Wrong size on ULevelVariantSetsFunctionDirector");

// Class VariantManagerContent.PropertyValue
// 0x0190 (0x01B8 - 0x0028)
class UPropertyValue : public UObject
{
public:
	uint8                                         Pad_24A6[0x60];                                    // 0x0028(0x0060)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<TFieldPath<struct FProperty>>          Properties;                                        // 0x0088(0x0010)(ZeroConstructor, Deprecated, Protected, NativeAccessSpecifierProtected)
	TArray<int32>                                 PropertyIndices;                                   // 0x0098(0x0010)(ZeroConstructor, Deprecated, Protected, NativeAccessSpecifierProtected)
	TArray<struct FCapturedPropSegment>           CapturedPropSegments;                              // 0x00A8(0x0010)(ZeroConstructor, Protected, NativeAccessSpecifierProtected)
	class FString                                 FullDisplayString;                                 // 0x00B8(0x0010)(ZeroConstructor, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected)
	class FName                                   PropertySetterName;                                // 0x00C8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected)
	TMap<class FString, class FString>            PropertySetterParameterDefaults;                   // 0x00D0(0x0050)(Protected, NativeAccessSpecifierProtected)
	bool                                          bHasRecordedData;                                  // 0x0120(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected)
	uint8                                         Pad_24A7[0x7];                                     // 0x0121(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UClass*                                 LeafPropertyClass;                                 // 0x0128(0x0008)(ZeroConstructor, Deprecated, IsPlainOldData, NoDestructor, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected)
	uint8                                         Pad_24A8[0x8];                                     // 0x0130(0x0008)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<uint8>                                 ValueBytes;                                        // 0x0138(0x0010)(ZeroConstructor, Protected, NativeAccessSpecifierProtected)
	EPropertyValueCategory                        PropCategory;                                      // 0x0148(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, Protected, HasGetValueTypeHash, NativeAccessSpecifierProtected)
	uint8                                         Pad_24A9[0x6F];                                    // 0x0149(0x006F)(Fixing Struct Size After Last Property [ Dumper-7 ])

public:
	class FString GetFullDisplayString() const;
	class FText GetPropertyTooltip() const;
	bool HasRecordedData() const;

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"PropertyValue">();
	}
	static class UPropertyValue* GetDefaultObj()
	{
		return GetDefaultObjImpl<UPropertyValue>();
	}
};
static_assert(alignof(UPropertyValue) == 0x000008, "Wrong alignment on UPropertyValue");
static_assert(sizeof(UPropertyValue) == 0x0001B8, "Wrong size on UPropertyValue");
static_assert(offsetof(UPropertyValue, Properties) == 0x000088, "Member 'UPropertyValue::Properties' has a wrong offset!");
static_assert(offsetof(UPropertyValue, PropertyIndices) == 0x000098, "Member 'UPropertyValue::PropertyIndices' has a wrong offset!");
static_assert(offsetof(UPropertyValue, CapturedPropSegments) == 0x0000A8, "Member 'UPropertyValue::CapturedPropSegments' has a wrong offset!");
static_assert(offsetof(UPropertyValue, FullDisplayString) == 0x0000B8, "Member 'UPropertyValue::FullDisplayString' has a wrong offset!");
static_assert(offsetof(UPropertyValue, PropertySetterName) == 0x0000C8, "Member 'UPropertyValue::PropertySetterName' has a wrong offset!");
static_assert(offsetof(UPropertyValue, PropertySetterParameterDefaults) == 0x0000D0, "Member 'UPropertyValue::PropertySetterParameterDefaults' has a wrong offset!");
static_assert(offsetof(UPropertyValue, bHasRecordedData) == 0x000120, "Member 'UPropertyValue::bHasRecordedData' has a wrong offset!");
static_assert(offsetof(UPropertyValue, LeafPropertyClass) == 0x000128, "Member 'UPropertyValue::LeafPropertyClass' has a wrong offset!");
static_assert(offsetof(UPropertyValue, ValueBytes) == 0x000138, "Member 'UPropertyValue::ValueBytes' has a wrong offset!");
static_assert(offsetof(UPropertyValue, PropCategory) == 0x000148, "Member 'UPropertyValue::PropCategory' has a wrong offset!");

// Class VariantManagerContent.PropertyValueTransform
// 0x0000 (0x01B8 - 0x01B8)
class UPropertyValueTransform final : public UPropertyValue
{
public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"PropertyValueTransform">();
	}
	static class UPropertyValueTransform* GetDefaultObj()
	{
		return GetDefaultObjImpl<UPropertyValueTransform>();
	}
};
static_assert(alignof(UPropertyValueTransform) == 0x000008, "Wrong alignment on UPropertyValueTransform");
static_assert(sizeof(UPropertyValueTransform) == 0x0001B8, "Wrong size on UPropertyValueTransform");

// Class VariantManagerContent.PropertyValueVisibility
// 0x0000 (0x01B8 - 0x01B8)
class UPropertyValueVisibility final : public UPropertyValue
{
public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"PropertyValueVisibility">();
	}
	static class UPropertyValueVisibility* GetDefaultObj()
	{
		return GetDefaultObjImpl<UPropertyValueVisibility>();
	}
};
static_assert(alignof(UPropertyValueVisibility) == 0x000008, "Wrong alignment on UPropertyValueVisibility");
static_assert(sizeof(UPropertyValueVisibility) == 0x0001B8, "Wrong size on UPropertyValueVisibility");

// Class VariantManagerContent.PropertyValueColor
// 0x0000 (0x01B8 - 0x01B8)
class UPropertyValueColor final : public UPropertyValue
{
public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"PropertyValueColor">();
	}
	static class UPropertyValueColor* GetDefaultObj()
	{
		return GetDefaultObjImpl<UPropertyValueColor>();
	}
};
static_assert(alignof(UPropertyValueColor) == 0x000008, "Wrong alignment on UPropertyValueColor");
static_assert(sizeof(UPropertyValueColor) == 0x0001B8, "Wrong size on UPropertyValueColor");

// Class VariantManagerContent.PropertyValueMaterial
// 0x0000 (0x01B8 - 0x01B8)
class UPropertyValueMaterial final : public UPropertyValue
{
public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"PropertyValueMaterial">();
	}
	static class UPropertyValueMaterial* GetDefaultObj()
	{
		return GetDefaultObjImpl<UPropertyValueMaterial>();
	}
};
static_assert(alignof(UPropertyValueMaterial) == 0x000008, "Wrong alignment on UPropertyValueMaterial");
static_assert(sizeof(UPropertyValueMaterial) == 0x0001B8, "Wrong size on UPropertyValueMaterial");

// Class VariantManagerContent.PropertyValueOption
// 0x0000 (0x01B8 - 0x01B8)
class UPropertyValueOption final : public UPropertyValue
{
public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"PropertyValueOption">();
	}
	static class UPropertyValueOption* GetDefaultObj()
	{
		return GetDefaultObjImpl<UPropertyValueOption>();
	}
};
static_assert(alignof(UPropertyValueOption) == 0x000008, "Wrong alignment on UPropertyValueOption");
static_assert(sizeof(UPropertyValueOption) == 0x0001B8, "Wrong size on UPropertyValueOption");

// Class VariantManagerContent.PropertyValueSoftObject
// 0x0000 (0x01B8 - 0x01B8)
class UPropertyValueSoftObject final : public UPropertyValue
{
public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"PropertyValueSoftObject">();
	}
	static class UPropertyValueSoftObject* GetDefaultObj()
	{
		return GetDefaultObjImpl<UPropertyValueSoftObject>();
	}
};
static_assert(alignof(UPropertyValueSoftObject) == 0x000008, "Wrong alignment on UPropertyValueSoftObject");
static_assert(sizeof(UPropertyValueSoftObject) == 0x0001B8, "Wrong size on UPropertyValueSoftObject");

// Class VariantManagerContent.SwitchActor
// 0x0028 (0x0250 - 0x0228)
class ASwitchActor final : public AActor
{
public:
	uint8                                         Pad_24AA[0x18];                                    // 0x0228(0x0018)(Fixing Size After Last Property [ Dumper-7 ])
	class USceneComponent*                        SceneComponent;                                    // 0x0240(0x0008)(Edit, ExportObject, ZeroConstructor, EditConst, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
	int32                                         LastSelectedOption;                                // 0x0248(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
	uint8                                         Pad_24AB[0x4];                                     // 0x024C(0x0004)(Fixing Struct Size After Last Property [ Dumper-7 ])

public:
	void SelectOption(int32 OptionIndex);

	TArray<class AActor*> GetOptions() const;
	int32 GetSelectedOption() const;

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"SwitchActor">();
	}
	static class ASwitchActor* GetDefaultObj()
	{
		return GetDefaultObjImpl<ASwitchActor>();
	}
};
static_assert(alignof(ASwitchActor) == 0x000008, "Wrong alignment on ASwitchActor");
static_assert(sizeof(ASwitchActor) == 0x000250, "Wrong size on ASwitchActor");
static_assert(offsetof(ASwitchActor, SceneComponent) == 0x000240, "Member 'ASwitchActor::SceneComponent' has a wrong offset!");
static_assert(offsetof(ASwitchActor, LastSelectedOption) == 0x000248, "Member 'ASwitchActor::LastSelectedOption' has a wrong offset!");

// Class VariantManagerContent.Variant
// 0x0058 (0x0080 - 0x0028)
class UVariant final : public UObject
{
public:
	TArray<struct FVariantDependency>             Dependencies;                                      // 0x0028(0x0010)(ZeroConstructor, NativeAccessSpecifierPrivate)
	class FText                                   DisplayText;                                       // 0x0038(0x0018)(Deprecated, NativeAccessSpecifierPrivate)
	uint8                                         Pad_24AC[0x18];                                    // 0x0050(0x0018)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<class UVariantObjectBinding*>          ObjectBindings;                                    // 0x0068(0x0010)(ExportObject, ZeroConstructor, ContainsInstancedReference, NativeAccessSpecifierPrivate)
	class UTexture2D*                             Thumbnail;                                         // 0x0078(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate)

public:
	int32 AddDependency(struct FVariantDependency* Dependency);
	void DeleteDependency(int32 Param_Index);
	class AActor* GetActor(int32 ActorIndex);
	struct FVariantDependency GetDependency(int32 Param_Index);
	TArray<class UVariant*> GetDependents(class ULevelVariantSets* LevelVariantSets, bool bOnlyEnabledDependencies);
	int32 GetNumActors();
	int32 GetNumDependencies();
	class UVariantSet* GetParent();
	class UTexture2D* GetThumbnail();
	bool IsActive();
	void SetDependency(int32 Param_Index, struct FVariantDependency* Dependency);
	void SetDisplayText(const class FText& NewDisplayText);
	void SetThumbnailFromCamera(class UObject* WorldContextObject, const struct FTransform& CameraTransform, float FOVDegrees, float MinZ, float Gamma);
	void SetThumbnailFromEditorViewport();
	void SetThumbnailFromFile(const class FString& FilePath);
	void SetThumbnailFromTexture(class UTexture2D* NewThumbnail);
	void SwitchOn();

	class FText GetDisplayText() const;

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"Variant">();
	}
	static class UVariant* GetDefaultObj()
	{
		return GetDefaultObjImpl<UVariant>();
	}
};
static_assert(alignof(UVariant) == 0x000008, "Wrong alignment on UVariant");
static_assert(sizeof(UVariant) == 0x000080, "Wrong size on UVariant");
static_assert(offsetof(UVariant, Dependencies) == 0x000028, "Member 'UVariant::Dependencies' has a wrong offset!");
static_assert(offsetof(UVariant, DisplayText) == 0x000038, "Member 'UVariant::DisplayText' has a wrong offset!");
static_assert(offsetof(UVariant, ObjectBindings) == 0x000068, "Member 'UVariant::ObjectBindings' has a wrong offset!");
static_assert(offsetof(UVariant, Thumbnail) == 0x000078, "Member 'UVariant::Thumbnail' has a wrong offset!");

// Class VariantManagerContent.VariantObjectBinding
// 0x0068 (0x0090 - 0x0028)
class UVariantObjectBinding final : public UObject
{
public:
	class FString                                 CachedActorLabel;                                  // 0x0028(0x0010)(ZeroConstructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
	struct FSoftObjectPath                        ObjectPtr;                                         // 0x0038(0x0018)(ZeroConstructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
	TLazyObjectPtr<class UObject>                 LazyObjectPtr;                                     // 0x0050(0x001C)(IsPlainOldData, NoDestructor, UObjectWrapper, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
	uint8                                         Pad_24B4[0x4];                                     // 0x006C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<class UPropertyValue*>                 CapturedProperties;                                // 0x0070(0x0010)(ZeroConstructor, NativeAccessSpecifierPrivate)
	TArray<struct FFunctionCaller>                FunctionCallers;                                   // 0x0080(0x0010)(ZeroConstructor, NativeAccessSpecifierPrivate)

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"VariantObjectBinding">();
	}
	static class UVariantObjectBinding* GetDefaultObj()
	{
		return GetDefaultObjImpl<UVariantObjectBinding>();
	}
};
static_assert(alignof(UVariantObjectBinding) == 0x000008, "Wrong alignment on UVariantObjectBinding");
static_assert(sizeof(UVariantObjectBinding) == 0x000090, "Wrong size on UVariantObjectBinding");
static_assert(offsetof(UVariantObjectBinding, CachedActorLabel) == 0x000028, "Member 'UVariantObjectBinding::CachedActorLabel' has a wrong offset!");
static_assert(offsetof(UVariantObjectBinding, ObjectPtr) == 0x000038, "Member 'UVariantObjectBinding::ObjectPtr' has a wrong offset!");
static_assert(offsetof(UVariantObjectBinding, LazyObjectPtr) == 0x000050, "Member 'UVariantObjectBinding::LazyObjectPtr' has a wrong offset!");
static_assert(offsetof(UVariantObjectBinding, CapturedProperties) == 0x000070, "Member 'UVariantObjectBinding::CapturedProperties' has a wrong offset!");
static_assert(offsetof(UVariantObjectBinding, FunctionCallers) == 0x000080, "Member 'UVariantObjectBinding::FunctionCallers' has a wrong offset!");

// Class VariantManagerContent.VariantSet
// 0x0050 (0x0078 - 0x0028)
class UVariantSet final : public UObject
{
public:
	class FText                                   DisplayText;                                       // 0x0028(0x0018)(Deprecated, NativeAccessSpecifierPrivate)
	uint8                                         Pad_24B5[0x18];                                    // 0x0040(0x0018)(Fixing Size After Last Property [ Dumper-7 ])
	bool                                          bExpanded;                                         // 0x0058(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
	uint8                                         Pad_24B6[0x7];                                     // 0x0059(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<class UVariant*>                       Variants;                                          // 0x0060(0x0010)(ZeroConstructor, NativeAccessSpecifierPrivate)
	class UTexture2D*                             Thumbnail;                                         // 0x0070(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate)

public:
	class ULevelVariantSets* GetParent();
	class UTexture2D* GetThumbnail();
	class UVariant* GetVariant(int32 VariantIndex);
	class UVariant* GetVariantByName(const class FString& VariantName);
	void SetDisplayText(const class FText& NewDisplayText);
	void SetThumbnailFromCamera(class UObject* WorldContextObject, const struct FTransform& CameraTransform, float FOVDegrees, float MinZ, float Gamma);
	void SetThumbnailFromEditorViewport();
	void SetThumbnailFromFile(const class FString& FilePath);
	void SetThumbnailFromTexture(class UTexture2D* NewThumbnail);

	class FText GetDisplayText() const;
	int32 GetNumVariants() const;

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"VariantSet">();
	}
	static class UVariantSet* GetDefaultObj()
	{
		return GetDefaultObjImpl<UVariantSet>();
	}
};
static_assert(alignof(UVariantSet) == 0x000008, "Wrong alignment on UVariantSet");
static_assert(sizeof(UVariantSet) == 0x000078, "Wrong size on UVariantSet");
static_assert(offsetof(UVariantSet, DisplayText) == 0x000028, "Member 'UVariantSet::DisplayText' has a wrong offset!");
static_assert(offsetof(UVariantSet, bExpanded) == 0x000058, "Member 'UVariantSet::bExpanded' has a wrong offset!");
static_assert(offsetof(UVariantSet, Variants) == 0x000060, "Member 'UVariantSet::Variants' has a wrong offset!");
static_assert(offsetof(UVariantSet, Thumbnail) == 0x000070, "Member 'UVariantSet::Thumbnail' has a wrong offset!");

}

