
#include "Precomp.h"
#include "UClass.h"
#include "UEnum.h"
#include "Properties/UPointerProperty.h"
#include "Properties/UIntProperty.h"
#include "Properties/UClassProperty.h"
#include "Properties/UNameProperty.h"
#include "Properties/UStringProperty.h"
#include "Properties/UStrProperty.h"
#include "Properties/UBoolProperty.h"
#include "Properties/UByteProperty.h"
#include "Properties/UFloatProperty.h"
#include "Properties/UArrayProperty.h"
#include "VM/Bytecode.h"
#include "VM/NativeFunc.h"
#include "VM/ScriptCall.h"
#include "Package/PackageManager.h"
#include "Engine.h"
#include <cstdlib>

UClass::UClass(NameString name, UClass* base, ObjectFlags flags) : UState(std::move(name), nullptr, flags, base)
{
	if (base)
		ClsFlags = base->ClsFlags;

	if (name == "Object")
	{
		// Object is special as its the base class for everything. Described in Core.u with circular references.
		// This creates just enough of the properties to resolve it, hopefully.

		if (engine->LaunchInfo.IsUnrealTournament_469()) // 469 changed ObjectInternal from int to pointer
		{
			auto objInternal = GC::Alloc<UPointerProperty>("ObjectInternal", nullptr, ObjectFlags::Native);
			objInternal->ArrayDimension = 6;
			Properties.push_back(objInternal);
		}
		else if (!engine->LaunchInfo.IsUnreal1_227k()) // Unreal 227k has removed ObjectInternal entirely
		{
			auto objInternal = GC::Alloc<UIntProperty>("ObjectInternal", nullptr, ObjectFlags::Native);
			objInternal->ArrayDimension = 6;
			Properties.push_back(objInternal);
		}

		if (engine->LaunchInfo.IsUnreal1_227k())
			Properties.push_back(GC::Alloc<UIntProperty>("ObjectIndex", nullptr, ObjectFlags::Native));
		Properties.push_back(GC::Alloc<UObjectProperty>("Outer", nullptr, ObjectFlags::Native));
		if (engine->LaunchInfo.IsUnreal1_227k())
			Properties.push_back(GC::Alloc<UObjectProperty>("ObjectArchetype", nullptr, ObjectFlags::Native));
		Properties.push_back(GC::Alloc<UIntProperty>("ObjectFlags", nullptr, ObjectFlags::Native));
		Properties.push_back(GC::Alloc<UNameProperty>("Name", nullptr, ObjectFlags::Native));
		Properties.push_back(GC::Alloc<UClassProperty>("Class", nullptr, ObjectFlags::Native));

		size_t offset = 0;
		size_t structAlignment = 1;
		for (UProperty* prop : Properties)
		{
			size_t alignment = prop->ArrayAlignment();
			size_t size = prop->ArraySize();
			prop->DataOffset.DataOffset = (offset + alignment - 1) / alignment * alignment;
			offset = prop->DataOffset.DataOffset + size;
			structAlignment = std::max(structAlignment, alignment);
		}
		StructAlignment = structAlignment;
		StructSize = offset;
	}
}

void UClass::Load(ObjectStream* stream)
{
	UState::Load(stream);

	if (stream->GetVersion() <= 61)
	{
		OldClassRecordSize = stream->ReadUInt32();
		Flags = Flags | ObjectFlags::Public | ObjectFlags::Standalone;
	}

	ClsFlags = (ClassFlags)stream->ReadUInt32();
	stream->ReadBytes(ClassGuid.Data, 16);

	int NumDependencies = stream->ReadIndex();
	for (int i = 0; i < NumDependencies; i++)
	{
		ClassDependency dep;
		dep.Class = stream->ReadObject<UClass>();
		dep.Deep = stream->ReadUInt32();
		dep.ScriptTextCRC = stream->ReadUInt32();
		Dependencies.push_back(dep);
	}

	int NumPackageImports = stream->ReadIndex();
	for (int i = 0; i < NumPackageImports; i++)
		PackageImports.push_back(stream->ReadIndex());

	if (stream->GetVersion() >= 62)
	{
		ClassWithin = stream->ReadIndex();
		ClassConfigName = stream->ReadName();
	}

	PropertyData.Init(this);
	PropertyData.Load(stream);

	// Copy native UObject properties into the VM
	SetObject("Class", this);
	SetName("Name", Name);
	SetInt("ObjectFlags", (int)Flags);

	LoadProperties(&PropertyData);

	for (UField* child = Children; child; child = child->Next)
	{
		if (auto state = UObject::TryCast<UState>(child))
		{
			States[child->Name] = state;
		}
	}
}

void UClass::Save(PackageStreamWriter* stream)
{
	UState::Save(stream);

	if (stream->GetVersion() <= 61)
		stream->WriteUInt32(OldClassRecordSize);

	stream->WriteUInt32((uint32_t)ClsFlags);
	stream->WriteBytes(ClassGuid.Data, 16);

	stream->WriteIndex((int)Dependencies.size());
	for (const ClassDependency& dep : Dependencies)
	{
		stream->WriteObject(dep.Class);
		stream->WriteUInt32(dep.Deep);
		stream->WriteUInt32(dep.ScriptTextCRC);
	}

	stream->WriteIndex((int)PackageImports.size());
	for (int v : PackageImports)
		stream->WriteIndex(v);

	if (stream->GetVersion() >= 62)
	{
		stream->WriteIndex(ClassWithin);
		stream->WriteName(ClassConfigName);
	}

	PropertyData.Save(stream, nullptr);
}

std::map<NameString, std::string> UClass::ParseStructValue(const std::string& text)
{
	// Parse one of the following:
	//
	// Object=(Name=Package.ObjectName,Class=ObjectClass,MetaClass=Package.MetaClassName,Description="descriptive string")
	// Preferences=(Caption="display name",Parent="display name of parent",Class=Package.ClassName,Category=variable group name,Immediate=True)

	if (text.size() < 2 || text.front() != '(' || text.back() != ')')
		return {};

	std::map<NameString, std::string> desc;

	// This would have been so much easier with a regular expression, but we can't use that as we have no idea what character set those .int files might be using
	size_t pos = 1;
	while (pos < text.size() - 1)
	{
		size_t endpos = text.find('=', pos);
		if (endpos == std::string::npos)
			break;
		NameString keyname = text.substr(pos, endpos - pos);
		pos = endpos + 1;

		if (text[pos] == '"')
		{
			pos++;
			endpos = text.find('"', pos);
			if (endpos == std::string::npos)
				break;

			std::string value = text.substr(pos, endpos - pos);
			desc[keyname] = value;
			pos++;

			pos = text.find(',', pos);
			if (pos == std::string::npos)
				break;
			pos++;
		}
		else
		{
			endpos = text.find_first_of(",)", pos);
			if (endpos == std::string::npos)
				break;
			std::string value = text.substr(pos, endpos - pos);
			desc[keyname] = value;
			pos = endpos + 1;
		}
	}

	return desc;
}

UProperty* UClass::GetProperty(const NameString& propName)
{
	for (UProperty* prop : PropertyData.Class->Properties)
	{
		if (prop->Name == propName)
			return prop;
	}
	Exception::Throw("Class Property '" + Name.ToString() + "." + propName.ToString() + "' not found");
}

void UClass::SaveConfig()
{
	// Saves the default object properties to the ini file
	SaveProperties(&PropertyData);
}

namespace
{
	// Assigns a single dynamic-array element's value from its ini string representation, mirroring
	// the per-type dispatch UClass::LoadProperties() already uses for scalar and fixed-size array
	// config properties. Class-typed elements are resolved via the given PackageManager the same
	// way UClassProperty is handled elsewhere in this file.
	void LoadConfigArrayElement(PackageManager* pm, UProperty* elementProp, void* ptr, const std::string& value)
	{
		if (auto byteprop = UObject::TryCast<UByteProperty>(elementProp))
		{
			if (!value.empty() && value.front() >= '0' && value.front() <= '9')
			{
				*static_cast<uint8_t*>(ptr) = (uint8_t)std::atoi(value.c_str());
			}
			else if (byteprop->EnumType)
			{
				int index = 0;
				for (const NameString& elementName : byteprop->EnumType->ElementNames)
				{
					if (elementName == value)
					{
						*static_cast<uint8_t*>(ptr) = (uint8_t)index;
						break;
					}
					index++;
				}
			}
		}
		else if (UObject::IsType<UIntProperty>(elementProp)) *static_cast<int32_t*>(ptr) = (int32_t)std::atoi(value.c_str());
		else if (UObject::IsType<UFloatProperty>(elementProp)) *static_cast<float*>(ptr) = (float)std::atof(value.c_str());
		else if (UObject::IsType<UNameProperty>(elementProp)) *static_cast<NameString*>(ptr) = value;
		else if (UObject::IsType<UStrProperty>(elementProp)) *static_cast<std::string*>(ptr) = value;
		else if (UObject::IsType<UStringProperty>(elementProp)) *static_cast<std::string*>(ptr) = value;
		else if (auto boolprop = UObject::TryCast<UBoolProperty>(elementProp))
		{
			std::string lower = value;
			for (char& c : lower)
				if (c >= 'A' && c <= 'Z')
					c += 'a' - 'A';
			boolprop->SetBool(ptr, lower == "1" || lower == "true" || lower == "yes");
		}
		else if (UObject::IsType<UClassProperty>(elementProp))
		{
			try
			{
				size_t pos = value.find_first_of('.');
				if (pos != std::string::npos)
				{
					NameString packageName = value.substr(0, pos);
					NameString className = value.substr(pos + 1);
					Package* pkg = pm->GetPackage(packageName);
					*static_cast<UObject**>(ptr) = pkg->GetUObject("Class", className);
				}
			}
			catch (...)
			{
			}
		}
		// Other element types (struct, nested array, object) aren't handled here yet.
	}

	// Reads every indexed ini entry for a dynamic array config property (Key[0]=, Key[1]=, ...)
	// and populates the array to match. UClass::LoadProperties()'s normal per-property loop below
	// only handles FIXED-size arrays (prop->ArrayDimension, e.g. WeaponPriority[50]) - a dynamic
	// array property has ArrayDimension 1 and no engine support at all for loading its config
	// values, so it silently stayed empty regardless of what was in the ini, with no error. This
	// is that missing piece: UBrowserAll's ListFactories (the list of master server query
	// factories the internet server browser uses) is exactly this kind of property, which is why
	// populating it in the ini alone had no observable effect - the object holding it never
	// actually read those values into its own memory.
	void LoadConfigArrayProperty(PackageManager* pm, const NameString& configName, const NameString& sectionName, const NameString& name, UArrayProperty* arrayprop, void* ptr)
	{
		static const bool debugConfig = std::getenv("SE_DEBUG_CONFIG") != nullptr;

		if (!arrayprop->Inner)
		{
			if (debugConfig)
				fprintf(stderr, "[Config] LoadConfigArrayProperty: [%s] %s has no Inner element type, skipped\n", sectionName.ToString().c_str(), name.ToString().c_str());
			return;
		}

		Array<std::string> values = pm->GetIniValues(configName, sectionName, name);
		if (debugConfig)
			fprintf(stderr, "[Config] LoadConfigArrayProperty: [%s] %s -> %d ini value(s) found\n", sectionName.ToString().c_str(), name.ToString().c_str(), (int)values.size());
		if (values.empty())
			return;

		ScriptArray* arr = static_cast<ScriptArray*>(ptr);
		if (debugConfig)
			fprintf(stderr, "[Config] LoadConfigArrayProperty: [%s] %s populated with %d element(s)\n", sectionName.ToString().c_str(), name.ToString().c_str(), (int)values.size());
		arr->Resize(values.size());
		for (size_t i = 0; i < values.size(); i++)
			LoadConfigArrayElement(pm, arrayprop->Inner, arr->GetItem(i), values[i]);
	}

	// Save-side counterpart of LoadConfigArrayElement, mirroring UClass::SaveProperties()'s own
	// per-type stringification. Returns false for element types it doesn't know how to stringify
	// (struct, nested array, object), which the caller skips rather than writing a blank entry.
	bool SaveConfigArrayElement(UProperty* elementProp, void* ptr, std::string& out)
	{
		if (UObject::IsType<UByteProperty>(elementProp)) out = std::to_string(*static_cast<uint8_t*>(ptr));
		else if (UObject::IsType<UIntProperty>(elementProp)) out = std::to_string(*static_cast<int32_t*>(ptr));
		else if (UObject::IsType<UFloatProperty>(elementProp)) out = std::to_string(*static_cast<float*>(ptr));
		else if (UObject::IsType<UNameProperty>(elementProp)) out = (*static_cast<NameString*>(ptr)).ToString();
		else if (UObject::IsType<UStrProperty>(elementProp)) out = *static_cast<std::string*>(ptr);
		else if (UObject::IsType<UStringProperty>(elementProp)) out = *static_cast<std::string*>(ptr);
		else if (auto boolprop = UObject::TryCast<UBoolProperty>(elementProp)) out = boolprop->GetBool(ptr) ? "True" : "False";
		else return false;
		return true;
	}

	// Save-side counterpart of LoadConfigArrayProperty: writes a dynamic array's elements back out
	// as indexed ini entries (Key[0]=, Key[1]=, ...), which UClass::SaveProperties()'s normal loop
	// below has no support for either (same gap as the load side).
	void SaveConfigArrayProperty(PackageManager* pm, const NameString& configName, const NameString& sectionName, const NameString& name, UArrayProperty* arrayprop, void* ptr)
	{
		if (!arrayprop->Inner)
			return;

		ScriptArray* arr = static_cast<ScriptArray*>(ptr);
		Array<std::string> values;
		values.reserve(arr->GetSize());
		for (size_t i = 0, count = arr->GetSize(); i < count; i++)
		{
			std::string value;
			if (SaveConfigArrayElement(arrayprop->Inner, arr->GetItem(i), value))
				values.push_back(value);
		}
		if (!values.empty())
			pm->SetIniValues(configName, sectionName, name, values, true);
	}
}

void UClass::LoadProperties(PropertyDataBlock* propertyBlock, UObject* instance)
{
	// PerObjectConfig classes (e.g. UBrowserAll/UBrowserUT/UBrowserLAN, all instances of the same
	// browser-list class, each holding its own ListFactories) store their config under a section
	// named after the OBJECT instance, not Package.ClassName - confirmed from a real UT99
	// UnrealTournament.ini, which has a bare "[UBrowserAll]" section, not "[UBrowser.UBrowserAll]".
	// Package::NewObject() never used to load config into newly constructed instances at all
	// (it only copied class defaults), so this path previously never ran for these objects -
	// this was the actual reason ListFactories always loaded empty regardless of the dynamic-array
	// property support added above: the section name computed below was simply never the one the
	// real per-object ini values live under.
	static const bool debugConfig = std::getenv("SE_DEBUG_CONFIG") != nullptr;
	bool perObjectConfig = instance && (ClsFlags & ClassFlags::PerObjectConfig);
	NameString sectionName = perObjectConfig ? instance->Name : NameString(package->GetPackageName().ToString() + "." + Name.ToString());
	NameString configName = ClassConfigName;
	if (configName.IsNone()) configName = "system";
	if (debugConfig && instance)
	{
		fprintf(stderr, "[Config] LoadProperties() called on instance %s of class %s (PerObjectConfig %s, section [%s])\n",
			instance->Name.ToString().c_str(), Name.ToString().c_str(), perObjectConfig ? "set" : "NOT set", sectionName.ToString().c_str());
		// Dump every property this class actually has, to check whether ListFactories (or
		// whatever holds the master server factory list) is even present here, and if so whether
		// it's flagged Config/GlobalConfig - if it's missing from this dump entirely, ListFactories
		// must live on a different object than the one named "UBrowserAll" that LoadProperties()
		// is being called on here.
		for (UProperty* p : Properties)
		{
			const char* typeName =
				UObject::TryCast<UArrayProperty>(p) ? "Array" :
				UObject::TryCast<UStructProperty>(p) ? "Struct" :
				UObject::TryCast<UClassProperty>(p) ? "Class" :
				UObject::TryCast<UObjectProperty>(p) ? "Object" :
				UObject::TryCast<UStrProperty>(p) ? "Str" :
				UObject::TryCast<UStringProperty>(p) ? "String" :
				UObject::TryCast<UNameProperty>(p) ? "Name" :
				UObject::TryCast<UBoolProperty>(p) ? "Bool" :
				UObject::TryCast<UByteProperty>(p) ? "Byte" :
				UObject::TryCast<UIntProperty>(p) ? "Int" :
				UObject::TryCast<UFloatProperty>(p) ? "Float" : "Other";
			fprintf(stderr, "[Config]   property %s type=%s dim=%d (Config=%s, GlobalConfig=%s)\n",
				p->Name.ToString().c_str(), typeName, p->ArrayDimension,
				AnyFlags(p->PropFlags, PropertyFlags::Config) ? "yes" : "no",
				AnyFlags(p->PropFlags, PropertyFlags::GlobalConfig) ? "yes" : "no");
		}
	}
	for (UProperty* prop : Properties)
	{
		if (AnyFlags(prop->PropFlags, PropertyFlags::Config | PropertyFlags::GlobalConfig | PropertyFlags::Localized))
		{
			void* ptr = propertyBlock->Ptr(prop);

			if (auto arrayprop = UObject::TryCast<UArrayProperty>(prop))
			{
				if (AllFlags(prop->PropFlags, PropertyFlags::GlobalConfig))
				{
					if (UClass* outer = UObject::TryCast<UClass>(prop->Outer()))
					{
						NameString outerSectionName = outer->package->GetPackageName().ToString() + "." + outer->Name.ToString();
						NameString outerConfigName = outer->ClassConfigName;
						if (outerConfigName.IsNone()) outerConfigName = "system";
						LoadConfigArrayProperty(package->GetPackageManager(), outerConfigName, outerSectionName, prop->Name, arrayprop, ptr);
					}
				}
				else if (AllFlags(prop->PropFlags, PropertyFlags::Config))
				{
					LoadConfigArrayProperty(package->GetPackageManager(), configName, sectionName, prop->Name, arrayprop, ptr);
				}
				continue;
			}

			for (int arrayIndex = 0; arrayIndex < prop->ArrayDimension; arrayIndex++)
			{
				// Bug: ini keys are stored bare ("ListFactories"), with the "[N]=" index parsed
				// out separately (see IniKey/IniSection) - looking them up by a key literally
				// named "ListFactories[0]" (as this used to do) can never match, so every fixed-
				// size (ArrayDimension > 1) config array property silently loaded as empty
				// regardless of what the ini said. GetIniValue()'s `index` parameter is how you're
				// meant to select the Nth value of the (bare-named) key.
				NameString name = prop->Name;
				NameString displayName = prop->ArrayDimension > 1 ? NameString(name.ToString() + "[" + std::to_string(arrayIndex) + "]") : name;

				bool traceThis = debugConfig && (prop->Name == "ListFactories" || prop->Name == "ServerListNames");
				NameString usedIniName, usedSectionName;

				std::string value;
				if (AllFlags(prop->PropFlags, PropertyFlags::GlobalConfig))
				{
					if (UClass* outer = UObject::TryCast<UClass>(prop->Outer()))
					{
						NameString outerSectionName = outer->package->GetPackageName().ToString() + "." + outer->Name.ToString();
						NameString outerConfigName = outer->ClassConfigName;
						if (outerConfigName.IsNone()) outerConfigName = "system";
						value = package->GetPackageManager()->GetIniValue(outerConfigName, outerSectionName, name, "", arrayIndex);
						usedIniName = outerConfigName;
						usedSectionName = outerSectionName;
					}
					else if (traceThis)
					{
						fprintf(stderr, "[Config]   %s: prop->Outer() is not a UClass - GlobalConfig lookup skipped entirely\n", displayName.ToString().c_str());
					}
				}
				else if (AllFlags(prop->PropFlags, PropertyFlags::Config))
				{
					value = package->GetPackageManager()->GetIniValue(configName, sectionName, name, "", arrayIndex);
					usedIniName = configName;
					usedSectionName = sectionName;
				}
				else if (AllFlags(prop->PropFlags, PropertyFlags::Localized))
				{
					value = package->GetPackageManager()->Localize(package->GetPackageName(), Name, displayName);
				}

				if (traceThis)
				{
					fprintf(stderr, "[Config]   %s (ini \"%s\", section [%s], instance=%s) -> %s\n",
						displayName.ToString().c_str(), usedIniName.ToString().c_str(), usedSectionName.ToString().c_str(),
						instance ? instance->Name.ToString().c_str() : "(class default)",
						value.empty() ? "(empty)" : ("\"" + value + "\"").c_str());
				}

				if (!value.empty())
				{
					if (auto byteprop = UObject::TryCast<UByteProperty>(prop))
					{
						if (value.front() >= '0' && value.front() <= '9')
						{
							*static_cast<uint8_t*>(ptr) = (uint8_t)std::atoi(value.c_str());
						}
						else if (byteprop->EnumType)
						{
							int index = 0;
							for (const NameString& elementName : byteprop->EnumType->ElementNames)
							{
								if (elementName == value)
								{
									*static_cast<uint8_t*>(ptr) = (uint8_t)index;
									break;
								}
								index++;
							}
						}
					}
					else if (UObject::IsType<UIntProperty>(prop)) *static_cast<int32_t*>(ptr) = (int32_t)std::atoi(value.c_str());
					else if (UObject::IsType<UFloatProperty>(prop)) *static_cast<float*>(ptr) = (float)std::atof(value.c_str());
					else if (UObject::IsType<UNameProperty>(prop)) *static_cast<NameString*>(ptr) = value;
					else if (UObject::IsType<UStrProperty>(prop)) *static_cast<std::string*>(ptr) = value;
					else if (UObject::IsType<UStringProperty>(prop)) *static_cast<std::string*>(ptr) = value;
					else if (auto boolprop = UObject::TryCast<UBoolProperty>(prop))
					{
						for (char& c : value)
							if (c >= 'A' && c <= 'Z')
								c += 'a' - 'A';
						boolprop->SetBool(ptr, value == "1" || value == "true" || value == "yes");
					}
					else if (UObject::IsType<UClassProperty>(prop))
					{
						try
						{
							size_t pos = value.find_first_of('.');
							if (pos != std::string::npos)
							{
								NameString packageName = value.substr(0, pos);
								NameString className = value.substr(pos + 1);
								Package* pkg = package->GetPackageManager()->GetPackage(packageName);
								*static_cast<UObject**>(ptr) = pkg->GetUObject("Class", className);
							}
						}
						catch (...)
						{
							// To do: is this actually a fatal error?
						}
					}
					else if (auto structprop = UObject::TryCast<UStructProperty>(prop))
					{
						// Yes, this is total spaghetti code at this point. No, I don't care anymore. ;)
						auto values = ParseStructValue(value);
						for (UProperty* member : structprop->Struct->Properties)
						{
							std::string membervalue = values[member->Name];
							void* memberptr = static_cast<uint8_t*>(ptr) + member->DataOffset.DataOffset;
							if (auto byteprop = UObject::TryCast<UByteProperty>(member))
							{
								if (!membervalue.empty() && membervalue.front() >= '0' && membervalue.front() <= '9')
								{
									*static_cast<uint8_t*>(memberptr) = (uint8_t)std::atoi(membervalue.c_str());
								}
								else if (byteprop->EnumType)
								{
									int index = 0;
									for (const NameString& elementName : byteprop->EnumType->ElementNames)
									{
										if (elementName == membervalue)
										{
											*static_cast<uint8_t*>(memberptr) = (uint8_t)index;
											break;
										}
										index++;
									}
								}
							}
							else if (UObject::IsType<UIntProperty>(member)) *static_cast<int32_t*>(memberptr) = (int32_t)std::atoi(membervalue.c_str());
							else if (UObject::IsType<UFloatProperty>(member)) *static_cast<float*>(memberptr) = (float)std::atof(membervalue.c_str());
							else if (UObject::IsType<UNameProperty>(member)) *static_cast<NameString*>(memberptr) = membervalue;
							else if (UObject::IsType<UStrProperty>(member)) *static_cast<std::string*>(memberptr) = membervalue;
							else if (UObject::IsType<UStringProperty>(member)) *static_cast<std::string*>(memberptr) = membervalue;
							else if (auto boolprop = UObject::TryCast<UBoolProperty>(member))
							{
								for (char& c : membervalue)
									if (c >= 'A' && c <= 'Z')
										c += 'a' - 'A';
								boolprop->SetBool(memberptr, membervalue == "1" || membervalue == "true" || membervalue == "yes");
							}
							else if (UObject::IsType<UClassProperty>(member))
							{
								try
								{
									size_t pos = membervalue.find_first_of('.');
									if (pos != std::string::npos)
									{
										NameString packageName = membervalue.substr(0, pos);
										NameString className = membervalue.substr(pos + 1);
										Package* pkg = package->GetPackageManager()->GetPackage(packageName);
										*static_cast<UObject**>(memberptr) = pkg->GetUObject("Class", className);
									}
								}
								catch (...)
								{
									// To do: is this actually a fatal error?
								}
							}
							else if (UObject::IsType<UObjectProperty>(member))
							{
								// This happens for Deus Ex
							}
							else
							{
								Exception::Throw("localize keyword used on unsupported struct member property type");
							}
						}
					}
					else
					{
						Exception::Throw("localize keyword used on unsupported property type");
					}
				}

				ptr = static_cast<uint8_t*>(ptr) + prop->ElementPitch();
			}
		}
	}
}

void UClass::SaveProperties(PropertyDataBlock* propertyBlock, UObject* instance)
{
	// Diagnostic: set SE_DEBUG_CONFIG=1 to trace every SaveProperties() call and whether it's
	// actually allowed to write anything - a class whose ClassFlags don't include Config never
	// gets its config/globalconfig properties saved at all, silently, regardless of how those
	// individual properties are flagged. Useful for tracking down a setting that looks like it
	// should persist (e.g. a config property visible in the game's own ini) but doesn't survive
	// a restart when changed through SurrealEngine.
	static const bool debugConfig = std::getenv("SE_DEBUG_CONFIG") != nullptr;
	if (debugConfig)
	{
		fprintf(stderr, "[Config] SaveProperties() called on class %s (ClassFlags::Config %s)\n",
			Name.ToString().c_str(), (ClsFlags & ClassFlags::Config) ? "set" : "NOT set - saving skipped entirely");
	}

	if (!(ClsFlags & ClassFlags::Config))
		return;

	// See LoadProperties() for why PerObjectConfig instances (UBrowserAll and siblings) need the
	// section name to be their own bare object Name rather than Package.ClassName.
	bool perObjectConfig = instance && (ClsFlags & ClassFlags::PerObjectConfig);
	NameString sectionName = perObjectConfig ? instance->Name : NameString(package->GetPackageName().ToString() + "." + Name.ToString());
	NameString configName = ClassConfigName;
	if (configName.IsNone()) configName = "system";

	for (UProperty* prop : Properties)
	{
		if (AnyFlags(prop->PropFlags, PropertyFlags::Config | PropertyFlags::GlobalConfig))
		{
			auto ptr = propertyBlock->Ptr(prop);

			if (auto arrayprop = UObject::TryCast<UArrayProperty>(prop))
			{
				if (AllFlags(prop->PropFlags, PropertyFlags::GlobalConfig))
				{
					if (UClass* outer = UObject::TryCast<UClass>(prop->Outer()))
					{
						NameString outerSectionName = outer->package->GetPackageName().ToString() + "." + outer->Name.ToString();
						NameString outerConfigName = outer->ClassConfigName;
						if (outerConfigName.IsNone()) outerConfigName = "system";
						SaveConfigArrayProperty(package->GetPackageManager(), outerConfigName, outerSectionName, prop->Name, arrayprop, ptr);
					}
				}
				else if (AllFlags(prop->PropFlags, PropertyFlags::Config))
				{
					SaveConfigArrayProperty(package->GetPackageManager(), configName, sectionName, prop->Name, arrayprop, ptr);
				}
				if (debugConfig)
					fprintf(stderr, "[Config]   array property %s saved\n", prop->Name.ToString().c_str());
				continue;
			}

			for (int arrayIndex = 0; arrayIndex < prop->ArrayDimension; arrayIndex++)
			{
				// See the matching bug/fix note in LoadProperties(): ini keys are stored bare, so
				// the lookup/write index has to go through SetIniValue()'s `index` parameter
				// rather than being baked into the key name as "Key[N]" - that string was never a
				// real key, so every fixed-size config array silently failed to round-trip.
				NameString name = prop->Name;
				bool indexed = prop->ArrayDimension > 1;
				NameString displayName = indexed ? NameString(name.ToString() + "[" + std::to_string(arrayIndex) + "]") : name;

				bool unsupported = false;
				std::string value;
				if (UObject::IsType<UByteProperty>(prop)) value = std::to_string(*static_cast<uint8_t*>(ptr));
				else if (UObject::IsType<UIntProperty>(prop)) value = std::to_string(*static_cast<int32_t*>(ptr));
				else if (UObject::IsType<UFloatProperty>(prop)) value = std::to_string(*static_cast<float*>(ptr));
				else if (UObject::IsType<UNameProperty>(prop)) value = (*static_cast<NameString*>(ptr)).ToString();
				else if (UObject::IsType<UStrProperty>(prop)) value = *static_cast<std::string*>(ptr);
				else if (UObject::IsType<UStringProperty>(prop)) value = *static_cast<std::string*>(ptr);
				else if (auto boolprop = UObject::TryCast<UBoolProperty>(prop)) value = boolprop->GetBool(ptr) ? "True" : "False";
				else unsupported = true;

				if (debugConfig)
				{
					fprintf(stderr, "[Config]   property %s = \"%s\" (%s%s)\n", displayName.ToString().c_str(), value.c_str(),
						unsupported ? "UNSUPPORTED TYPE, not saved" : "saving",
						AnyFlags(prop->PropFlags, PropertyFlags::GlobalConfig) ? ", GlobalConfig" :
							AnyFlags(prop->PropFlags, PropertyFlags::Config) ? ", Config" : "");
				}

				if (!unsupported)
				{
					if (AnyFlags(prop->PropFlags, PropertyFlags::GlobalConfig))
					{
						if (UClass* outer = UObject::TryCast<UClass>(prop->Outer()))
						{
							NameString outerSectionName = outer->package->GetPackageName().ToString() + "." + outer->Name.ToString();
							NameString outerConfigName = outer->ClassConfigName;
							if (outerConfigName.IsNone()) outerConfigName = "system";
							package->GetPackageManager()->SetIniValue(outerConfigName, outerSectionName, name, value, arrayIndex, indexed);
						}
					}
					else if (AnyFlags(prop->PropFlags, PropertyFlags::Config))
					{
						package->GetPackageManager()->SetIniValue(configName, sectionName, name, value, arrayIndex, indexed);
					}
				}
				ptr = static_cast<uint8_t*>(ptr) + prop->ElementPitch();
			}
		}
	}

	if (propertyBlock != &PropertyData)
	{
		// If its not our own block getting saved we need to load them into our default block
		LoadProperties(&PropertyData);
	}

	// GlobalConfig properties are shared across the whole class hierarchy that
	// declares them, so a change must propagate to every class deriving from the
	// *declaring* class - not just classes deriving from `this`. Otherwise sibling
	// classes (e.g. UMenuLoadGameClientWindow vs UMenuSaveGameClientWindow, which
	// both inherit globalconfig SlotNames[] from UMenuSlotClientWindow) keep a stale
	// default until the next restart re-reads the ini.
	Array<UStruct*> propagationRoots;
	propagationRoots.push_back(this);
	for (UProperty* prop : Properties)
	{
		if (AnyFlags(prop->PropFlags, PropertyFlags::GlobalConfig))
		{
			if (UClass* declaring = UObject::TryCast<UClass>(prop->Outer()))
			{
				bool known = false;
				for (UStruct* root : propagationRoots)
					if (root == declaring) { known = true; break; }
				if (!known)
					propagationRoots.push_back(declaring);
			}
		}
	}

	for (GCObject* gcObj : GC::GetObjects())
	{
		if (UClass* cls = dynamic_cast<UClass*>(gcObj))
		{
			bool propagate = false;
			for (UStruct* base = cls; base && !propagate; base = base->BaseStruct)
			{
				for (UStruct* root : propagationRoots)
				{
					if (base == root)
					{
						propagate = true;
						break;
					}
				}
			}
			// Reload through cls's own property list (not this->Properties), so the
			// property offsets match cls's data block. this->Properties can be a
			// superset of an ancestor/sibling's layout and would overrun its block.
			if (propagate && cls != this)
				cls->LoadProperties(&cls->PropertyData);
		}
	}
}
