using UnrealBuildTool;
using System.IO;

public class Quilkin : ModuleRules
{
	public Quilkin(ReadOnlyTargetRules Target) : base(Target)
	{
		PCHUsage = PCHUsageMode.UseExplicitOrSharedPCHs;

		PrivateDependencyModuleNames.AddRange(new string[] {
			"Sockets",
			"Json",
			"Engine"
		});

		PublicDependencyModuleNames.AddRange(new string[] {
			"Core",
			"CoreUObject",
		});
	}
}
