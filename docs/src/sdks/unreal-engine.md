# Quilkin Unreal Engine Plugin

This is an alpha version of the Unreal Engine plugin for Quilkin. Currently it only supports adding a routing token in the following format.

```
<packet> | token    | version
X bytes  | 16 bytes | 1 bytes
```

## How to install
To get this client proxy installed, the SDK should be located in `Engine` path for Plugins, so copy the whole `ue4` folder (resides under `sdks` folder) in your Unreal Engine path `/[UE4 Root]/Engine/Plugins`, then you may want to rename the ue4 folder to `Quilkin`. Unreal Engine will automatically discover the plugin by searching for `.uplugin` file.
