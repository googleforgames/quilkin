(function() {var implementors = {};
implementors["quilkin"] = [{"text":"impl JsonSchema for <a class=\"enum\" href=\"quilkin/metadata/enum.Value.html\" title=\"enum quilkin::metadata::Value\">Value</a>","synthetic":false,"types":["quilkin::metadata::Value"]},{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.63.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> + JsonSchema&gt; JsonSchema for <a class=\"struct\" href=\"quilkin/metadata/struct.MetadataView.html\" title=\"struct quilkin::metadata::MetadataView\">MetadataView</a>&lt;T&gt;","synthetic":false,"types":["quilkin::metadata::MetadataView"]},{"text":"impl JsonSchema for <a class=\"enum\" href=\"quilkin/config/enum.ConfigType.html\" title=\"enum quilkin::config::ConfigType\">ConfigType</a>","synthetic":false,"types":["quilkin::config::config_type::ConfigType"]},{"text":"impl&lt;T:&nbsp;JsonSchema + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.63.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>&gt; JsonSchema for <a class=\"struct\" href=\"quilkin/config/struct.Slot.html\" title=\"struct quilkin::config::Slot\">Slot</a>&lt;T&gt;","synthetic":false,"types":["quilkin::config::slot::Slot"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/config/watch/agones/crd/struct.GameServer.html\" title=\"struct quilkin::config::watch::agones::crd::GameServer\">GameServer</a>","synthetic":false,"types":["quilkin::config::watch::agones::crd::GameServer"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/config/watch/agones/crd/struct.Inner.html\" title=\"struct quilkin::config::watch::agones::crd::Inner\">Inner</a>","synthetic":false,"types":["quilkin::config::watch::agones::crd::Inner"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/config/watch/agones/crd/struct.GameServerSpec.html\" title=\"struct quilkin::config::watch::agones::crd::GameServerSpec\">GameServerSpec</a>","synthetic":false,"types":["quilkin::config::watch::agones::crd::GameServerSpec"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/config/watch/agones/crd/struct.Health.html\" title=\"struct quilkin::config::watch::agones::crd::Health\">Health</a>","synthetic":false,"types":["quilkin::config::watch::agones::crd::Health"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/config/watch/agones/crd/struct.GameServerPort.html\" title=\"struct quilkin::config::watch::agones::crd::GameServerPort\">GameServerPort</a>","synthetic":false,"types":["quilkin::config::watch::agones::crd::GameServerPort"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/config/watch/agones/crd/struct.GameServerStatus.html\" title=\"struct quilkin::config::watch::agones::crd::GameServerStatus\">GameServerStatus</a>","synthetic":false,"types":["quilkin::config::watch::agones::crd::GameServerStatus"]},{"text":"impl JsonSchema for <a class=\"enum\" href=\"quilkin/config/watch/agones/crd/enum.GameServerState.html\" title=\"enum quilkin::config::watch::agones::crd::GameServerState\">GameServerState</a>","synthetic":false,"types":["quilkin::config::watch::agones::crd::GameServerState"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/config/watch/agones/crd/struct.GameServerStatusPort.html\" title=\"struct quilkin::config::watch::agones::crd::GameServerStatusPort\">GameServerStatusPort</a>","synthetic":false,"types":["quilkin::config::watch::agones::crd::GameServerStatusPort"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/config/watch/agones/crd/struct.SdkServer.html\" title=\"struct quilkin::config::watch::agones::crd::SdkServer\">SdkServer</a>","synthetic":false,"types":["quilkin::config::watch::agones::crd::SdkServer"]},{"text":"impl JsonSchema for <a class=\"enum\" href=\"quilkin/config/watch/agones/crd/enum.SdkServerLogLevel.html\" title=\"enum quilkin::config::watch::agones::crd::SdkServerLogLevel\">SdkServerLogLevel</a>","synthetic":false,"types":["quilkin::config::watch::agones::crd::SdkServerLogLevel"]},{"text":"impl JsonSchema for <a class=\"enum\" href=\"quilkin/config/watch/agones/crd/enum.PortPolicy.html\" title=\"enum quilkin::config::watch::agones::crd::PortPolicy\">PortPolicy</a>","synthetic":false,"types":["quilkin::config::watch::agones::crd::PortPolicy"]},{"text":"impl JsonSchema for <a class=\"enum\" href=\"quilkin/config/watch/agones/crd/enum.SchedulingStrategy.html\" title=\"enum quilkin::config::watch::agones::crd::SchedulingStrategy\">SchedulingStrategy</a>","synthetic":false,"types":["quilkin::config::watch::agones::crd::SchedulingStrategy"]},{"text":"impl JsonSchema for <a class=\"enum\" href=\"quilkin/config/watch/agones/crd/enum.Protocol.html\" title=\"enum quilkin::config::watch::agones::crd::Protocol\">Protocol</a>","synthetic":false,"types":["quilkin::config::watch::agones::crd::Protocol"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/config/watch/agones/crd/struct.Fleet.html\" title=\"struct quilkin::config::watch::agones::crd::Fleet\">Fleet</a>","synthetic":false,"types":["quilkin::config::watch::agones::crd::Fleet"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/config/watch/agones/crd/struct.FleetSpec.html\" title=\"struct quilkin::config::watch::agones::crd::FleetSpec\">FleetSpec</a>","synthetic":false,"types":["quilkin::config::watch::agones::crd::FleetSpec"]},{"text":"impl JsonSchema for <a class=\"enum\" href=\"quilkin/config/watch/agones/crd/enum.FleetScheduling.html\" title=\"enum quilkin::config::watch::agones::crd::FleetScheduling\">FleetScheduling</a>","synthetic":false,"types":["quilkin::config::watch::agones::crd::FleetScheduling"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/config/watch/agones/crd/struct.FleetStrategy.html\" title=\"struct quilkin::config::watch::agones::crd::FleetStrategy\">FleetStrategy</a>","synthetic":false,"types":["quilkin::config::watch::agones::crd::FleetStrategy"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/config/watch/agones/crd/struct.FleetStrategyRollingUpdate.html\" title=\"struct quilkin::config::watch::agones::crd::FleetStrategyRollingUpdate\">FleetStrategyRollingUpdate</a>","synthetic":false,"types":["quilkin::config::watch::agones::crd::FleetStrategyRollingUpdate"]},{"text":"impl JsonSchema for <a class=\"enum\" href=\"quilkin/config/watch/agones/crd/enum.FleetStrategyType.html\" title=\"enum quilkin::config::watch::agones::crd::FleetStrategyType\">FleetStrategyType</a>","synthetic":false,"types":["quilkin::config::watch::agones::crd::FleetStrategyType"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/config/watch/agones/crd/struct.GameServerTemplateSpec.html\" title=\"struct quilkin::config::watch::agones::crd::GameServerTemplateSpec\">GameServerTemplateSpec</a>","synthetic":false,"types":["quilkin::config::watch::agones::crd::GameServerTemplateSpec"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/config/watch/agones/crd/struct.FleetStatus.html\" title=\"struct quilkin::config::watch::agones::crd::FleetStatus\">FleetStatus</a>","synthetic":false,"types":["quilkin::config::watch::agones::crd::FleetStatus"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/struct.Config.html\" title=\"struct quilkin::Config\">Config</a>","synthetic":false,"types":["quilkin::config::Config"]},{"text":"impl JsonSchema for <a class=\"enum\" href=\"quilkin/config/enum.Version.html\" title=\"enum quilkin::config::Version\">Version</a>","synthetic":false,"types":["quilkin::config::Version"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/config/struct.Proxy.html\" title=\"struct quilkin::config::Proxy\">Proxy</a>","synthetic":false,"types":["quilkin::config::Proxy"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/config/struct.Admin.html\" title=\"struct quilkin::config::Admin\">Admin</a>","synthetic":false,"types":["quilkin::config::Admin"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/config/struct.ManagementServer.html\" title=\"struct quilkin::config::ManagementServer\">ManagementServer</a>","synthetic":false,"types":["quilkin::config::ManagementServer"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/config/struct.Filter.html\" title=\"struct quilkin::config::Filter\">Filter</a>","synthetic":false,"types":["quilkin::config::Filter"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/endpoint/struct.Locality.html\" title=\"struct quilkin::endpoint::Locality\">Locality</a>","synthetic":false,"types":["quilkin::endpoint::locality::Locality"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/endpoint/struct.LocalityEndpoints.html\" title=\"struct quilkin::endpoint::LocalityEndpoints\">LocalityEndpoints</a>","synthetic":false,"types":["quilkin::endpoint::locality::LocalityEndpoints"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/endpoint/struct.Endpoint.html\" title=\"struct quilkin::endpoint::Endpoint\">Endpoint</a>","synthetic":false,"types":["quilkin::endpoint::Endpoint"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/endpoint/struct.Metadata.html\" title=\"struct quilkin::endpoint::Metadata\">Metadata</a>","synthetic":false,"types":["quilkin::endpoint::Metadata"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/filters/capture/struct.Prefix.html\" title=\"struct quilkin::filters::capture::Prefix\">Prefix</a>","synthetic":false,"types":["quilkin::filters::capture::affix::Prefix"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/filters/capture/struct.Suffix.html\" title=\"struct quilkin::filters::capture::Suffix\">Suffix</a>","synthetic":false,"types":["quilkin::filters::capture::affix::Suffix"]},{"text":"impl JsonSchema for <a class=\"enum\" href=\"quilkin/filters/capture/enum.Strategy.html\" title=\"enum quilkin::filters::capture::Strategy\">Strategy</a>","synthetic":false,"types":["quilkin::filters::capture::config::Strategy"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/filters/capture/struct.Config.html\" title=\"struct quilkin::filters::capture::Config\">Config</a>","synthetic":false,"types":["quilkin::filters::capture::config::Config"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/filters/capture/struct.Regex.html\" title=\"struct quilkin::filters::capture::Regex\">Regex</a>","synthetic":false,"types":["quilkin::filters::capture::regex::Regex"]},{"text":"impl JsonSchema for <a class=\"enum\" href=\"quilkin/filters/compress/enum.Mode.html\" title=\"enum quilkin::filters::compress::Mode\">Mode</a>","synthetic":false,"types":["quilkin::filters::compress::config::Mode"]},{"text":"impl JsonSchema for <a class=\"enum\" href=\"quilkin/filters/compress/enum.Action.html\" title=\"enum quilkin::filters::compress::Action\">Action</a>","synthetic":false,"types":["quilkin::filters::compress::config::Action"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/filters/compress/struct.Config.html\" title=\"struct quilkin::filters::compress::Config\">Config</a>","synthetic":false,"types":["quilkin::filters::compress::config::Config"]},{"text":"impl JsonSchema for <a class=\"enum\" href=\"quilkin/filters/concatenate_bytes/enum.Strategy.html\" title=\"enum quilkin::filters::concatenate_bytes::Strategy\">Strategy</a>","synthetic":false,"types":["quilkin::filters::concatenate_bytes::config::Strategy"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/filters/concatenate_bytes/struct.Config.html\" title=\"struct quilkin::filters::concatenate_bytes::Config\">Config</a>","synthetic":false,"types":["quilkin::filters::concatenate_bytes::config::Config"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/filters/debug/struct.Config.html\" title=\"struct quilkin::filters::debug::Config\">Config</a>","synthetic":false,"types":["quilkin::filters::debug::Config"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/filters/drop/struct.Config.html\" title=\"struct quilkin::filters::drop::Config\">Config</a>","synthetic":false,"types":["quilkin::filters::drop::Config"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/filters/firewall/struct.Config.html\" title=\"struct quilkin::filters::firewall::Config\">Config</a>","synthetic":false,"types":["quilkin::filters::firewall::config::Config"]},{"text":"impl JsonSchema for <a class=\"enum\" href=\"quilkin/filters/firewall/enum.Action.html\" title=\"enum quilkin::filters::firewall::Action\">Action</a>","synthetic":false,"types":["quilkin::filters::firewall::config::Action"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/filters/firewall/struct.Rule.html\" title=\"struct quilkin::filters::firewall::Rule\">Rule</a>","synthetic":false,"types":["quilkin::filters::firewall::config::Rule"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/filters/firewall/struct.PortRange.html\" title=\"struct quilkin::filters::firewall::PortRange\">PortRange</a>","synthetic":false,"types":["quilkin::filters::firewall::config::PortRange"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/filters/load_balancer/struct.Config.html\" title=\"struct quilkin::filters::load_balancer::Config\">Config</a>","synthetic":false,"types":["quilkin::filters::load_balancer::config::Config"]},{"text":"impl JsonSchema for <a class=\"enum\" href=\"quilkin/filters/load_balancer/enum.Policy.html\" title=\"enum quilkin::filters::load_balancer::Policy\">Policy</a>","synthetic":false,"types":["quilkin::filters::load_balancer::config::Policy"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/filters/local_rate_limit/struct.Config.html\" title=\"struct quilkin::filters::local_rate_limit::Config\">Config</a>","synthetic":false,"types":["quilkin::filters::local_rate_limit::Config"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/filters/match/struct.Config.html\" title=\"struct quilkin::filters::match::Config\">Config</a>","synthetic":false,"types":["quilkin::filters::match::config::Config"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/filters/match/struct.DirectionalConfig.html\" title=\"struct quilkin::filters::match::DirectionalConfig\">DirectionalConfig</a>","synthetic":false,"types":["quilkin::filters::match::config::DirectionalConfig"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/filters/match/struct.Branch.html\" title=\"struct quilkin::filters::match::Branch\">Branch</a>","synthetic":false,"types":["quilkin::filters::match::config::Branch"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/filters/match/struct.Fallthrough.html\" title=\"struct quilkin::filters::match::Fallthrough\">Fallthrough</a>","synthetic":false,"types":["quilkin::filters::match::config::Fallthrough"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/filters/pass/struct.Config.html\" title=\"struct quilkin::filters::pass::Config\">Config</a>","synthetic":false,"types":["quilkin::filters::pass::Config"]},{"text":"impl JsonSchema for <a class=\"struct\" href=\"quilkin/filters/token_router/struct.Config.html\" title=\"struct quilkin::filters::token_router::Config\">Config</a>","synthetic":false,"types":["quilkin::filters::token_router::Config"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()