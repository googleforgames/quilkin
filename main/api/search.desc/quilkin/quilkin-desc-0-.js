searchState.loadedDescShard("quilkin", 0, "Quilkin: a non-transparent UDP proxy specifically designed …\nConfiguration for a component\nContains the error value\nContains the success value\nRun Quilkin as a UDP reverse proxy.\nMacro that can get the function name of the function the …\nImplementations and utility methods for various codecs …\nCollection types designed for use with Quilkin.\nQuilkin configuration.\nThe path to the configuration file for the Quilkin …\nFilters for processing packets.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nThe interval in seconds at which the relay will send a …\nIncludes generated Protobuf definitions from <code>tonic</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nOne or more <code>quilkin manage</code> endpoints to listen to for …\nThe remote URL or local file path to retrieve the Maxmind …\nThe port to listen on.\nThe port to listen on.\nWhether Quilkin will report any results to stdout/stderr.\nCreates a temporary file with the specified prefix in a …\nOne or more socket addresses to forward packets to.\nAssigns dynamic tokens to each address in the <code>--to</code> argument\nNumber of worker threads used to process packets.\nQuilkin: a non-transparent UDP proxy specifically designed …\nThe various Quilkin commands.\nThe various log format options\nThe address to bind for the admin server.\nSets the xDS service port.\nThe path to the configuration file for the Quilkin …\nDrives the main quilkin application lifecycle using the …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nEnables the mDS service.\nSets the mDS service port.\nEnables the Phoenix service.\nSets the Phoenix service port.\nEnables the QCMP service.\nSets the UDP service port.\nWhether Quilkin will report any results to stdout/stderr.\nThe <code>region</code> to set in the cluster map for any provider …\nThe main entrypoint for listening network servers. When …\nLaunches the user space implementation of the packet …\nThe <code>sub_zone</code> in the <code>zone</code> in the <code>region</code> to set in the …\nEnables the UDP service.\nSets the UDP service port.\nAmount of UDP workers to run.\nEnables the xDS service.\nSets the xDS service port.\nThe <code>zone</code> in the <code>region</code> to set in the cluster map for any …\nRuns Quilkin as a relay service that runs a Manager …\nIf specified, filters the available gameserver addresses …\nReturns the argument unchanged.\nThe ICAO code for the agent.\nCalls <code>U::from(self)</code>.\nIf specified, additionally filters the gameserver address …\nThe configuration source for a management server.\nPort for QCMP service.\nOne or more <code>quilkin relay</code> endpoints to push configuration …\nGenerates JSON schema files for known filters.\nA list of one or more filter IDs to generate or ‘all’ …\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nThe directory to write configuration files.\nRuns Quilkin as a xDS management server, using <code>provider</code> as …\nIf specified, filters the available gameserver addresses …\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nIf specified, additionally filters the gameserver address …\nThe TCP port to listen to, to serve discovery responses.\nThe configuration source for a management server.\nOne or more <code>quilkin relay</code> endpoints to push configuration …\nRun Quilkin as a UDP reverse proxy.\nXDP (eXpress Data Path) options\nForces the use of TX checksum offload\nForces the use of XDP.\nForces the use of <code>XDP_ZEROCOPY</code>\nReturns the argument unchanged.\nThe interval in seconds at which the relay will send a …\nCalls <code>U::from(self)</code>.\nOne or more <code>quilkin manage</code> endpoints to listen to for …\nThe maximum amount of memory mapped for packet buffers, in …\nThe remote URL or local file path to retrieve the Maxmind …\nThe name of the network interface to bind the XDP …\nThe port to listen on.\nThe port to listen on.\nStart and run a proxy.\nOne or more socket addresses to forward packets to.\nAssigns dynamic tokens to each address in the <code>--to</code> argument\nNumber of worker threads used to process packets.\nPings a endpoint for a <code>amount</code> of attempts, printing the …\nThe number of pings to send to the endpoint (default: 5).\nThe quilkin endpoint to ping\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nRuns Quilkin as a relay service that runs a Manager …\nReturns the argument unchanged.\nThe interval in seconds at which the relay will send a …\nCalls <code>U::from(self)</code>.\nPort for mDS service.\nPort for xDS management_server service\nExtensions to <code>prost</code> and related crates.\nLogic for parsing and generating Quilkin Control Message …\nThe maximum length of a QCMP packet, including 2 …\nThe minimum length of a QCMP packet\nThe initation of a ping command to send to a Quilkin proxy …\nThe reply from a Quilkin proxy from a <code>Self::Ping</code> command. …\nThe set of possible QCMP commands.\nA measurement implementation using QCMP pings for …\nIf the command is <code>Protocol::PingReply</code>, with …\nEncodes the protocol command into a buffer of bytes for …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns the packet’s nonce.\nParses the provided input, and attempts to parse it as a …\nCreates a <code>Self::Ping</code> with a random nonce, should be sent …\nCreates a <code>Self::PingReply</code> from the client and server start …\nCreates a <code>Self::Ping</code> with a user-specified nonce, should …\nIf the command is <code>Protocol::PingReply</code>, with …\nThe timestamp from when the client sent the packet.\nThe timestamp from when the client sent the ping packet.\nThe client’s nonce.\nThe client’s nonce.\nThe timestamp from when the server received the ping …\nThe timestamp from when the server sent the reply.\nCreates a buffer filled with the specified data, only used …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nSplits a prefix of the specified length from the buffer …\nSplits a suffix of the specified length from the buffer …\nThe shard wasn’t locked, and the value wasn’t present …\nA view into an entry in the map. It may either be …\nThe shard was locked.\nA view into an occupied entry in the map.\nThe value was present in the map, and the lock for the …\nRepresents the result of a non-blocking read from a DashMap…\nTtlMap is a key value hash map where entries are …\nA view into a vacant entry in the map.\nA wrapper around the value of an entry in the map. It …\nRemoves all entries from the map\nReturns true if the map contains a value for the specified …\nReturns an entry for in-place updates of the specified …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns a reference to value corresponding to key.\nReturns a reference to the entry’s value. The value will …\nReturns a mutable reference to value corresponding to key. …\nReturns a mutable reference to the entry’s value. The …\nInserts a key-value pair into the map. The value will be …\nReplace the entry’s value with a new value, returning …\nSet an entry’s value. The value will be set to expire at …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns <code>true</code> if the shard wasn’t locked, and the value …\nReturns whether the map currently contains no entries.\nReturns <code>true</code> if the shard was locked.\nReturns whether the map currently contains any entries.\nReturns <code>true</code> if the value was present in the map, and the …\nReturns the number of entries currently in the map.\nRemoves a key-value pair from the map.\nReturns a reference to value corresponding to key.\nIf <code>self</code> is Present, returns the reference to the value in …\nIf <code>self</code> is Present, returns the reference to the value in …\nArgs common across all components\nConfig\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nThe ready check and idle duration\nChannel used to indicate graceful shutdown requests\nThe runtime mode of Quilkin, which contains various …\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nThe location of an <code>Endpoint</code>.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nIf true, only care about the provider being healthy, not …\nThe location of an <code>Endpoint</code>.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nA data structure that is responsible for holding sessions, …\nThe number of tokens to assign to each <code>to</code> address\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nThe size of each token\nConstructs a new session pool, it’s created with an <code>Arc</code> …\nSends packet data to the appropiate session based on its …\nReturns a map of active sessions.\nRepresents the required arguments to run a worker task that\nRepresentation of an immutable set of bytes pulled from …\nRepresentation of an mutable set of bytes pulled from the …\nReturns the underlying slice of bytes representing the …\nReturns an immutable version of the packet, this allows …\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nReturns whether the given packet is empty.\nReturns the size of the packet.\nSpawns a background task that sits in a loop, receiving …\nID of the worker.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nConfiguration for a component\nThe configuration of a <code>Filter</code> from either a static or …\nDynamic configuration from Protobuf.\nFilter is the configuration for a single filter\nA mutable memory location with atomic storage rules.\nStatic configuration from YAML.\nValidation failure for a Config\nGets the datacenters, panicking if this is an agent config\nGiven a list of subscriptions and the current state of the …\nDeserializes takes two type arguments <code>Static</code> and <code>Dynamic</code> …\nCreates a new empty slot.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nAttempts to deserialize <code>input</code> as a YAML object …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns whether any data is present in the slot.\nProvides a reference to the underlying data.\nProvides a view into a mutable reference of the current …\nCreates a new slot for <code>value</code>.\nRemoves any data from the slot.\nReplaces the data in the slot with <code>value</code>.\nReplaces the data if the slot is empty.\nReplaces the current data in the slot with <code>value</code>’s data, …\nAdds a watcher to to the slot. The watcher will fire …\nCreates a new slot containing the default instance of <code>T</code>.\nWatches Agones’ game server CRDs for <code>Allocated</code> game …\nWatches for changes to the file located at <code>path</code>.\nThe available xDS source providers.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nThe namespace under which the configmap is stored.\nThe namespace under which the game servers run.\nThe path to the source config.\nThe GameServer has been allocated to a session\nThe Pod for the GameServer is being created.\nOutput all messages including debug messages.\nprioritise allocating GameServers on Nodes with the least …\nThe system will choose an open port for the <code>GameServer</code> in …\nSomething has gone wrong with the Gameserver and it cannot …\nOnly output error messages.\nFleetSpec is the spec for a Fleet. More info: …\nFleetSpec is the spec for a Fleet. More info: …\nFleetStatus is the status of a Fleet. More info: …\nAuto-generated derived type for GameServerSpec via …\nDefines a set of Ports that are to be exposed via the …\nThe status for a <code>GameServer</code> resource.\nThe port that was allocated to a GameServer.\nGameServer is the data structure for a GameServer resource.\nOutput all messages except for debug messages.\nPrioritise allocating GameServers on Nodes with the most …\nDynamically sets the container port to the same value as …\nA dynamically allocating GameServer is being created, an …\nThe GameServer is ready to take connections from game …\nThe GameServer has declared that it is ready\nThe GameServer is reserved and therefore can be allocated …\nWe have determined that the Pod has been scheduled in the …\nthe strategy that a Fleet &amp; GameServers will use when …\nParameters for the Agones SDK Server sidecar container\nThe GameServer has shutdown and everything needs to be …\nThe Pods for the GameServer are being created but are not …\nThe user defines the host port to be used in the …\nThe GameServer has failed its health checks\nContainer specifies which Pod container is the game …\nThe name of the container on which to open the port. …\nThe port that is being opened on the specified container’…\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGRPCPort is the port on which the SDK Server binds the …\nConfigures health checking\nThe port exposed on the host for clients to connect to\nHTTPPort is the port on which the SDK Server binds the …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nLogLevel for SDK server (sidecar) logs. Defaults to “Info…\nName is the descriptive name of the port\nSpec based constructor for derived custom resource\nPortPolicy defines the policy for how the HostPort is …\nPorts are the array of ports that can be exposed via the …\nProtocol is the network protocol being used. Defaults to …\nScheduling strategy. Defaults to “Packed”\nSpecifies parameters for the Agones SDK Server sidecar …\nGameServerSpec is the spec for a GameServer resource. More …\nThe current state of a <code>GameServer</code>.\nDescribes the Pod that will be created for the <code>GameServer</code>.\nGameServer is the data structure for a GameServer resource.\nThe available xDS source provider.\nIf specified, filters the available gameserver addresses …\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nIf specified, additionally filters the gameserver address …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nThe binary configuration of the filter. <strong>Must</strong> be <code>prost</code> …\nFilter for compressing and decompressing packet data\nThe <code>Concatenate</code> filter’s job is to add a byte packet to …\nThe human-readable configuration of the filter. <strong>Must</strong> be …\nAn error representing failure to convert a filter’s …\nArguments needed to create a new filter.\nAn error that occurred when attempting to create a <code>Filter</code> …\nDebug logs all incoming and outgoing packets\nAlways drops a packet, mostly useful in combination with …\nAn owned pointer to a dynamic <code>FilterFactory</code> instance.\nTrait for routing and manipulating packets.\nA chain of <code>Filter</code>s to be executed in order.\nAll possible errors that can be returned from <code>Filter</code> …\nProvides the name and creation function for a given …\nThe value returned by <code>FilterFactory::create_filter</code>.\nA map of <code>FilterFactory::name</code>s to <code>DynFilterFactory</code> values.\nRegistry of all <code>Filter</code>s that can be applied in the system.\nA set of filters to be registered with a <code>FilterRegistry</code>.\nFilter for allowing/blocking traffic by IP and port.\nBalances packets over the upstream endpoints.\nA filter that implements rate limiting on packets based on …\nThe globally unique name of the filter.\nAllows a packet to pass through, mostly useful in …\nThe input arguments to <code>Filter::read</code>.\nStatically safe version of <code>Filter</code>, if you’re writing a …\nA filter that reads a metadata value as a timestamp to be …\nFilter that only allows packets to be passed to Endpoints …\nThe input arguments to <code>Filter::write</code>.\nConfiguration for the filter.\nReturns the schema for the configuration of the …\nContents of the received packet.\nContents of the received packet.\nReturns a filter based on the provided arguments.\nReturns a <code>FilterSet</code> with the filters provided through …\nThe destination of the received packet.\nThe upstream endpoints that the packet will be forwarded …\nCreates a new instance of <code>CreateFilterArgs</code> using a dynamic …\nConverts YAML configuration into its Protobuf equivalvent.\nConverts YAML configuration into its Protobuf equivalvent.\nThe upstream endpoints that the packet will be forwarded …\nConvenience method for providing a consistent error …\nCreates a new dynamic <code>FilterFactory</code> virtual table.\nCreates a new instance of <code>CreateFilterArgs</code> using a fixed …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nInstantiates a new <code>StaticFilter</code> from the given …\nCreates and returns a new dynamic instance of <code>Filter</code> for a …\nReturns a <code>DynFilterFactory</code> if one matches <code>id</code>, otherwise …\nReturns a <code>DynFilterFactory</code> for a given <code>key</code>. Returning <code>None</code> …\nInserts factory for the specified <code>FilterFactory</code>, returning …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns a by reference iterator over the set of filters.\nArbitrary values that can be passed from one filter to …\nArbitrary values that can be passed from one filter to …\nname returns the configuration name for the Filter The …\nCreate a new instance of <code>CreateFilterArgs</code>.\nCreates a new <code>ReadContext</code>.\nCreates a new <code>WriteContext</code>\nConstructs a <code>FilterInstance</code>.\nPrelude containing all types and traits required to …\n<code>Filter::read</code> is invoked when the proxy receives data from a\n<code>Filter::read</code> is invoked when the proxy receives data from a\nLoads the provided <code>FilterSet</code> into the registry of …\nReturns the <code>ConfigType</code> from the provided Option, otherwise …\nReturns the <code>ConfigType</code> from the provided Option, otherwise …\nThe source of the received packet.\nThe source of the received packet.\nValidates the filter configurations in the provided config …\nValidates the filter configurations in the provided config …\nInstantiates a new <code>StaticFilter</code> from the given …\nCreates a new <code>FilterSet</code> with the set of <code>filter_factories</code> …\n<code>Filter::write</code> is invoked when the proxy is about to send …\n<code>Filter::write</code> is invoked when the proxy is about to send …\nThe default key under which the <code>Capture</code> filter puts the …\nTrait to implement different strategies for capturing …\nCapture from the start of the packet.\nLooks for the set of bytes at the beginning of the packet\nCapture from the start of the packet.\nLook for the set of bytes at the end of the packet\nStrategy to apply for acquiring a set of bytes in the UDP …\nCapture from the end of the packet.\nLook for the set of bytes at the end of the packet\nCapture packet data from the contents, and optionally …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nThe key to use when storing the captured value in the …\nThe regular expression to use for capture.\nWhether captured bytes are removed from the original …\nThe number of bytes to capture.\nThe number of bytes to capture.\nWhether captured bytes are removed from the original …\nThe capture strategy.\nWhether to do nothing, compress or decompress the packet.\nFilter for compressing and decompressing packet data\nA trait that provides a compression and decompression …\nThe library to use when compressing.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nThe <code>Concatenate</code> filter’s job is to add a byte packet to …\nConfig represents a <code>Concatenate</code> filter configuration.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nWhether or not to <code>append</code> or <code>prepend</code> or <code>do nothing</code> on …\nWhether or not to <code>append</code> or <code>prepend</code> or <code>do nothing</code> on …\nA Debug filter’s configuration.\nDebug logs all incoming and outgoing packets\nReturns the argument unchanged.\nIdentifier that will be optionally included with each log …\nCalls <code>U::from(self)</code>.\n<code>pass</code> filter’s configuration.\nAlways drops a packet, mostly useful in combination with …\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nWhether or not a matching Rule should Allow or Deny access\nMatching rules will allow packets through.\nRepresents how a Firewall filter is configured for read …\nMatching rules will block packets.\nFilter for allowing/blocking traffic by IP and port.\nRange of matching ports that are configured against a Rule.\nInvalid min and max values for a PortRange.\nCombination of CIDR range, port range and action to take.\nReturns <code>true</code> if any <code>address</code> matches the provided CIDR …\nReturns true if the range contain the given <code>port</code>.\nPort ranges can be specified in yaml as either “10” as …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCreates a new PortRange, where min is inclusive, max is …\nSerialise the PortRange into a single digit if min and max …\nipv4 or ipv6 CIDR address.\nThe configuration for <code>load_balancer</code>.\nSend packets to endpoints based on hash of source IP and …\nBalances packets over the upstream endpoints.\nPolicy represents how a <code>load_balancer</code> distributes packets …\nSend packets to endpoints chosen at random.\nSend packets to endpoints in turns.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nConfig represents a self’s configuration.\nA filter that implements rate limiting on packets based on …\nSESSION_TIMEOUT_SECONDS is the default session timeout.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nThe maximum number of packets allowed to be forwarded by …\nThe duration in seconds during which max_packets applies. …\nA specific match branch. The filter is run when <code>value</code> …\nConfiguration for <code>Match</code>.\nConfiguration for a specific direction.\nThe behaviour when the none of branches match. Defaults to …\nList of filters to compare and potentially run if any …\nThe behaviour for when none of the <code>branches</code> match.\nThe filter to run on successful matches.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nThe key for the metadata to compare against.\nConfiguration for <code>Filter::read</code>.\nConfiguration for <code>Filter::write</code>.\nThe value to compare against the dynamic metadata.\n<code>pass</code> filter’s configuration.\nAllows a packet to pass through, mostly useful in …\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nConfig represents a self’s configuration.\nA filter that reads a metadata value as a timestamp to be …\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nThe metadata key to read the UTC UNIX Timestamp from.\nObserves the duration since a timestamp stored in <code>metadata</code> …\nFilter that only allows packets to be passed to Endpoints …\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nthe key to use when retrieving the token from the Filter’…\nThe same as DualStackSocket but uses epoll instead of …\nAn ipv6 socket that can accept and send data from either a …\nTCP listener for a GRPC service, always binds to the local …\nBinds a TCP listener, if <code>None</code> is passed, binds to an …\nTypes representing where the data is the sent.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nRetrieves the local address the listener is bound to\nPhoenix Network Coordinate System\nRetrieves the port the listener is bound to\nRepresents a full snapshot of all clusters.\nCreates a map of tokens -&gt; address for the current set\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCreates a new endpoint set, calculating a unique version …\nBumps the version, calculating a hash for the entire …\nUnique version for this endpoint set\nCreates a new endpoint set with the provided version hash, …\nReturns the value of <code>config</code>, or the default value if <code>config</code>…\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nNested message and enum types in <code>Host</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns the value of <code>label</code>, or the default value if <code>label</code> …\nEncodes the message to a buffer.\nReturns the encoded length of the message without a length …\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nDecodes an instance of the message from a buffer, and …\nThe kind of address, such as Domain Name or IP address. …\nA destination endpoint with any associated metadata.\nA valid socket address. This differs from …\nThe location of an <code>Endpoint</code>.\nMetadata specific to endpoints.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nA valid name or IP address that resolves to a address.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nKnown Quilkin metadata.\nCreates a new <code>Endpoint</code> with no metadata.\nReturns the port for the endpoint address, or <code>0</code> if no port …\nThe port of the socket address, if present.\nReturns the socket address for the endpoint, resolving any …\nUser created metadata.\nCreates a new <code>Endpoint</code> with the specified <code>metadata</code>.\nShared state between <code>Filter</code>s during processing for a …\nA key in the metadata table.\nRepresents a view into the metadata object attached to …\nReference to a metadata value.\nA literal value or a reference to a value in a metadata …\nReturns the inner <code>String</code> value of <code>self</code> if it matches …\nReturns the inner <code>String</code> value of <code>self</code> if it matches …\nReturns the inner <code>String</code> value of <code>self</code> if it matches …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nKnown Quilkin metadata.\nResolves a symbol into a <code>Value</code>, using <code>ctx</code> for any …\nTries to <code>Self::resolve</code> the symbol to a <code>bytes::Bytes</code>, …\nUser created metadata.\nA simple packet queue that signals when a packet is pushed\nThe asn info for the sender, used for metrics\nThe packet data being sent\nThe destination address of the packet\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nPushes a packet onto the queue to be sent, signalling a …\nThe network coordinates of a node in the phoenix system.\nAn implementation of measuring the network difference …\nA <code>Phoenix</code> instance maintains a virtual coordinate space …\nThe amount of time the check will change by depending on …\nStarts the background update task to continously sample …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nThe range at which continually update the nodes …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nGets the difference between this node and <code>address</code>, …\nConstructs a new <code>Phoenix</code> builder.\nThe threshold at which the path to a node is consider …\nSets the percentage of nodes to regularly measure at …\nThe NIC will be determined from the set of available NICs, …\nSpecifies a NIC by index, setup will fail if the index isn…\nSpecifies a NIC by name, setup will fail if a NIC with …\nUser supplied configuration\nThe external port that downstream clients use to …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nThe maximum amount of memory, in bytes, that the memory …\nThe NIC to attach to\nThe port QCMP packets can be sent to\nRequires that the chosen NIC supports …\nRequires that the chosen NIC supports <code>XDP_ZEROCOPY</code>\nAttempts to setup XDP by querying NIC support and …\nDetaches the eBPF program from the attacked NIC and …\nThe entrypoint into the XDP I/O loop.\nThe external port is how we determine if packets come from …\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nIn a benching environment, some or all shutdown behavior …\nNormal shutdown kind, the receiver should perform proper …\nReceiver for a shutdown event.\nIn a testing environment, some or all shutdown behavior …\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCreates a new handler for shutdown signal (e.g. SIGTERM, …\nA UTC timestamp\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nGets the current Unix timestamp\nGets the current Unix timestamp in nanoseconds.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.")