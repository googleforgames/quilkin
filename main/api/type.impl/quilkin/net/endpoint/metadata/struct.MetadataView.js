(function() {var type_impls = {
"quilkin":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-MetadataView%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/quilkin/net/endpoint/metadata.rs.html#225-242\">source</a><a href=\"#impl-MetadataView%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>&gt; <a class=\"struct\" href=\"quilkin/net/endpoint/metadata/struct.MetadataView.html\" title=\"struct quilkin::net::endpoint::metadata::MetadataView\">MetadataView</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><section id=\"method.new\" class=\"method\"><a class=\"src rightside\" href=\"src/quilkin/net/endpoint/metadata.rs.html#226-231\">source</a><h4 class=\"code-header\">pub fn <a href=\"quilkin/net/endpoint/metadata/struct.MetadataView.html#tymethod.new\" class=\"fn\">new</a>(known: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;T&gt;) -&gt; Self</h4></section><section id=\"method.with_unknown\" class=\"method\"><a class=\"src rightside\" href=\"src/quilkin/net/endpoint/metadata.rs.html#233-241\">source</a><h4 class=\"code-header\">pub fn <a href=\"quilkin/net/endpoint/metadata/struct.MetadataView.html#tymethod.with_unknown\" class=\"fn\">with_unknown</a>(known: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;T&gt;, unknown: <a class=\"struct\" href=\"https://docs.rs/serde_json/1.0.116/serde_json/map/struct.Map.html\" title=\"struct serde_json::map::Map\">Map</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/1.77.0/alloc/string/struct.String.html\" title=\"struct alloc::string::String\">String</a>, <a class=\"enum\" href=\"https://docs.rs/serde_json/1.0.116/serde_json/value/enum.Value.html\" title=\"enum serde_json::value::Value\">Value</a>&gt;) -&gt; Self</h4></section></div></details>",0,"quilkin::net::endpoint::EndpointMetadata"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-MetadataView%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/quilkin/net/endpoint/metadata.rs.html#213\">source</a><a href=\"#impl-Clone-for-MetadataView%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"quilkin/net/endpoint/metadata/struct.MetadataView.html\" title=\"struct quilkin::net::endpoint::metadata::MetadataView\">MetadataView</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/quilkin/net/endpoint/metadata.rs.html#213\">source</a><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.77.0/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; <a class=\"struct\" href=\"quilkin/net/endpoint/metadata/struct.MetadataView.html\" title=\"struct quilkin::net::endpoint::metadata::MetadataView\">MetadataView</a>&lt;T&gt;</h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/1.77.0/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.77.0/src/core/clone.rs.html#169\">source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.77.0/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.0/std/primitive.reference.html\">&amp;Self</a>)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/1.77.0/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","quilkin::net::endpoint::EndpointMetadata"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-From%3CMetadata%3E-for-MetadataView%3CMetadata%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/quilkin/net/endpoint.rs.html#156-163\">source</a><a href=\"#impl-From%3CMetadata%3E-for-MetadataView%3CMetadata%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"quilkin/net/endpoint/struct.Metadata.html\" title=\"struct quilkin::net::endpoint::Metadata\">Metadata</a>&gt; for <a class=\"struct\" href=\"quilkin/net/endpoint/metadata/struct.MetadataView.html\" title=\"struct quilkin::net::endpoint::metadata::MetadataView\">MetadataView</a>&lt;<a class=\"struct\" href=\"quilkin/net/endpoint/struct.Metadata.html\" title=\"struct quilkin::net::endpoint::Metadata\">Metadata</a>&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.from\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/quilkin/net/endpoint.rs.html#157-162\">source</a><a href=\"#method.from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.77.0/core/convert/trait.From.html#tymethod.from\" class=\"fn\">from</a>(metadata: <a class=\"struct\" href=\"quilkin/net/endpoint/struct.Metadata.html\" title=\"struct quilkin::net::endpoint::Metadata\">Metadata</a>) -&gt; Self</h4></section></summary><div class='docblock'>Converts to this type from the input type.</div></details></div></details>","From<Metadata>","quilkin::net::endpoint::EndpointMetadata"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-MetadataView%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/quilkin/net/endpoint/metadata.rs.html#213\">source</a><a href=\"#impl-Debug-for-MetadataView%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for <a class=\"struct\" href=\"quilkin/net/endpoint/metadata/struct.MetadataView.html\" title=\"struct quilkin::net::endpoint::metadata::MetadataView\">MetadataView</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/quilkin/net/endpoint/metadata.rs.html#213\">source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.77.0/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/1.77.0/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"type\" href=\"https://doc.rust-lang.org/1.77.0/core/fmt/type.Result.html\" title=\"type core::fmt::Result\">Result</a></h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/1.77.0/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","quilkin::net::endpoint::EndpointMetadata"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Deserialize%3C'de%3E-for-MetadataView%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/quilkin/net/endpoint/metadata.rs.html#213\">source</a><a href=\"#impl-Deserialize%3C'de%3E-for-MetadataView%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;'de, T&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.198/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"quilkin/net/endpoint/metadata/struct.MetadataView.html\" title=\"struct quilkin::net::endpoint::metadata::MetadataView\">MetadataView</a>&lt;T&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.198/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.deserialize\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/quilkin/net/endpoint/metadata.rs.html#213\">source</a><a href=\"#method.deserialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/serde/1.0.198/serde/de/trait.Deserialize.html#tymethod.deserialize\" class=\"fn\">deserialize</a>&lt;__D&gt;(__deserializer: __D) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.77.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self, __D::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.198/serde/de/trait.Deserializer.html#associatedtype.Error\" title=\"type serde::de::Deserializer::Error\">Error</a>&gt;<div class=\"where\">where\n    __D: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.198/serde/de/trait.Deserializer.html\" title=\"trait serde::de::Deserializer\">Deserializer</a>&lt;'de&gt;,</div></h4></section></summary><div class='docblock'>Deserialize this value from the given Serde deserializer. <a href=\"https://docs.rs/serde/1.0.198/serde/de/trait.Deserialize.html#tymethod.deserialize\">Read more</a></div></details></div></details>","Deserialize<'de>","quilkin::net::endpoint::EndpointMetadata"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Serialize-for-MetadataView%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/quilkin/net/endpoint/metadata.rs.html#213\">source</a><a href=\"#impl-Serialize-for-MetadataView%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.198/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"quilkin/net/endpoint/metadata/struct.MetadataView.html\" title=\"struct quilkin::net::endpoint::metadata::MetadataView\">MetadataView</a>&lt;T&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.198/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.serialize\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/quilkin/net/endpoint/metadata.rs.html#213\">source</a><a href=\"#method.serialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/serde/1.0.198/serde/ser/trait.Serialize.html#tymethod.serialize\" class=\"fn\">serialize</a>&lt;__S&gt;(&amp;self, __serializer: __S) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.77.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;__S::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.198/serde/ser/trait.Serializer.html#associatedtype.Ok\" title=\"type serde::ser::Serializer::Ok\">Ok</a>, __S::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.198/serde/ser/trait.Serializer.html#associatedtype.Error\" title=\"type serde::ser::Serializer::Error\">Error</a>&gt;<div class=\"where\">where\n    __S: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.198/serde/ser/trait.Serializer.html\" title=\"trait serde::ser::Serializer\">Serializer</a>,</div></h4></section></summary><div class='docblock'>Serialize this value into the given Serde serializer. <a href=\"https://docs.rs/serde/1.0.198/serde/ser/trait.Serialize.html#tymethod.serialize\">Read more</a></div></details></div></details>","Serialize","quilkin::net::endpoint::EndpointMetadata"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-JsonSchema-for-MetadataView%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/quilkin/net/endpoint/metadata.rs.html#213\">source</a><a href=\"#impl-JsonSchema-for-MetadataView%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> + JsonSchema&gt; JsonSchema for <a class=\"struct\" href=\"quilkin/net/endpoint/metadata/struct.MetadataView.html\" title=\"struct quilkin::net::endpoint::metadata::MetadataView\">MetadataView</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.schema_name\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/quilkin/net/endpoint/metadata.rs.html#213\">source</a><a href=\"#method.schema_name\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">schema_name</a>() -&gt; <a class=\"struct\" href=\"https://doc.rust-lang.org/1.77.0/alloc/string/struct.String.html\" title=\"struct alloc::string::String\">String</a></h4></section></summary><div class='docblock'>The name of the generated JSON Schema. <a>Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.schema_id\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/quilkin/net/endpoint/metadata.rs.html#213\">source</a><a href=\"#method.schema_id\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">schema_id</a>() -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.77.0/alloc/borrow/enum.Cow.html\" title=\"enum alloc::borrow::Cow\">Cow</a>&lt;'static, <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.0/std/primitive.str.html\">str</a>&gt;</h4></section></summary><div class='docblock'>Returns a string that uniquely identifies the schema produced by this type. <a>Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.json_schema\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/quilkin/net/endpoint/metadata.rs.html#213\">source</a><a href=\"#method.json_schema\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">json_schema</a>(gen: &amp;mut SchemaGenerator) -&gt; Schema</h4></section></summary><div class='docblock'>Generates a JSON Schema for this type. <a>Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.is_referenceable\" class=\"method trait-impl\"><a href=\"#method.is_referenceable\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">is_referenceable</a>() -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.0/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>Whether JSON Schemas generated for this type should be re-used where possible using the <code>$ref</code> keyword. <a>Read more</a></div></details></div></details>","JsonSchema","quilkin::net::endpoint::EndpointMetadata"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-TryFrom%3CStruct%3E-for-MetadataView%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/quilkin/net/endpoint/metadata.rs.html#284-311\">source</a><a href=\"#impl-TryFrom%3CStruct%3E-for-MetadataView%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T, E&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"struct\" href=\"https://docs.rs/prost-types/0.12.2/prost_types/protobuf/struct.Struct.html\" title=\"struct prost_types::protobuf::Struct\">Struct</a>&gt; for <a class=\"struct\" href=\"quilkin/net/endpoint/metadata/struct.MetadataView.html\" title=\"struct quilkin::net::endpoint::metadata::MetadataView\">MetadataView</a>&lt;T&gt;<div class=\"where\">where\n    E: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/error/trait.Error.html\" title=\"trait core::error::Error\">Error</a> + 'static,\n    T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"struct\" href=\"https://docs.rs/prost-types/0.12.2/prost_types/protobuf/struct.Struct.html\" title=\"struct prost_types::protobuf::Struct\">Struct</a>, Error = E&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.Error\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.Error\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"https://doc.rust-lang.org/1.77.0/core/convert/trait.TryFrom.html#associatedtype.Error\" class=\"associatedtype\">Error</a> = <a class=\"struct\" href=\"https://docs.rs/eyre/0.6.12/eyre/struct.Report.html\" title=\"struct eyre::Report\">Report</a></h4></section></summary><div class='docblock'>The type returned in the event of a conversion error.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.try_from\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/quilkin/net/endpoint/metadata.rs.html#291-310\">source</a><a href=\"#method.try_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.77.0/core/convert/trait.TryFrom.html#tymethod.try_from\" class=\"fn\">try_from</a>(value: <a class=\"struct\" href=\"https://docs.rs/prost-types/0.12.2/prost_types/protobuf/struct.Struct.html\" title=\"struct prost_types::protobuf::Struct\">Struct</a>) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.77.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self, Self::<a class=\"associatedtype\" href=\"https://doc.rust-lang.org/1.77.0/core/convert/trait.TryFrom.html#associatedtype.Error\" title=\"type core::convert::TryFrom::Error\">Error</a>&gt;</h4></section></summary><div class='docblock'>Performs the conversion.</div></details></div></details>","TryFrom<Struct>","quilkin::net::endpoint::EndpointMetadata"],["<section id=\"impl-StructuralPartialEq-for-MetadataView%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/quilkin/net/endpoint/metadata.rs.html#213\">source</a><a href=\"#impl-StructuralPartialEq-for-MetadataView%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/marker/trait.StructuralPartialEq.html\" title=\"trait core::marker::StructuralPartialEq\">StructuralPartialEq</a> for <a class=\"struct\" href=\"quilkin/net/endpoint/metadata/struct.MetadataView.html\" title=\"struct quilkin::net::endpoint::metadata::MetadataView\">MetadataView</a>&lt;T&gt;</h3></section>","StructuralPartialEq","quilkin::net::endpoint::EndpointMetadata"],["<section id=\"impl-Eq-for-MetadataView%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/quilkin/net/endpoint/metadata.rs.html#213\">source</a><a href=\"#impl-Eq-for-MetadataView%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> for <a class=\"struct\" href=\"quilkin/net/endpoint/metadata/struct.MetadataView.html\" title=\"struct quilkin::net::endpoint::metadata::MetadataView\">MetadataView</a>&lt;T&gt;</h3></section>","Eq","quilkin::net::endpoint::EndpointMetadata"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PartialEq-for-MetadataView%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/quilkin/net/endpoint/metadata.rs.html#213\">source</a><a href=\"#impl-PartialEq-for-MetadataView%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a> for <a class=\"struct\" href=\"quilkin/net/endpoint/metadata/struct.MetadataView.html\" title=\"struct quilkin::net::endpoint::metadata::MetadataView\">MetadataView</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.eq\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/quilkin/net/endpoint/metadata.rs.html#213\">source</a><a href=\"#method.eq\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.77.0/core/cmp/trait.PartialEq.html#tymethod.eq\" class=\"fn\">eq</a>(&amp;self, other: &amp;<a class=\"struct\" href=\"quilkin/net/endpoint/metadata/struct.MetadataView.html\" title=\"struct quilkin::net::endpoint::metadata::MetadataView\">MetadataView</a>&lt;T&gt;) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.0/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>self</code> and <code>other</code> values to be equal, and is used\nby <code>==</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ne\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.77.0/src/core/cmp.rs.html#242\">source</a></span><a href=\"#method.ne\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.77.0/core/cmp/trait.PartialEq.html#method.ne\" class=\"fn\">ne</a>(&amp;self, other: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.0/std/primitive.reference.html\">&amp;Rhs</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.0/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>!=</code>. The default implementation is almost always\nsufficient, and should not be overridden without very good reason.</div></details></div></details>","PartialEq","quilkin::net::endpoint::EndpointMetadata"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Default-for-MetadataView%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/quilkin/net/endpoint/metadata.rs.html#213\">source</a><a href=\"#impl-Default-for-MetadataView%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"quilkin/net/endpoint/metadata/struct.MetadataView.html\" title=\"struct quilkin::net::endpoint::metadata::MetadataView\">MetadataView</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.default\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/quilkin/net/endpoint/metadata.rs.html#213\">source</a><a href=\"#method.default\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.77.0/core/default/trait.Default.html#tymethod.default\" class=\"fn\">default</a>() -&gt; <a class=\"struct\" href=\"quilkin/net/endpoint/metadata/struct.MetadataView.html\" title=\"struct quilkin::net::endpoint::metadata::MetadataView\">MetadataView</a>&lt;T&gt;</h4></section></summary><div class='docblock'>Returns the “default value” for a type. <a href=\"https://doc.rust-lang.org/1.77.0/core/default/trait.Default.html#tymethod.default\">Read more</a></div></details></div></details>","Default","quilkin::net::endpoint::EndpointMetadata"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()