/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

mod filter;
mod include;

use quote::{quote, ToTokens};
use syn::parse_macro_input;

use filter::FilterAttribute;
use include::IncludeProto;

/// Includes generated Protobuf definitions from `tonic`.
///
/// Accepts a single argument for the gRPC package name, which then recreates
/// the package structure as modules.
///
/// ### Input
/// ```
/// quilkin::include_proto!("quilkin.extensions.filters.debug.v1alpha1");
/// ```
///
/// ### Output
/// ```
/// mod quilkin {
///     pub(crate) mod extensions {
///         pub(crate) mod filters {
///             pub(crate) mod debug {
///                 pub(crate) mod v1alpha1 {
///                     #![doc(hidden)]
///                     tonic::include_proto!("quilkin.extensions.filters.debug.v1alpha1");
///                 }
///             }
///         }
///     }
/// }
/// ```
#[proc_macro]
pub fn include_proto(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    parse_macro_input!(input as IncludeProto)
        .to_token_stream()
        .into()
}

/// An attribute procedural macro for defining filters.
///
/// The `filter` attribute can be prepended to any struct, to automatically
/// import the protobuf runtime version that was defined with [`include_proto`],
/// and it defines an associated constant named `FILTER_NAME` containing
/// the protobuf identifier.
///
/// A string literal representing the gRPC Protobuf name of the struct should
/// always the first argument, followed by these optional keyword arguments for
/// additional configuration.
///
/// - `root` sets the root of the path to import your Protobuf generated struct.
///   **default:** `self`.
///
/// - `vis` sets the visibility of the associated `PROTOBUF_ID` constant.
///   **default:** `pub (crate)`.
///
/// The macro generates code that looks something like the following;
///
/// ### Input
/// ```
/// #[quilkin::filter("quilkin.extensions.filters.debug.v1alpha1.Debug")]
/// pub struct Debug;
/// ```
///
/// ### Output
/// ```
/// impl Debug {
///     pub (crate) const FILTER_NAME: &str = "quilkin.extensions.filters.debug.v1alpha1.Debug";
/// }
/// ```
#[proc_macro_attribute]
pub fn filter(
    args: proc_macro::TokenStream,
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let constant = parse_macro_input!(args as FilterAttribute);
    let item = parse_macro_input!(input as syn::ItemStruct);
    let name = &item.ident;
    let (impl_generics, ty_generics, where_clause) = item.generics.split_for_impl();

    quote!(
        #item

        impl #impl_generics #name #ty_generics #where_clause {
            #constant
        }
    )
    .into()
}
