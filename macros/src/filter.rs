/*
 * Copyright 2021 Google LLC All Rights Reserved.
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

use proc_macro2::{Span, TokenStream};
use quote::{quote, ToTokens, TokenStreamExt};
use syn::{
    parse::{Parse, ParseStream},
    spanned::Spanned,
    Ident, NestedMeta, Token,
};

/// The data representation of `#[quilkin::filter]`.
pub(crate) struct FilterAttribute {
    /// The protobuf ID for the filter.
    id: String,
    /// The visibility of the `PROTOBUF_ID` constant.
    vis: syn::Visibility,
}

fn parse_str_literal(input: &syn::Lit, span: Span) -> syn::Result<String> {
    match input {
        syn::Lit::Str(s) => {
            let s = s.value();

            if s.is_empty() {
                Err(syn::Error::new(span, "Str literal must not be empty."))
            } else {
                Ok(s)
            }
        }
        _ => Err(syn::Error::new(span, "Expected str literal.")),
    }
}

fn parse_meta_lit_str(input: &NestedMeta, span: Span) -> syn::Result<String> {
    match input {
        NestedMeta::Lit(lit) => parse_str_literal(lit, lit.span()),
        _ => Err(syn::Error::new(span, "Expected literal.")),
    }
}

fn parse_meta_name_value(input: &NestedMeta, span: Span) -> syn::Result<syn::MetaNameValue> {
    match input {
        NestedMeta::Meta(syn::Meta::NameValue(value)) => Ok(value.clone()),
        _ => Err(syn::Error::new(span, "Expected `<name>=<value>`.")),
    }
}

impl Parse for FilterAttribute {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let args = syn::punctuated::Punctuated::<NestedMeta, Token![,]>::parse_terminated(input)?;

        let mut args = args.iter();

        let id = {
            let arg = args
                .next()
                .ok_or_else(|| syn::Error::new(input.span(), "Expected a protobuf identifier."))?;
            parse_meta_lit_str(arg, arg.span())?
        };

        let mut vis = None;

        for arg in args {
            let name_value = parse_meta_name_value(arg, arg.span())?;

            if name_value.path.is_ident("vis") {
                if vis.is_some() {
                    return Err(syn::Error::new(
                        name_value.span(),
                        "`vis` defined more than once.",
                    ));
                }

                let input = parse_str_literal(&name_value.lit, name_value.lit.span())?;
                vis = Some(syn::parse_str(&input)?);
            }
        }

        Ok(Self {
            id,
            vis: vis.unwrap_or_else(|| syn::parse_quote!(pub (crate))),
        })
    }
}

impl ToTokens for FilterAttribute {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let id = &self.id;
        let vis = &self.vis;
        let mut protobuf_path =
            syn::punctuated::Punctuated::<syn::PathSegment, syn::token::Colon2>::new();

        let split = self.id.split('.');
        protobuf_path
            .extend(split.map(|s| syn::PathSegment::from(Ident::new(s, Span::mixed_site()))));

        tokens.append_all(quote! {
            #vis const FILTER_NAME: &'static str = #id;
        })
    }
}
