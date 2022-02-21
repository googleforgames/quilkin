/*
 * Copyright 2020 Google LLC
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

use arc_swap::ArcSwap;
use once_cell::sync::Lazy;

use crate::filters::{CreateFilterArgs, DynFilterFactory, Error, FilterInstance, FilterSet};

static REGISTRY: Lazy<ArcSwap<FilterSet>> =
    Lazy::new(|| ArcSwap::new(std::sync::Arc::new(FilterSet::default())));

/// Registry of all [`Filter`][crate::filters::Filter]s that can be applied in the system.
///
/// **Note:** Cloning [`FilterRegistry`], clones a new reference to the data and
/// does not clone the data itself. In other words the clone is "shallow" and
/// not deep.
#[derive(Debug)]
pub struct FilterRegistry;

impl FilterRegistry {
    /// Loads the provided [`FilterSet`] into the registry of available filters.
    pub fn register(factories: impl IntoIterator<Item = DynFilterFactory>) {
        let mut registry = FilterSet::clone(&REGISTRY.load_full());
        for factory in factories {
            registry.insert(factory);
        }

        REGISTRY.store(std::sync::Arc::from(registry));
    }

    /// Creates and returns a new dynamic instance of [`Filter`][crate::filters::Filter] for a given
    /// `key`. Errors if the filter cannot be found, or if there is a
    /// configuration issue.
    pub fn get(key: &str, args: CreateFilterArgs) -> Result<FilterInstance, Error> {
        match REGISTRY.load().get(key).map(|p| p.create_filter(args)) {
            None => Err(Error::NotFound(key.to_owned())),
            Some(filter) => filter,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::test_utils::load_test_filters;

    use super::*;
    use crate::endpoint::{Endpoint, EndpointAddress, Endpoints};
    use crate::filters::{
        Filter, FilterRegistry, ReadContext, ReadResponse, WriteContext, WriteResponse,
    };

    struct TestFilter {}

    impl Filter for TestFilter {
        fn read(&self, _: ReadContext) -> Option<ReadResponse> {
            None
        }

        fn write(&self, _: WriteContext) -> Option<WriteResponse> {
            None
        }
    }

    #[test]
    fn insert_and_get() {
        load_test_filters();

        match FilterRegistry::get(&String::from("not.found"), CreateFilterArgs::fixed(None)) {
            Ok(_) => unreachable!("should not be filter"),
            Err(err) => assert_eq!(Error::NotFound("not.found".to_string()), err),
        };

        assert!(
            FilterRegistry::get(&String::from("TestFilter"), CreateFilterArgs::fixed(None)).is_ok()
        );

        let filter =
            FilterRegistry::get(&String::from("TestFilter"), CreateFilterArgs::fixed(None))
                .unwrap()
                .filter;

        let addr: EndpointAddress = (Ipv4Addr::LOCALHOST, 8080).into();
        let endpoint = Endpoint::new(addr.clone());

        assert!(filter
            .read(ReadContext::new(
                Endpoints::new(vec![endpoint.clone()]).unwrap().into(),
                addr.clone(),
                vec![]
            ))
            .is_some());
        assert!(filter
            .write(WriteContext::new(&endpoint, addr.clone(), addr, vec![],))
            .is_some());
    }
}
