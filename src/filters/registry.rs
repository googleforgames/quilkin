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

use std::sync::Arc;

use crate::filters::{CreateFilterArgs, Error, Filter, FilterMap, FilterSet};

/// Registry of all [`Filter`]s that can be applied in the system.
///
/// **Note:** Cloning [`FilterRegistry`], clones a new reference to the data and
/// does not clone the data itself. In other words the clone is "shallow" and
/// not deep.
#[derive(Clone, Default)]
pub struct FilterRegistry {
    registry: Arc<FilterMap>,
}

impl FilterRegistry {
    /// Creates a new registry using the provided [`FilterSet`] as the set of
    /// available filters.
    pub fn new(factories: FilterSet) -> Self {
        Self {
            registry: Arc::new(
                factories
                    .into_iter()
                    .map(|factory| (factory.name(), factory))
                    .collect(),
            ),
        }
    }

    /// Creates and returns a new dynamic instance of [`Filter`] for a given
    /// `key`. Errors if ther filter cannot be found, or if there is a
    /// configuration issue.
    pub fn get(&self, key: &str, args: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
        match self.registry.get(key).map(|p| p.create_filter(args)) {
            None => Err(Error::NotFound(key.to_owned())),
            Some(filter) => filter,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::test_utils::{logger, new_registry};

    use super::*;
    use crate::endpoint::{Endpoint, Endpoints};
    use crate::filters::{ReadContext, ReadResponse, WriteContext, WriteResponse};
    use prometheus::Registry;

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
        let reg = new_registry(&logger());

        match reg.get(
            &String::from("not.found"),
            CreateFilterArgs::fixed(Registry::default(), None),
        ) {
            Ok(_) => unreachable!("should not be filter"),
            Err(err) => assert_eq!(Error::NotFound("not.found".to_string()), err),
        };

        assert!(reg
            .get(
                &String::from("TestFilter"),
                CreateFilterArgs::fixed(Registry::default(), None)
            )
            .is_ok());

        let filter = reg
            .get(
                &String::from("TestFilter"),
                CreateFilterArgs::fixed(Registry::default(), None),
            )
            .unwrap();

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let endpoint = Endpoint::new(addr);

        assert!(filter
            .read(ReadContext::new(
                Endpoints::new(vec![Endpoint::new("127.0.0.1:8080".parse().unwrap(),)])
                    .unwrap()
                    .into(),
                addr,
                vec![]
            ))
            .is_some());
        assert!(filter
            .write(WriteContext::new(&endpoint, addr, addr, vec![],))
            .is_some());
    }
}
