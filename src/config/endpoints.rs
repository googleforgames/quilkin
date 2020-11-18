use crate::config::EndPoint;
use std::sync::Arc;

#[derive(Debug)]
pub struct EmptyListError;

#[derive(Debug)]
pub struct IndexOutOfRangeError;

/// Endpoints represents the set of all known upstream endpoints.
#[derive(Clone)]
pub struct Endpoints(Arc<Vec<EndPoint>>);

/// UpstreamEndpoints is wrapper [`Endpoints`] that exposes a subset of
/// the internal endpoints.
/// This subset is guaranteed to be non-empty.
pub enum UpstreamEndpoints {
    // All is backed by all endpoints in the original set.
    All(Endpoints),
    // Some is backed by a subset of endpoints in the original set.
    // It uses indices into the original set, to form its subset.
    Some(Endpoints, Vec<usize>),
}

impl Endpoints {
    /// Returns an [`Endpoints`] backed by the provided list of endpoints.
    pub fn new(endpoints: Vec<EndPoint>) -> Result<Self, EmptyListError> {
        if endpoints.is_empty() {
            Err(EmptyListError)
        } else {
            Ok(Self(Arc::new(endpoints)))
        }
    }

    /// Returns a [`Endpoints`] backed by an empty list of endpoints.
    ///
    /// # Safety
    /// Invoking operations on [`Endpoints`] empty is not supported and the effect
    /// is undefined. The caller must either ensure that the returned value is populated
    /// by some other means or avoid invoking any operation the returned value.
    pub(crate) unsafe fn empty() -> Self {
        Self(Arc::new(vec![]))
    }
}

impl From<Endpoints> for UpstreamEndpoints {
    fn from(endpoints: Endpoints) -> Self {
        UpstreamEndpoints::All(endpoints)
    }
}

impl UpstreamEndpoints {
    /// Returns the number of endpoints in the backing set.
    pub fn size(&self) -> usize {
        match self {
            UpstreamEndpoints::All(endpoints) => endpoints.0.len(),
            UpstreamEndpoints::Some(_, subset) => subset.len(),
        }
    }

    /// Returns a new [`UpstreamEndpoints`] backed by a singleton set that
    /// contains the endpoint at the specified zero-indexed position.
    pub fn keep(self, index: usize) -> Result<Self, IndexOutOfRangeError> {
        if index >= self.size() {
            return Err(IndexOutOfRangeError);
        }

        let (endpoints, index) = match self {
            UpstreamEndpoints::All(endpoints) => (endpoints, index),
            UpstreamEndpoints::Some(endpoints, subset) => (endpoints, subset[index]),
        };

        Ok(UpstreamEndpoints::Some(endpoints, vec![index]))
    }

    /// Returns a new [`UpstreamEndpoints`] backed by a subset set that
    /// contains only the endpoint for which the predicate returned `true`.
    /// Returns `None` if the predicate returns `false` for all endpoints.
    pub fn retain<F>(self, predicate: F) -> Option<Self>
    where
        F: Fn(&EndPoint) -> bool,
    {
        let (endpoints, subset) = match self {
            UpstreamEndpoints::All(endpoints) => {
                let subset = endpoints
                    .0
                    .iter()
                    .enumerate()
                    .filter(|(_, ep)| predicate(ep))
                    .map(|(i, _)| i)
                    .collect::<Vec<_>>();
                (endpoints, subset)
            }
            UpstreamEndpoints::Some(endpoints, subset) => {
                let subset = subset
                    .into_iter()
                    .filter(|&index| predicate(&endpoints.0[index]))
                    .collect::<Vec<_>>();
                (endpoints, subset)
            }
        };

        if subset.is_empty() {
            None
        } else {
            Some(UpstreamEndpoints::Some(endpoints, subset))
        }
    }

    /// Iterate over the endpoints in the backing set.
    pub fn iter(&self) -> UpstreamEndpointsIter {
        UpstreamEndpointsIter {
            endpoints: self,
            index: 0,
        }
    }
}

/// An Iterator over all endpoints in an [`UpstreamEndpoints`]
pub struct UpstreamEndpointsIter<'a> {
    endpoints: &'a UpstreamEndpoints,
    index: usize,
}

impl<'a> Iterator for UpstreamEndpointsIter<'a> {
    type Item = &'a EndPoint;

    fn next(&mut self) -> Option<Self::Item> {
        match self.endpoints {
            UpstreamEndpoints::All(endpoints) => {
                self.index += 1;
                endpoints.0.get(self.index - 1)
            }
            UpstreamEndpoints::Some(endpoints, subset) => {
                self.index += 1;
                subset
                    .get(self.index - 1)
                    .and_then(|&index| endpoints.0.get(index))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Endpoints;
    use crate::config::{EndPoint, UpstreamEndpoints};

    fn ep(id: usize) -> EndPoint {
        EndPoint::new(
            format!("ep-{}", id),
            format!("127.0.0.{}:8080", id).parse().unwrap(),
            vec![],
        )
    }

    #[test]
    fn new_endpoints() {
        assert!(Endpoints::new(vec![]).is_err());
        assert!(Endpoints::new(vec![ep(1)]).is_ok());
    }

    #[test]
    fn keep() {
        let initial_endpoints = vec![ep(1), ep(2), ep(3)];

        let up: UpstreamEndpoints = Endpoints::new(initial_endpoints.clone()).unwrap().into();
        assert!(up.keep(initial_endpoints.len() - 1).is_ok());

        let up: UpstreamEndpoints = Endpoints::new(initial_endpoints.clone()).unwrap().into();
        assert!(up.keep(initial_endpoints.len()).is_err());

        // Limit the set to only one element.
        let up = UpstreamEndpoints::from(Endpoints::new(initial_endpoints.clone()).unwrap())
            .keep(1)
            .unwrap();
        let up = up.keep(0).unwrap();
        assert_eq!(vec![&initial_endpoints[1]], up.iter().collect::<Vec<_>>());

        let up = UpstreamEndpoints::from(Endpoints::new(initial_endpoints).unwrap())
            .keep(1)
            .unwrap();
        assert!(up.keep(1).is_err());
    }

    #[test]
    fn retain() {
        let initial_endpoints = vec![ep(1), ep(2), ep(3), ep(4)];

        let up: UpstreamEndpoints = Endpoints::new(initial_endpoints).unwrap().into();

        let up = up.retain(|ep| ep.name != "ep-2").unwrap();
        assert_eq!(up.size(), 3);
        assert_eq!(
            vec![ep(1), ep(3), ep(4)],
            up.iter().cloned().collect::<Vec<_>>()
        );

        let up = up.retain(|ep| ep.name != "ep-3").unwrap();
        assert_eq!(up.size(), 2);
        assert_eq!(vec![ep(1), ep(4)], up.iter().cloned().collect::<Vec<_>>());
    }

    #[test]
    fn upstream_len() {
        let endpoints: UpstreamEndpoints =
            Endpoints::new(vec![ep(1), ep(2), ep(3)]).unwrap().into();
        // starts out with all endpoints.
        assert_eq!(endpoints.size(), 3);
        // verify that the set is now a singleton.
        assert_eq!(endpoints.keep(1).unwrap().size(), 1);
    }

    #[test]
    fn upstream_all_iter() {
        let initial_endpoints = vec![ep(1), ep(2), ep(3)];
        let endpoints: UpstreamEndpoints =
            Endpoints::new(initial_endpoints.clone()).unwrap().into();

        let result = endpoints.iter().cloned().collect::<Vec<_>>();
        assert_eq!(initial_endpoints, result);
    }

    #[test]
    fn upstream_some_iter() {
        let endpoints = UpstreamEndpoints::from(Endpoints::new(vec![ep(1), ep(2), ep(3)]).unwrap())
            .keep(1)
            .unwrap();
        assert_eq!(vec![ep(2)], endpoints.iter().cloned().collect::<Vec<_>>());
    }
}
