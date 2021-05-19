use std::collections::HashMap;

use crate::{
    extensions::{filters, FilterFactory},
};

type DynFilterFactory = Box<dyn FilterFactory>;
type FilterMap = HashMap<&'static str, DynFilterFactory>;

#[derive(Default)]
pub struct FilterSet(FilterMap);

impl FilterSet {
    /// Returns a default set of filters that are user configurable and used with
    /// each default instance.
    ///
    /// Current default filters:
    /// - [`Debug`][filters::Debug]
    /// - [`LocalRateLimit`][filters::LocalRateLimit]
    /// - [`ConcatBytes`][filters::ConcatBytes]
    /// - [`LoadBalancer`][filters::LoadBalancer]
    /// - [`CaptureBytes`][filters::CaptureBytes]
    /// - [`TokenRouter`][filters::TokenRouter]
    /// - [`Compress`][filters::Compress]
    pub fn default(base: &Logger) -> Self {
        std::array::IntoIter::new([
            Box::from(filters::DebugFactory::new(base)) as Box<dyn FilterFactory>,
            Box::from(filters::RateLimitFilterFactory::default()),
            Box::from(filters::ConcatBytesFactory::default()),
            Box::from(filters::LoadBalancerFilterFactory::default()),
            Box::from(filters::CaptureBytesFactory::new(base)),
            Box::from(filters::TokenRouterFactory::new(base)),
            Box::from(filters::CompressFactory::new(base)),
        ])
            .collect()
    }

    /// Insert a new entry.
    fn insert(&mut self, value: DynFilterFactory) {
        self.0.insert(value.name(), value);
    }

    /// Returns the filters from self, plus the filter's from `rhs`. With the
    /// filters from `rhs` overrding any conflicting entry.
    pub fn join(mut self, rhs: Self) -> Self {
        for item in rhs {
            self.insert(item);
        }
        self
    }
}

impl std::iter::FromIterator<DynFilterFactory> for FilterSet {
    fn from_iter<I: IntoIterator<Item = DynFilterFactory>>(iter: I) -> Self
    {
        let mut set = Self(Default::default());

        for item in iter {
            set.insert(item);
        }

        set
    }
}

impl std::iter::IntoIterator for FilterSet {
    type Item = DynFilterFactory;
    type IntoIter = impl IntoIterator<Item=Self::Item>;

    fn into_iter(self) -> Self::IntoIter
    {
        self.0.into_iter().map(into_value)
    }
}

fn into_value((key, value): (&str, DynFilterFactory)) -> DynFilterFactory {
    value

}
