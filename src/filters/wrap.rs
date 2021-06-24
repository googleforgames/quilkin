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
//! A wrapper that allows you to use closures for writing filters instead of
//! needing newtypes. `Wrapper` contains all the information needed to both run
//! and create the filters, so it can implement both `Filter` and
//! `FilterFactory` and this is safe because we only ever expose one of
//! those traits across the API boundary.

use super::{prelude::*, DynFilterFactory};

type ReadFn = fn(ReadContext) -> Option<ReadResponse>;
type WriteFn = fn(WriteContext) -> Option<WriteResponse>;

fn no_write(ctx: WriteContext) -> Option<WriteResponse> {
    Some(ctx.into())
}
fn no_read(ctx: ReadContext) -> Option<ReadResponse> {
    Some(ctx.into())
}

/// Creates a single function filter factory named `name` that is called
/// on [`Filter::read`].
/// ```
/// let factory = quilkin::filters::read("print-contents.v1", |ctx| {
///     println!("packet: {:?}", ctx.contents);
///     Some(ctx.into())
/// });
/// ```
pub fn read(name: &'static str, read_fn: ReadFn) -> DynFilterFactory {
    Box::new(Wrapper::new(name, read_fn, no_write))
}

/// Creates a single function filter factory named `name` that is called
/// on [`Filter::write`].
/// ```
/// use std::net::{SocketAddr, IpAddr, Ipv4Addr};
///
/// let factory = quilkin::filters::write("redirect.v1", |mut ctx| {
///     ctx.to = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
///     Some(ctx.into())
/// });
/// ```
pub fn write(name: &'static str, write_fn: WriteFn) -> DynFilterFactory {
    Box::new(Wrapper::new(name, no_read, write_fn))
}

/// Creates a two function filter factory named `name` where `read_fn` is called
/// on [`Filter::read`] and `write_fn` is called on [`Filter::write`].
/// ```
/// let factory = quilkin::filters::read_write(
///     "log.v1",
///     |ctx| {
///         println!("Reading from {}", ctx.from);
///         Some(ctx.into())
///     },
///     |ctx| {
///         println!("Writing to {}", ctx.to);
///         Some(ctx.into())
///     }
/// );
/// ```
pub fn read_write(name: &'static str, read_fn: ReadFn, write_fn: WriteFn) -> DynFilterFactory {
    Box::new(Wrapper::new(name, read_fn, write_fn))
}

struct Wrapper {
    name: &'static str,
    read_fn: ReadFn,
    write_fn: WriteFn,
}

impl Wrapper {
    fn new(name: &'static str, read_fn: ReadFn, write_fn: WriteFn) -> Self {
        Self {
            name,
            read_fn,
            write_fn,
        }
    }
}

impl FilterFactory for Wrapper {
    fn name(&self) -> &'static str {
        self.name
    }

    fn create_filter(&self, _: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
        Ok(Box::new(Self::new(self.name, self.read_fn, self.write_fn)))
    }
}

impl Filter for Wrapper {
    fn read(&self, ctx: ReadContext) -> Option<ReadResponse> {
        (self.read_fn)(ctx)
    }

    fn write(&self, ctx: WriteContext) -> Option<WriteResponse> {
        (self.write_fn)(ctx)
    }
}
