/*
 * Copyright 2020 Google LLC All Rights Reserved.
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

use crate::extensions::filter_registry::{
    CreateFilterArgs, Error, FilterFactory, ReadContext, ReadResponse, WriteContext, WriteResponse,
};
use crate::extensions::Filter;
use wasmtime::*;

const WASM: &[u8] = include_bytes!("./../../../target/wasm32-unknown-unknown/debug/quilkin_wasm.wasm");

/// Factory for the Debug
pub struct WasmtimeFactory {
    engine: Engine,
}

impl WasmtimeFactory {
    pub fn new() -> Self {
        let mut config = Config::default();
        config.wasm_reference_types(true);
        let engine = Engine::new(&config).unwrap();

        Self { engine }
    }
}

impl FilterFactory for WasmtimeFactory {
    fn name(&self) -> String {
        "quilkin.extensions.filters.wasmtime.v1alpha1.Wasmtime".into()
    }

    fn create_filter(&self, _args: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
        Ok(Box::new(Wasmtime::new(self.engine.clone(), WASM)))
    }
}

/// Debug logs all incoming and outgoing packets
pub struct Wasmtime {
    engine: Engine,
    module: Module,
}

impl Wasmtime {
    /// Constructor for the Debug. Pass in a "id" to append a string to your log messages from this
    /// Filter.
    fn new(engine: Engine, wat: &[u8]) -> Self {
        let module = Module::from_binary(&engine, wat).unwrap();

        Self {
            engine,
            module,
        }
    }

    unsafe fn _get_memory(&self, instance: &Instance, ptr: *const u8, len: usize) -> Result<Vec<u8>, ()> {
        let memory = instance.get_memory("memory").unwrap();
        let raw = memory.data_ptr().offset(*ptr as isize);
        Ok(Vec::from_raw_parts(raw, len, len))
    }

    /// Copy a byte array into an instance's linear memory
    /// and return the offset relative to the module's memory.
    fn copy_memory(&self, instance: &Instance, bytes: &Vec<u8>) -> Result<isize, ()> {
        let memory = instance.get_memory("memory").unwrap();
        // Get the guest's exported alloc function, and call it with the
        // length of the byte array we are trying to copy.
        // The result is an offset relative to the module's linear memory,
        // which is used to copy the bytes into the module's memory.
        // Then, return the offset.
        let alloc = instance
            .get_typed_func::<i32, i32>("alloc")
            .expect("expected alloc function not found");
        let guest_ptr_offset = alloc.call(bytes.len() as i32).unwrap() as isize;

        unsafe {
            let raw = memory.data_ptr().offset(guest_ptr_offset);
            raw.copy_from(bytes.as_ptr(), bytes.len());
        }

        return Ok(guest_ptr_offset);
    }
}

impl Filter for Wasmtime {
    fn read(&self, ctx: ReadContext) -> Option<ReadResponse> {
        let store = Store::new(&self.engine);
        let instance = Instance::new(&store, &self.module, &[]).unwrap();
        let ptr = self.copy_memory(&instance, &ctx.contents).unwrap();
        let func = instance.get_typed_func::<(i32, i32), i32>("read").unwrap();
        let result = func.call((ptr as i32, ctx.contents.len() as i32)).unwrap();
        (result != 0).then(|| ctx.into())
    }

    fn write(&self, ctx: WriteContext) -> Option<WriteResponse> {
        let store = Store::new(&self.engine);
        let instance = Instance::new(&store, &self.module, &[]).unwrap();
        let ptr = self.copy_memory(&instance, &ctx.contents).unwrap();
        let func = instance.get_typed_func::<(i32, i32), i32>("write").unwrap();
        let result = func.call((ptr as i32, ctx.contents.len() as i32)).unwrap();
        (result != 0).then(|| ctx.into())
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::{assert_filter_read_no_change, assert_write_no_change};

    use super::*;

    #[test]
    fn read() {
        let wasmtime = Wasmtime::new(Engine::default(), WASM);
        assert_filter_read_no_change(&wasmtime);
    }

    #[test]
    fn write() {
        let wasmtime = Wasmtime::new(Engine::default(), WASM);
        assert_write_no_change(&wasmtime);
    }
}
