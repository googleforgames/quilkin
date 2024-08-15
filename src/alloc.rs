mod metrics;
pub use metrics::spawn_heap_stats_updates;

cfg_if::cfg_if! {
    if #[cfg(feature = "heap-stats")] {
        mod tracking;
    } else if #[cfg(feature = "mimalloc")] {
        #[global_allocator]
        static GLOBAL_ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;
    } else {
    }
}
