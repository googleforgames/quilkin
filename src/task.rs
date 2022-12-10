pub(crate) fn provider<FUTURE, TASK, OUTPUT, ERROR>(
    task: TASK,
) -> impl std::future::Future<Output = Result<OUTPUT, ERROR>>
where
    ERROR: std::fmt::Display,
    FUTURE: std::future::Future<Output = Result<OUTPUT, ERROR>>,
    TASK: Fn() -> FUTURE,
{
    const PROVIDER_BACKOFF: std::time::Duration = std::time::Duration::from_millis(250);
    tryhard::retry_fn(task)
        .retries(u32::MAX)
        .exponential_backoff(PROVIDER_BACKOFF)
        .on_retry(|_, _, error| {
            let error = error.to_string();
            async move {
                tracing::warn!(%error, "provider task error, retrying");
            }
        })
}
