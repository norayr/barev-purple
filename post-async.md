# Asynchronous post checkpoints

`post-async.c` validates application snapshots and checkpoint lineage on the
owning thread while the bounded `post-io.c` workers read and replace copied opaque
bytes. Its native counterpart is `BarevPostAsync`.

## Loading and saving

Call `barev_post_async_start` on the application thread before submitting work.
`barev_post_async_load` creates a request for
`PROFILE/barev/posts-OWNER.state`. Poll `barev_post_async_loaded` until it returns
a terminal status. Output context/store slots must initially be `NULL` and remain
unchanged on failure. A missing file returns a ready context with a `NULL` store;
the account layer decides whether first initialization is permitted.

Successful loads decode an independent baseline and application store. Saving
checks owner binding and lineage, encodes an isolated proposed image, and retains
a validated baseline before submitting a conditional replacement. Later caller
mutations cannot alter that prepared image. Poll `barev_post_async_saved` to
advance the context only after successful completion.

Return statuses are `okay` (0), `missing` (1), `invalid` (2), `storageError` (3),
`changed` (4), `pending` (5) and `busy` (6). Each context permits one pending save.
`barev_post_async_ready` is false while saving or after an uncertain save result.
Storage failure, stale-writer detection or save cancellation blocks that context;
close it and load again before further writes.

## Lifetime and shutdown

Request and context slots initially contain `NULL`. All application calls belong
to the thread that starts the service. Foreign-thread operations cannot mutate
contexts, consume requests or stop the worker service.

`barev_post_async_cancel` releases one application request. Cancelling a load
retires its unpublished context; cancelling a save blocks its context. Closing a
context retires its baseline while an outstanding request keeps its native
allocation alive. Late save completion cannot revive a closed context.

Accepted writes may finish after cancellation, closure or worker shutdown. A
complete image may therefore be recovered by a later load even when the original
caller receives no successful reply. Close contexts and cancel retained requests,
then stop the service and keep the module loaded until
`barev_post_async_idle` succeeds. Restart is permitted after workers drain.

The shared worker's filesystem validation, profile locking, atomic replacement
and synchronization contracts are described in `post-io.md`.

## Tests

`make test-post-async` uses disposable profiles and fresh processes to check load
validation, missing history, isolated prepared images, serialized saves, lineage,
competing writers, lock failure, cancellation, context closure, queue exhaustion,
foreign-thread calls, shutdown/restart and recovery of accepted writes. The C
sanitizer profile also enables leak and stack-use-after-return detection.
