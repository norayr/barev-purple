# Background checkpoint file I/O

`post-io.c` supplies bounded background reads and conditional atomic replacements
of opaque checkpoint bytes. It uses GLib's existing thread pool API and POSIX file
operations, with no additional library dependency. Its standalone tests exercise
the binding before application and desktop integration.

## Ownership and bounds

All public calls belong to the thread that calls `BarevPostIO_Start`. Submission
copies the profile, owner identifier and byte buffers into native allocations.
Workers never access Oberon objects or caller-owned memory. Completion is polled
on the owning thread; there are no application callbacks from workers.

At most four jobs are outstanding, including completed jobs whose results have
not been released. A private pool runs at most two jobs concurrently. Each input
and result image is bounded to 6 MiB. A full queue or invalid submission returns
handle zero. Positive handles are not reused during the module's lifetime.

## Operations

`Read` retrieves `PROFILE/barev/posts-OWNER.state` under the existing validated
private-profile directory lock. `Replace` performs an exact-byte conditional
replacement under that same lock. An expected length of `-1` means an absent
file; a length of zero means an existing empty file.

The replacement succeeds when the current bytes equal the expected image or
already equal the replacement image. Otherwise it returns `changed`. A current
file exceeding the image bound is rejected. Symlinks and nonregular checkpoint
files are refused. Lock contention is reported without waiting.

New data is written to a descriptor-relative, exclusively created temporary file
with mode `0600` before the umask is applied. After writing and file synchronization,
the worker atomically renames it over the checkpoint and synchronizes the
directory. Identical-image retries also synchronize the directory. A failure
after rename can leave the complete new image installed. Releasing a request or
stopping the worker does not roll back an accepted write.

The binding treats contents as opaque. Oberon validates the expected and proposed
snapshots, owner, lineage and audiences before submission, then applies commit
decisions on the runtime's owning thread. A changed opaque image requires a fresh
read and validation before further application operations.

## Results and shutdown

`Status` returns `okay` (0), `missing` (1), `invalid` (2), `storageError` (3),
`changed` (4) or `pending` (5). Invalid or released handles return `invalid`.
`Length` and `Copy` expose completed successful read results. Copying into an
undersized buffer or copying a pending/failed result leaves the output untouched.

`Release` abandons one handle without waiting. `Stop` rejects submissions and
abandons every result. Pending jobs retain their native buffers until completion.
`Idle` reaps abandoned completed jobs and joins worker epilogues after all I/O has
finished. Hosts must keep the module loaded until `Idle` succeeds. Starting again
is allowed after shutdown has drained; handles retain their monotonic sequence.

## Validation

The Oberon repository runs `make post-io-test`; the C repository runs
`make test-post-io`. Disposable profiles cover binary and maximum-size images,
exact comparisons, missing versus empty files, partial/interrupted I/O, write,
read, close, rename and synchronization failures, lock contention, wrong file
types, queue bounds, foreign-thread calls and shutdown/restart lifetimes.

A filesystem barrier holds a worker in `fsync` while the main context continues
processing timer events. It also checks that submitted input bytes have been
copied and that abandoning an accepted write neither exposes caller memory nor
permits early module unloading. Validation is Linux-only; the Windows file path
returns a storage error.
