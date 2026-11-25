# jaunt-recording-s3

An S3-compatible recording sink for the Jaunt control daemon. Recordings are staged
on local disk while a session is running and published to the bucket when the
agent completes the upload.

## Bucket layout

For every recording the sink writes two objects under the configured prefix
(default `recordings/`): `<year>/<month>/<session id>.cast` and
`<year>/<month>/<session id>.manifest.json`. The cast is uploaded first, the
manifest last; the manifest is the commit marker. Both are created with
conditional puts, so an existing object is never overwritten.

## Permissions

The credentials need `s3:PutObject`, `s3:GetObject`, `s3:ListBucket`,
`s3:DeleteObject` and `s3:AbortMultipartUpload` on the prefix. Add a lifecycle rule
with `AbortIncompleteMultipartUpload` so that interrupted multipart uploads do not
accumulate.

## What happens when an object already exists

One decision function decides every case, whoever asks (a live completion, an
idle sweep, a restart, a retry of a staged recording, the directory sink):

| The bucket holds | Outcome |
|---|---|
| nothing | the recording is published |
| the same cast and the same manifest | adopted, the staged files are released |
| the same cast and a synthetic incomplete manifest of the same session | adopted as incomplete (a lost acknowledgement) |
| the same cast and a different manifest | conflict |
| another cast, or a manifest of another session, node, user or login | conflict |
| a manifest that cannot be read | conflict |
| a manifest that is not a well formed record of its cast (unknown version; complete with dropped chunks, without a digest although it has chunks, or with a raw size other than the cast's; chunks and raw bytes without a cast object) | conflict, with or without staged files |
| the store cannot be read (timeout, outage, throttling, breaker open) | retried later, the recording stays receiving |
| a local read error while comparing | retried later, never a conflict |

A conflict never touches the bucket and never deletes anything locally. The
staged files stay on disk, the row stays `receiving`, further completions answer
`409 conflict`, and one error log line names the session id and the reason. The
periodic maintenance log lists up to 20 held and conflicted session ids.

## Clearing a conflict

1. Find the session id in the error log (`a recording conflicts with what the recording
   storage holds`) or in `conflicted_ids` of the maintenance log.
2. Decide which side is right.
   - The object in the bucket is foreign or stale: delete both objects of that
     session id (`.cast` and `.manifest.json`) from the bucket.
   - The staged recording is not wanted: delete its staged files
     (`<staging root>/<year>/<month>/<session id>.cast.part` and the matching
     `.manifest.pending`).
3. Restart the daemon. The conflicted set is held in memory only; on start every
   `receiving` row is looked at again and published, adopted or given up by the
   same table.

## Quarantine

Staged files whose pending manifest stays unreadable or does not fit the staged cast
are counted per session. After five failed attempts the files are moved to
`<staging root>/quarantine/<session id>/`, one error log line is written with
`reason = "quarantined"`, and the row becomes `failed`. Quarantined files are never
removed by the sink: inspect them and delete them by hand.

A staged recording whose store keeps refusing it for other reasons is held, not
deleted, and is listed as `refused_ids`.

## The bucket is a trusted store

Only the control server and trusted operators write to the bucket. Anyone with
write access to it can alter or forge recordings: digests are verified only
against staged data, so a manifest forged together with a matching cast is
accepted when no staged files exist to compare with. The structural checks
above hold for every caller, but they are not a defence against a writer who
controls the bucket. Restrict write access to the bucket accordingly.

## Local faults that never clear by themselves

A local read, open or write error on the staged files (permissions, EIO,
EMFILE, ENOSPC while stashing the manifest) is never a conflict and never
destroys anything: the live `complete` answers 503, an idle salvage is deferred,
a recovery leaves the row `receiving`, and `publish_pending` retries every cycle.
These faults are not counted toward the quarantine and they are not bounded in
time. A permanent one stays forever: a symlink or a directory in place of a
`.manifest.pending` is never read and never counted, a directory, a FIFO or a
symlink in place of a `.cast.part` or `chmod 000` on it defers every cycle, and
the row stays `receiving`. Each cycle logs a line naming the session id and the
error. The operator reads that line and must fix the file (restore the
permissions, remove the intruding entry) or remove the staged files of that
session id.

## Commit concurrency

A `complete` call holds a commit permit (default 8, shared by all uploads) for
its whole commit, including the read of the stored manifest when the object
already exists. Eight commits that stall at the same time (an object store that
accepts connections but does not answer) hold every other `complete` call until
one of them finishes or reaches its deadline. Chunk uploads do not need the
permit and keep flowing, and one stalled resolution does not block the others
while a permit is free.
