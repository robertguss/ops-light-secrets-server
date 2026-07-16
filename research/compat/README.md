# Pinned compatibility clients

[`client-matrix.json`](client-matrix.json) freezes the Linux amd64 client
artifacts used for compatibility capture. Versions were resolved on 2026-07-16
from the publishers' stable release feeds:

- Vault OSS 2.0.3 from HashiCorp Releases;
- OpenBao 2.6.0 from the OpenBao GitHub release;
- fnox 1.30.0 and 1.29.0, the two newest non-draft, non-prerelease GitHub
  releases.

Each exact archive was downloaded and independently hashed. The observed
SHA-256 values matched HashiCorp's `SHA256SUMS` file or GitHub's publisher asset
digest. `./scripts/fetch-compat-clients.sh OUTPUT_DIRECTORY` repeats the download
and refuses any mismatch before extracting or executing an artifact.

No legacy Vault line is pinned. No documented deployed legacy consumer was
supplied, and this prerecording stage has no evidence of a materially different
request contract. Adding a legacy line requires that evidence; age alone is not
a compatibility reason.

The matrix is evidence, not a promise about future client versions. Any version
change requires a new capture and compatibility review.
