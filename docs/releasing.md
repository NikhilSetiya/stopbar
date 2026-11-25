# Releases: install and verify

Every release (CS-196, FR-DX-2, NFR-7) is built by [GoReleaser](../.goreleaser.yaml) in [`.github/workflows/release.yml`](../.github/workflows/release.yml) when a `v*` tag is pushed. A release has:

| Artifact | What it is |
|---|---|
| `stopbar_<version>_<os>_<arch>.tar.gz` | `stopbard` + `stopbar` for linux/darwin × amd64/arm64. Static (`CGO_ENABLED=0`), built with `-trimpath`, file times set to the commit time, so a rebuild of the same commit gives identical binaries. |
| `…tar.gz.sbom.json` | SPDX SBOM for each archive, by syft. |
| `checksums.txt` | SHA-256 of every archive and SBOM. |
| `checksums.txt.sigstore.json` | Keyless cosign signature bundle for `checksums.txt` (signature, Fulcio certificate, Rekor entry). |
| `ghcr.io/nikhilsetiya/stopbar:<version>` | Multi-arch (linux/amd64, linux/arm64) image of `stopbard`, cosign-signed by digest, with a buildx SBOM attestation. |

`<version>` is the tag without the `v` (tag `v0.3.0-alpha` → `0.3.0-alpha`). `stopbar version` and `stopbard -version` print it.

Signing is **keyless**: there is no Stopbar signing key to leak. The signer is the release workflow itself. GitHub's OIDC token gets a short-lived Fulcio certificate whose identity is the workflow file at the tag, and the signature is logged in the public Rekor log. Verifying checks that identity, so a binary signed by anything else (a fork, another workflow, a laptop) fails.

The identity for tag `vX.Y.Z` is:

```text
certificate identity:  https://github.com/NikhilSetiya/stopbar/.github/workflows/release.yml@refs/tags/vX.Y.Z
OIDC issuer:           https://token.actions.githubusercontent.com
```

## Verify a binary

Needs [cosign](https://github.com/sigstore/cosign) v3 (the releases are signed with v3.1.5).

```bash
TAG=v0.3.0-alpha; V=${TAG#v}
BASE=https://github.com/NikhilSetiya/stopbar/releases/download/$TAG
curl -LO "$BASE/stopbar_${V}_linux_amd64.tar.gz"
curl -LO "$BASE/checksums.txt"
curl -LO "$BASE/checksums.txt.sigstore.json"

# 1. checksums.txt was signed by this repo's release workflow at this tag.
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/NikhilSetiya/stopbar/.github/workflows/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
# → Verified OK

# 2. The archive matches the signed checksum (macOS: shasum -a 256 -c).
sha256sum --ignore-missing -c checksums.txt
# → stopbar_<version>_linux_amd64.tar.gz: OK

tar xzf "stopbar_${V}_linux_amd64.tar.gz"
./stopbard -version
```

Both steps are needed: step 1 proves who produced `checksums.txt`, and step 2 ties the archive to it. The same `sha256sum -c` line checks a downloaded SBOM.

## Verify the image

```bash
TAG=v0.3.0-alpha; V=${TAG#v}
cosign verify "ghcr.io/nikhilsetiya/stopbar:$V" \
  --certificate-identity "https://github.com/NikhilSetiya/stopbar/.github/workflows/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

`cosign verify` prints the verified digest. Pull and deploy **by that digest** (`ghcr.io/nikhilsetiya/stopbar@sha256:…`), not by the tag, since a tag can be moved. The image's SBOM: `docker buildx imagetools inspect ghcr.io/nikhilsetiya/stopbar:$V --format '{{json .SBOM}}'`.

## Run the image

The image is distroless (`static-debian13:nonroot`): no shell, uid 65532, entrypoint `/stopbard`. With no arguments `stopbard` keeps its loopback default (`127.0.0.1:7777`), which is unreachable from outside the container. To serve it you have to listen on a non-loopback address, and **`stopbard` refuses that without `-auth-keys` (CS-103)**:

```bash
docker run --rm -p 7777:7777 \
  -v "$PWD/etc:/etc/stopbar:ro" -v stopbar-state:/home/nonroot \
  ghcr.io/nikhilsetiya/stopbar@sha256:… \
  -listen 0.0.0.0:7777 -auth-keys /etc/stopbar/api-keys.json -state-dir /home/nonroot \
  -config /etc/stopbar/stopbard.json
```

The image holds only the binary. Mount the config, API keys, approver keys and policy bundle (`-policies`; the default `examples/policies` isn't in the image), and keep state on a volume at `/home/nonroot`, the one directory uid 65532 can write.

API keys are still dev-only (no KMS/HSM yet), so the README's alpha status applies to the image too.

## Cutting a release (maintainer)

1. Make sure `main` is green. CI dry-runs this exact config on every PR (`goreleaser check` and `goreleaser release --snapshot --clean --skip=publish,sign`, plus a run of the built image), and `make e2e` does the same locally when goreleaser v2.20.3 is installed.
2. `git tag -s vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z`. Pushing any `v*` tag starts the release workflow.
3. On the first release only: ghcr.io creates the package as private. Set `ghcr.io/nikhilsetiya/stopbar` to public in the package settings so anyone can pull and verify it.
4. When it finishes, run the two verify sections above against the new release. That is the acceptance check for the release.

Tool pins (exact, never `@latest`): goreleaser v2.20.3, cosign v3.1.5, syft v1.57.2. They live in `release.yml`, `ci.yml` and `scripts/e2e.sh`. Change all three together.
