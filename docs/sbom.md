# Software Bill of Materials (human-readable)

Machine-readable version: [`sbom.json`](../sbom.json) (CycloneDX 1.6). This file is a readable summary of the same data — regenerate both together; see `sbom.json`'s `cdx:argus:note` property for how.

**Generated:** 2026-10-18T20:19:53Z  
**Component:** argus 1.0.0  
**Total components:** 79

## Container base images

| Image | Version | Notes |
|---|---|---|
| crowdsecurity/crowdsec | latest | Runtime base image (Alpine-based). Pin a digest in image/Dockerfile for reproducible builds. |
| node | 24-alpine | Build-stage image only; its /usr/local/bin/node binary is copied into the final image, the rest is discarded. |

## Alpine packages (added in `image/Dockerfile`)

| Package | Notes |
|---|---|
| bash |  |
| libstdc++ |  |
| libgcc |  |
| syslog-ng | Receives UDP 5514 / TCP 5515, writes CrowdSec acquisition files and the Argus remote-log spool. |
| tini | PID 1 / process supervisor (ENTRYPOINT). |
| tzdata |  |
| ca-certificates |  |

## Dashboard libraries (loaded from CDN, not npm-bundled)

`app/public/index.html` loads these directly in the browser from `cdn.jsdelivr.net` — they are not part of the npm dependency tree and `npm audit` will not see them.

| Library | Version | Notes |
|---|---|---|
| @tabler/core | 1 | Dashboard CSS framework, loaded client-side from cdn.jsdelivr.net (not bundled). |
| @tabler/icons-webfont | 3 |  |
| chart.js | 4 | Throughput / timeline charts. |
| papaparse | 5 | Client-side CSV export. |
| alpinejs | 3 | Dashboard reactivity/state (x-show, x-text, x-for throughout app/public/index.html). |

## npm dependency tree (`app/package-lock.json`) — 65 packages

Only `express` is a direct dependency in `app/package.json`; everything else is pulled in transitively. Full detail (hashes, exact resolved URLs) is in `sbom.json`.

| Package | Version |
|---|---|
| accepts | 2.0.0 |
| body-parser | 2.3.0 |
| bytes | 3.1.2 |
| call-bind-apply-helpers | 1.0.2 |
| call-bound | 1.0.4 |
| content-disposition | 2.0.1 |
| content-type | 2.1.0 |
| cookie | 0.7.2 |
| cookie-signature | 1.2.2 |
| debug | 4.4.3 |
| depd | 2.0.0 |
| dunder-proto | 1.0.1 |
| ee-first | 1.1.1 |
| encodeurl | 2.0.0 |
| es-define-property | 1.0.1 |
| es-errors | 1.3.0 |
| es-object-atoms | 1.1.2 |
| escape-html | 1.0.3 |
| etag | 1.8.1 |
| express **(direct)** | 5.3.0 |
| finalhandler | 2.1.1 |
| forwarded | 0.2.0 |
| fresh | 2.0.0 |
| function-bind | 1.1.2 |
| get-intrinsic | 1.3.0 |
| get-proto | 1.0.1 |
| gopd | 1.2.0 |
| has-symbols | 1.1.0 |
| hasown | 2.0.4 |
| http-errors | 2.0.1 |
| iconv-lite | 0.7.3 |
| inherits | 2.0.4 |
| ipaddr.js | 1.9.1 |
| is-promise | 4.0.0 |
| math-intrinsics | 1.1.0 |
| media-typer | 1.1.1 |
| merge-descriptors | 2.0.0 |
| mime-db | 1.54.0 |
| mime-types | 3.0.2 |
| ms | 2.1.3 |
| negotiator | 1.1.0 |
| object-inspect | 1.13.4 |
| on-finished | 2.4.1 |
| once | 1.4.0 |
| parseurl | 1.3.3 |
| path-to-regexp | 8.4.2 |
| proxy-addr | 2.0.8 |
| qs | 6.16.1 |
| range-parser | 1.3.0 |
| raw-body | 3.0.2 |
| router | 2.2.0 |
| safer-buffer | 2.1.2 |
| send | 1.2.1 |
| serve-static | 2.2.1 |
| setprototypeof | 1.2.0 |
| side-channel | 1.1.1 |
| side-channel-list | 1.0.1 |
| side-channel-map | 1.0.1 |
| side-channel-weakmap | 1.0.2 |
| statuses | 2.0.2 |
| toidentifier | 1.0.1 |
| type-is | 2.1.0 |
| unpipe | 1.0.0 |
| vary | 1.1.2 |
| wrappy | 1.0.2 |

