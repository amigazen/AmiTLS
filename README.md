# amitls.library

This is **AmiTLS**, an Amiga TLS client shared library for Amiga.  
It wraps [BearSSL](https://www.bearssl.org/) behind a compact, Amiga-native C API so
applications can speak TLS over caller-owned TCP sockets — without linking
OpenSSL or AmiSSL, and without exposing BearSSL structures to callers.

Primary consumer today: **amihttp.library**.  Any program that already uses 
`bsdsocket.library` for TCP can add TLS with a few library calls. Programs using 
amihttp.library will automatically inherit HTTPS support from amitls.library

## [amigazen project](http://www.amigazen.com)

*A web, suddenly*

*Forty years meditation*

*Minds awaken, free*

**amigazen project** is using modern software development tools and methods to update and rerelease classic Amiga open source software. Projects include a new AWeb, a new Amiga Python 2, and the ToolKit project — a universal SDK for Amiga development. All *amigazen project* releases are guaranteed to build against the ToolKit standard so that anyone can download and begin contributing straightaway without having to tailor the toolchain for their own setup.

AmiTLS is an original work of the amigazen project. amigazen project copyrighted code here in this project available under the MIT License or the BSD 2-Clause License, at your option (see [LICENSE.md](LICENSE.md)). BearSSL third-party code is under the MIT License in `Source/lib_source/third_party/bearssl/`.

The amigazen project philosophy is based on openness:

*Open* to anyone and everyone — *Open* source and free for all — *Open* your mind and create!

PRs for all projects are gratefully received at [GitHub](https://github.com/amigazen/). While the focus now is on classic 68k software, it is intended that all amigazen project releases can be ported to other Amiga-like systems including AROS and MorphOS where feasible.

## About amitls.library

amitls.library is a **standalone TLS client** for AmigaOS 3.2 and 4.1.  It performs
TLS 1.2 handshakes and encrypted record I/O on TCP file descriptors you already
opened with `bsdsocket.library`.  It does **not** perform DNS lookup, TCP
`connect()`, or `CloseSocket()` — those remain caller responsibilities.

Bootstrap is deliberately minimal:

```c
TlsBase = OpenLibrary("amitls.library", 0L);
SocketBase = OpenLibrary("bsdsocket.library", 4);
TlsTaskAttach(SocketBase, (APTR)&errno);
```

`dos.library` and `utility.library` open inside `OpenLibrary("amitls.library")`.
`bsdsocket.library` is **caller-owned** and must be passed to `TlsTaskAttach()`
before any connection I/O.

## Why a separate TLS library?

Classic Amiga HTTPS stacks historically depended on **AmiSSL** (OpenSSL port) —
powerful, but large and tied to OpenSSL release cycles.  For a lightweight HTTP
client, browser fetch path, or embedded tool, that footprint is often more than
required.

| Goal | How AmiTLS addresses it |
|------|-------------------------|
| **Small footprint** | BearSSL client profile; no OpenSSL runtime |
| **Amiga-native API** | Opaque handles, TagItem configuration, SFD/LVO stability |
| **Reuse** | One TLS implementation for amihttp, CLI tools, and custom protocols |
| **Separation of concerns** | TLS record layer in the library; TCP, HTTP, UI elsewhere |
| **Testability** | `ATlsTest` smoke test harness exercises the API without a browser |

## Relationship to amihttp.library

Build amihttp with the AmiTLS backend (`smake -f smakefile.amitls` in
`amihttp/Source/lib_source/`).  amihttp then:

- Calls `TlsTaskAttach()` / `TlsTaskDetach()` per task (ref-counted)
- Creates per-connection `TlsContext` with `ATSA_CA_BUNDLE_PATH`
- Attaches the pooled TCP socket with `TlsAttachSocketA()`
- Drives handshake via `TlsWrite()` (deferred model) or `TlsHandshake()`
- Maps `ERROR_TLS_*` to `ERROR_HTTP_*` for callers

Configure the CA bundle once at process level:

```c
HttpBaseTags(
    HTBT_CA_BUNDLE_PATH, (ULONG)"cacert.pem",
    HTSA_CA_BUNDLE_PATH, (ULONG)"cacert.pem",  /* amihttp session mirror */
    TAG_DONE);
```

amitls has **no implicit default CA path** — the application must set
`ATBT_CA_BUNDLE_PATH` or `ATSA_CA_BUNDLE_PATH` before `ATSSL_VERIFY_PEER`
handshakes succeed. This may change in future - what do you think the default bundle location should be? 

## API tiers

Public LVOs follow Amiga shared-library conventions: opaque handles, TagItem
configuration, and tiered scope (process → task → connection).

| Tier | Objects / LVOs | Use case |
|------|----------------|----------|
| 0 | `TlsBaseTagsA`, `TlsError`, `TlsGetErrorString` | Process defaults (CA bundle, verify policy, break mask) |
| 1 | `TlsTaskAttach`, `TlsTaskDetach`, `TlsContext` | Per-Exec-task socket/errno binding; persistent TLS settings |
| 2 | `TlsConnection` | **Primary API** — attach TLS to a connected TCP socket, read/write app data |
| 3 | `TlsLoadCABundle`, `TlsClearTrustedCerts` | Trust store path configuration (`TlsAddTrustedCert` reserved) |

### Typical Tier 2 flow

```c
struct TagItem basetags[] = {
    { ATBT_CA_BUNDLE_PATH, (ULONG)"cacert.pem" },
    { TAG_DONE, 0 }
};

TlsBase = OpenLibrary(AMITLSNAME, AMITLSVERSION);
SocketBase = OpenLibrary("bsdsocket.library", 4);
TlsTaskAttach(SocketBase, (APTR)&errno);
TlsBaseTagsA(basetags);

ctx = NewTlsContextA(NULL);
conn = NewTlsConnection(ctx);
/* sock = socket() + connect(host, 443) in your code */
TlsAttachSocket(conn, sock, (STRPTR)"www.example.com",
    ATTA_SSL_VERIFY, ATSSL_VERIFY_PEER,
    TAG_DONE);

TlsWrite(conn, (APTR)request, (ULONG)strlen(request));  /* handshake + send */
while ((n = TlsRead(conn, buf, sizeof(buf), 30)) > 0) {
    /* process buf[0..n-1] */
}

TlsShutdown(conn);
CloseSocket(sock);
DisposeTlsConnection(conn);
DisposeTlsContext(ctx);
TlsTaskDetach();
CloseLibrary(SocketBase);
CloseLibrary(TlsBase);
```

### Deferred handshake (ABI v1.1, revision 2+)

```c
TlsAttachSocketA(conn, sock, hostname, NULL);
rc = TlsHandshake(conn, 30);
if (rc == ERROR_TLS_WANT_READ || rc == ERROR_TLS_WANT_WRITE) {
    /* WaitSelect on sock, then retry TlsHandshake */
}
TlsWrite(conn, request, request_len);
```

### Non-blocking / layered I/O (amihttp async)

```c
TlsAttachSocket(conn, sock, hostname,
    ATTA_NON_BLOCKING, TRUE,
    ATTA_EXTERNAL_WAIT, TRUE,
    TAG_DONE);
/* TlsHandshake / TlsRead return WANT_* ; caller WaitSelects, then retries */
```

## TLS and trust features

### Protocol support

| Feature | Support | Notes |
|---------|---------|-------|
| TLS client | ✅ Full | TLS 1.2 only (`BR_TLS12`) |
| Cipher suites | ✅ Partial | ECDHE-ECDSA-CHACHA20, ECDHE-ECDSA-AES128-GCM, ECDHE-RSA-AES128-GCM |
| TLS 1.3 | ❌ | Not in BearSSL client profile used |
| SNI | ✅ Full | Hostname passed to `TlsAttachSocketA()` / `br_ssl_client_reset()` |
| ALPN | ❌ | Tag reserved (`ATSA_ALPN`) |
| Server role | ❌ | Client only |
| DNS / TCP connect | ❌ | Caller-owned (by design) |

### Certificate verification

| Feature | Support | Notes |
|---------|---------|-------|
| PEM CA bundle | ✅ Full | `ATBT_CA_BUNDLE_PATH`, `ATSA_CA_BUNDLE_PATH`, or `TlsLoadCABundle()` |
| BearSSL `x509_minimal` chain verify | ✅ Full | Lazy-loaded shared trust cache per process |
| Validation time | ✅ Full | Amiga `DateStamp()` mapped to BearSSL epoch |
| Peer cert fields | ✅ Full | `TlsGetPeerCert()` → `TlsPeerCertFree()` |
| Verify detail | ✅ Full | `TlsGetCertVerifyDetail()` after `ERROR_TLS_VERIFY` (BearSSL brerr) |
| Hostname pin (strict CN/SAN) | ⚠️ Partial | BearSSL minimal SAN/CN matching; see Autodoc |
| CRL / OCSP | ❌ | Not supported by BearSSL minimal |
| `TlsAddTrustedCert()` | ❌ | Returns `ERROR_TLS_NOT_IMPLEMENTED`; use PEM bundle |
| Custom cert hook | ❌ | `ATSA_CERT_HOOK` stored; dispatch reserved for v2 |

### I/O and concurrency

| Feature | Support | Notes |
|---------|---------|-------|
| Blocking read/write | ✅ Full | Default; internal `WaitSelect` when timeout > 0 |
| Non-blocking (`ATTA_NON_BLOCKING`) | ✅ Full | `ERROR_TLS_WANT_READ` / `WANT_WRITE`; retry after `WaitSelect` |
| External wait (`ATTA_EXTERNAL_WAIT`) | ✅ Full | Caller-owned `WaitSelect` before `TlsRead`/`TlsHandshake` retry |
| Multi-connection per task | ✅ Full | Each `TlsConnection` snapshots SocketBase/errno at attach |
| `TlsTaskAttach` refcount | ✅ Full | Nested attach/detach pairs supported |
| `TlsPending()` | ✅ Full | Decrypted bytes available without blocking read |

### Error model

| Scope | Function | Use |
|-------|----------|-----|
| Bootstrap / attach | `TlsError()` | Task attach, context alloc, trust path, attach failures |
| Connection I/O | `TlsGetLastError(conn)` | Authoritative for `TlsRead`/`TlsWrite`/`TlsHandshake`/`TlsShutdown` |
| Human string | `TlsGetErrorString(code)` | Static English description |

Success from `TlsRead`/`TlsWrite` is a **positive byte count** below `8800`.
Failures return `ERROR_TLS_*` (`8800`..`8816`) as the function result.

## CA bundle placement

amitls does not ship or search for a default bundle.  **`ATSSL_VERIFY_PEER`
requires a PEM CA bundle on disk** — without it, handshakes fail with
`ERROR_TLS_VERIFY` or trust-store errors at attach time.

Download the current Mozilla-derived bundle from curl’s CA extract page:

- **Documentation:** [curl.se/docs/caextract.html](https://curl.se/docs/caextract.html)
- **Direct download:** [curl.se/ca/cacert.pem](https://curl.se/ca/cacert.pem)

Include it in your application release, for example:

```
PROGDIR:cacert.pem
```

Point amitls (and amihttp) at that path via `ATBT_CA_BUNDLE_PATH` /
`ATSA_CA_BUNDLE_PATH` before verified HTTPS.

Refresh the bundle periodically — new public CAs (e.g. Sectigo R46) must be
present for modern sites.  The PEM file contains CA signatures only; browser
name constraints from Firefox are **not** included .

## Build

From `Source/lib_source/` on Amiga:

```
cd Source/lib_source
smake bearssl
smake
smake install
smake headers
```
N.B. the bearssl target requires at least 70MB to build, and will take several hours on a stock Amiga

Targets:

| Target | Action |
|--------|--------|
| `smake` | Build `amitls.library` (wrapper + vendored BearSSL objects) |
| `smake bearssl` | Rebuild BearSSL `.o` only (`smakefile.bearssl`) |
| `smake install` | Copy to `LIBS:amitls.library` and flush |
| `smake headers` | Install SDK headers to `SDK:Include_H/` |
| `smake rebuild` | Clean wrapper + relink |
| `smake rebuild-all` | Clean BearSSL + wrapper + full rebuild |

Building AmiTLS requires a compile that supports 64bit types and math operators, 
therefore the VBCC compiler is used rather than SAS/C.

Example smoke harness:

```
cd SDK/Examples
smake
ATlsTest
ATlsTest -verify -ca cacert.pem https://www.google.com
ATlsTest -bench-only -verify -ca cacert.pem www.google.com   # ElapsedTime benchmarks
```

## Prerequisites / dependencies

Building amitls.library requires:

- AmigaOS 3.2 or 4.1 target
- NDK 3.2 headers in `include:` path
- Roadshow (or equivalent) `bsdsocket.library` headers in `netinclude:` path
- VBCC **and** SAS/C smake + slink (ToolKit standard)

Runtime requirements for applications:

- `amitls.library` in `LIBS:`
- Caller opens `bsdsocket.library` and passes the base to `TlsTaskAttach()`
- PEM CA bundle path for verified HTTPS (`ATBT_CA_BUNDLE_PATH`)

Install public headers from `SDK/Include_H/` or run `smake headers`.

## Contact

- At GitHub https://github.com/amigazen/amitls/
- On the web at http://www.amigazen.com/ (Amiga browser compatible)
- Or email aweb@amigazen.com

## Acknowledgements

BearSSL is Copyright Thomas Pornin; see `Source/lib_source/third_party/bearssl/LICENSE.txt`.

*Amiga* is a trademark of **Amiga Inc**.
