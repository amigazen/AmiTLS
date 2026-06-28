# BearSSL source placeholder

Phase 1 requires importing BearSSL here.

Expected layout after import:

```text
third_party/bearssl/inc/bearssl.h
third_party/bearssl/src/...
```

The current scaffold builds only the transport and API skeleton. Real HTTPS/TLS will be enabled after the BearSSL client source files are imported and wired into the Makefile.
