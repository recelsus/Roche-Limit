# Third-Party Notices

Roche-Limit is licensed under the MIT License. See [`LICENSE`](./LICENSE).

This project links to or runs with the following third-party software. This file is a practical notice list for source and container distributions; the exact runtime package set may vary by base image and distribution.

## Direct Build / Runtime Dependencies

| Component | Use | Licence |
|---|---|---|
| Drogon | HTTP server framework | MIT |
| SQLite | Embedded database | Public Domain |
| libsodium | Password hashing and random session token generation | ISC |
| OpenSSL | SHA-256 helper through libcrypto | Apache-2.0 for OpenSSL 3.x |
| jsoncpp | Drogon dependency | MIT / Public Domain |
| c-ares | Drogon dependency | MIT |
| zlib | Drogon/runtime dependency | Zlib |
| libuuid / util-linux libuuid | Drogon/runtime dependency | BSD-3-Clause on common Linux distributions; distribution metadata may include additional util-linux licences |
| gosu | Docker entrypoint user switching | Apache-2.0 |
| Debian base image packages | Runtime operating system packages | See package notices in `/usr/share/doc/*/copyright` inside the image |

## Notes

- Roche-Limit does not vendor the source code of these libraries in this repository.
- Docker images install runtime libraries from Debian packages and keep package copyright files under `/usr/share/doc`.
- Drogon is built in the Dockerfile from the upstream source release selected by `DROGON_VERSION`.
- If a downstream distributor changes the base image, packages, or static/dynamic linking model, they should regenerate or review this notice.

## Upstream Licence References

- Drogon: <https://github.com/drogonframework/drogon>
- SQLite: <https://www.sqlite.org/copyright.html>
- libsodium: <https://doc.libsodium.org/doc>
- OpenSSL: <https://www.openssl-library.org/source/license/>
- c-ares: <https://c-ares.org/license.html>
- zlib: <https://www.zlib.net/zlib_license.html>
- util-linux / libuuid: <https://www.kernel.org/pub/linux/utils/util-linux/>
- gosu: <https://github.com/tianon/gosu>
